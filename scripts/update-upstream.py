#!/usr/bin/env python3
"""Giữ phiên bản gói Alpine upstream ở một nơi duy nhất và tự bump lên bản mới nhất.

Nguồn sự thật: security/upstream.lock.json. Lệnh:

  check   (offline) kiểm tra lock khớp melange/*.yaml, security/alpine-runtime.purls
          và security/distro.json. Dùng trong CI và unit test.
  update  tải APKINDEX của Alpine, nâng lock lên bản mới nhất rồi đồng bộ mọi nơi.

Ánh xạ gói Baseless:
  ca-certificates-bundle -> baseless-ca-certificates  (version/epoch lấy từ upstream)
  tzdata                 -> baseless-tzdata           (version/epoch lấy từ upstream)
  các gói còn lại        -> baseless-debug-tools      (version = busybox, epoch tăng dần)
"""
from __future__ import annotations

import argparse
import io
import json
import pathlib
import re
import sys
import tarfile
import urllib.request

LOCK = "security/upstream.lock.json"
PURLS = "security/alpine-runtime.purls"
DISTRO = "security/distro.json"
MELANGE = {
    "ca-certificates-bundle": "melange/baseless-ca-certificates.yaml",
    "tzdata": "melange/baseless-tzdata.yaml",
}
DEBUG_YAML = "melange/baseless-debug-tools.yaml"
BASELESS_NAME = {
    "ca-certificates-bundle": "baseless-ca-certificates",
    "tzdata": "baseless-tzdata",
}
DEBUG_NAME = "baseless-debug-tools"
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z._]*-r[0-9]+$")


class UpdateError(Exception):
    pass


def split_version(version: str) -> tuple[str, int]:
    base, _, rel = version.rpartition("-r")
    if not base or not rel.isdigit():
        raise UpdateError(f"invalid APK version: {version}")
    return base, int(rel)


def read_lock(root: pathlib.Path) -> dict:
    lock = json.loads((root / LOCK).read_text(encoding="utf-8"))
    for name, version in lock["packages"].items():
        if not VERSION_RE.match(version):
            raise UpdateError(f"invalid version for {name}: {version}")
    return lock


def write_lock(root: pathlib.Path, lock: dict) -> None:
    (root / LOCK).write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def runtime_packages(lock: dict) -> dict[str, str]:
    build_only = set(lock.get("build_only", []))
    return {n: v for n, v in lock["packages"].items() if n not in build_only}


def render_purls(lock: dict) -> str:
    distro = lock["alpine"]["release"]
    return "".join(
        f"pkg:apk/{n}@{v}?distro=alpine-{distro}\n" for n, v in runtime_packages(lock).items()
    )


def yaml_scalar(text: str, key: str) -> str:
    match = re.search(rf'^  {key}: "?([^"\n]+)"?\s*$', text, re.M)
    if not match:
        raise UpdateError(f"missing package.{key}")
    return match.group(1)


def yaml_set_package(text: str, version: str, epoch: int) -> str:
    text, n1 = re.subn(r'^(  version: )"[^"\n]*"', rf'\g<1>"{version}"', text, count=1, flags=re.M)
    text, n2 = re.subn(r"^(  epoch: )\d+", rf"\g<1>{epoch}", text, count=1, flags=re.M)
    if not (n1 and n2):
        raise UpdateError("cannot rewrite package version/epoch")
    return text


def yaml_set_pin(text: str, name: str, version: str) -> str:
    pattern = rf"^(\s+- {re.escape(name)}=)\S+$"
    text, count = re.subn(pattern, rf"\g<1>{version}", text, flags=re.M)
    if count != 1:
        raise UpdateError(f"expected exactly one pin for {name}, found {count}")
    return text


def yaml_pin(text: str, name: str) -> str | None:
    match = re.search(rf"^\s+- {re.escape(name)}=(\S+)$", text, re.M)
    return match.group(1) if match else None


def debug_version(root: pathlib.Path) -> str:
    text = (root / DEBUG_YAML).read_text(encoding="utf-8")
    return f"{yaml_scalar(text, 'version')}-r{yaml_scalar(text, 'epoch')}"


def check(root: pathlib.Path) -> list[str]:
    problems: list[str] = []
    lock = read_lock(root)
    packages = lock["packages"]
    if (root / PURLS).read_text(encoding="utf-8") != render_purls(lock):
        problems.append(f"{PURLS} differs from the lock; run update-upstream.py update")
    registry = {
        p["name"]: p for p in json.loads((root / DISTRO).read_text(encoding="utf-8"))["packages"]
    }
    debug_text = (root / DEBUG_YAML).read_text(encoding="utf-8")
    for name, version in packages.items():
        pin = yaml_pin(debug_text, name)
        if name in MELANGE:
            text = (root / MELANGE[name]).read_text(encoding="utf-8")
            pin = yaml_pin(text, name)
            own = f"{yaml_scalar(text, 'version')}-r{yaml_scalar(text, 'epoch')}"
            if own != version:
                problems.append(f"{MELANGE[name]}: package version {own} != lock {version}")
            if registry[BASELESS_NAME[name]]["current_version"] != version:
                problems.append(f"{DISTRO}: {BASELESS_NAME[name]} current_version != {version}")
        elif pin is None:
            problems.append(f"{DEBUG_YAML}: {name} is not pinned")
        if pin is not None and pin != version:
            problems.append(f"pin for {name} is {pin}, lock has {version}")
    if registry[DEBUG_NAME]["current_version"] != debug_version(root):
        problems.append(f"{DISTRO}: {DEBUG_NAME} current_version != {debug_version(root)}")
    return problems


def parse_apkindex(data: bytes) -> dict[str, str]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.extractfile("APKINDEX")
        if member is None:
            raise UpdateError("APKINDEX missing from archive")
        text = member.read().decode("utf-8")
    versions: dict[str, str] = {}
    for block in text.split("\n\n"):
        fields = dict(
            line.split(":", 1) for line in block.splitlines() if ":" in line and len(line) > 2
        )
        if "P" in fields and "V" in fields:
            versions[fields["P"]] = fields["V"]
    return versions


def fetch_index(lock: dict) -> dict[str, str]:
    url = f"{lock['alpine']['repository']}/x86_64/APKINDEX.tar.gz"
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https URL
        return parse_apkindex(response.read())


def add_release(entry: dict, version: str, source: dict) -> None:
    if all(r["version"] != version for r in entry["releases"]):
        entry["releases"].insert(0, {"version": version, "status": "supported", "source": source})
    entry["current_version"] = version


def apply_update(root: pathlib.Path, index: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Nâng lock theo `index`, đồng bộ các file. Trả về {gói: (cũ, mới)}."""
    lock = read_lock(root)
    changes: dict[str, tuple[str, str]] = {}
    for name, old in lock["packages"].items():
        new = index.get(name)
        if new is None:
            raise UpdateError(f"{name} is missing from the Alpine index")
        if not VERSION_RE.match(new):
            raise UpdateError(f"unexpected version for {name}: {new}")
        if new != old:
            changes[name] = (old, new)
            lock["packages"][name] = new
    if not changes:
        return changes

    registry_path = root / DISTRO
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    entries = {p["name"]: p for p in registry["packages"]}
    distro = lock["alpine"]["release"]
    debug_text = (root / DEBUG_YAML).read_text(encoding="utf-8")

    for name, (_, new) in changes.items():
        if name in MELANGE:
            path = root / MELANGE[name]
            text = yaml_set_pin(path.read_text(encoding="utf-8"), name, new)
            base, rel = split_version(new)
            path.write_text(yaml_set_package(text, base, rel), encoding="utf-8")
            add_release(
                entries[BASELESS_NAME[name]],
                new,
                {
                    "type": "apk",
                    "distro": f"alpine:{lock['alpine']['branch']}",
                    "purl": f"pkg:apk/alpine/{name}@{new}?distro=alpine-{distro}",
                },
            )
        else:
            debug_text = yaml_set_pin(debug_text, name, new)

    debug_changed = [n for n in changes if n not in MELANGE]
    if debug_changed:
        old_base = yaml_scalar(debug_text, "version")
        old_epoch = int(yaml_scalar(debug_text, "epoch"))
        busybox = lock["packages"]["busybox"]
        new_base, _ = split_version(busybox)
        epoch = old_epoch + 1 if new_base == old_base else 0
        debug_text = yaml_set_package(debug_text, new_base, epoch)
        add_release(
            entries[DEBUG_NAME],
            f"{new_base}-r{epoch}",
            {
                "type": "aggregate",
                "distro": f"alpine:{lock['alpine']['branch']}",
                "components": PURLS,
            },
        )
    (root / DEBUG_YAML).write_text(debug_text, encoding="utf-8")
    registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    (root / PURLS).write_text(render_purls(lock), encoding="utf-8")
    write_lock(root, lock)
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("command", choices=["check", "update"])
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        if args.command == "update":
            changes = apply_update(args.root, fetch_index(read_lock(args.root)))
            for name, (old, new) in sorted(changes.items()):
                print(f"{name}: {old} -> {new}")
            if not changes:
                print("already up to date")
        problems = check(args.root)
    except UpdateError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
