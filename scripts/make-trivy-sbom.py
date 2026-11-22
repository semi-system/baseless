#!/usr/bin/env python3
"""Chuyển security/alpine-runtime.purls thành CycloneDX SBOM để Trivy đối chiếu CVE.

Trivy không có họ OS `baseless`, nên `trivy image` không so khớp CVE gói OS
trên image Baseless. Các gói runtime lấy từ upstream thực chất là gói Alpine;
SBOM này khai báo chúng như vậy (OS component + purl apk) để `trivy sbom`
đối chiếu với advisory của Alpine.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.parse
import uuid

PURL = re.compile(r"^pkg:apk/(?P<name>[^@]+)@(?P<version>[^?]+)\?distro=alpine-(?P<distro>\S+)$")


def build(purl_file: pathlib.Path) -> dict:
    components = []
    distros = set()
    for line in purl_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = PURL.match(line)
        if not match:
            raise SystemExit(f"unsupported purl: {line}")
        name, version, distro = match["name"], match["version"], match["distro"]
        distros.add(distro)
        purl = f"pkg:apk/alpine/{name}@{urllib.parse.quote(version)}?distro={distro}"
        components.append(
            {"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl}
        )
    if len(distros) != 1:
        raise SystemExit(f"expected exactly one Alpine release, got {sorted(distros)}")
    if not components:
        raise SystemExit("no packages found")
    os_component = {
        "type": "operating-system",
        "bom-ref": "alpine-os",
        "name": "alpine",
        "version": distros.pop(),
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {"type": "container", "name": "baseless-upstream-components", "bom-ref": "root"}
        },
        "components": [os_component, *components],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("purls", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build(args.purls), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
