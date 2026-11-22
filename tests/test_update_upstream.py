import importlib.util
import io
import json
import pathlib
import shutil
import tarfile
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "update_upstream", REPO_ROOT / "scripts" / "update-upstream.py"
)
up = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(up)


def copy_repo(destination: pathlib.Path) -> None:
    for relative in (up.LOCK, up.PURLS, up.DISTRO, up.DEBUG_YAML, *up.MELANGE.values()):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / relative, target)


class UpdateUpstreamTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name)
        copy_repo(self.root)
        self.index = dict(up.read_lock(self.root)["packages"])

    def test_repository_is_consistent(self):
        self.assertEqual(up.check(REPO_ROOT), [])

    def test_parse_apkindex(self):
        data = b"C:x\nP:openssl\nV:3.5.9-r1\nA:x86_64\n\nP:musl\nV:1.2.6-r3\n\n"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("APKINDEX")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        self.assertEqual(
            up.parse_apkindex(buffer.getvalue()), {"openssl": "3.5.9-r1", "musl": "1.2.6-r3"}
        )

    def test_no_change_is_a_noop(self):
        before = (self.root / up.DEBUG_YAML).read_text(encoding="utf-8")
        self.assertEqual(up.apply_update(self.root, self.index), {})
        self.assertEqual((self.root / up.DEBUG_YAML).read_text(encoding="utf-8"), before)

    def test_debug_tool_bump_increments_epoch_and_registry(self):
        old = up.debug_version(self.root)
        current = self.index["openssl"]
        base, rel = up.split_version(current)
        bumped = f"{base}-r{rel + 1}"
        self.index["openssl"] = bumped
        changes = up.apply_update(self.root, self.index)
        self.assertEqual(changes, {"openssl": (current, bumped)})
        base, epoch = up.split_version(old)
        new = f"{base}-r{epoch + 1}"
        self.assertEqual(up.debug_version(self.root), new)
        registry = json.loads((self.root / up.DISTRO).read_text(encoding="utf-8"))
        entry = next(p for p in registry["packages"] if p["name"] == up.DEBUG_NAME)
        self.assertEqual(entry["current_version"], new)
        self.assertIn(old, [r["version"] for r in entry["releases"]])
        self.assertEqual(up.check(self.root), [])

    def test_ca_bundle_bump_updates_package_and_registry(self):
        self.index["ca-certificates-bundle"] = "20270101-r0"
        up.apply_update(self.root, self.index)
        text = (self.root / "melange/baseless-ca-certificates.yaml").read_text(encoding="utf-8")
        self.assertIn('version: "20270101"', text)
        self.assertIn("ca-certificates-bundle=20270101-r0", text)
        self.assertEqual(up.check(self.root), [])

    def test_busybox_version_change_resets_epoch(self):
        self.index["busybox"] = "1.38.0-r0"
        up.apply_update(self.root, self.index)
        self.assertEqual(up.debug_version(self.root), "1.38.0-r0")
        self.assertEqual(up.check(self.root), [])

    def test_missing_package_fails_closed(self):
        del self.index["musl"]
        with self.assertRaises(up.UpdateError):
            up.apply_update(self.root, self.index)

    def test_check_detects_drift(self):
        path = self.root / up.PURLS
        version = up.read_lock(self.root)["packages"]["openssl"]
        path.write_text(path.read_text(encoding="utf-8").replace(version, "0.0.1-r0"), encoding="utf-8")
        self.assertTrue(up.check(self.root))


if __name__ == "__main__":
    unittest.main()
