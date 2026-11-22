import importlib.util
import pathlib
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "make_trivy_sbom", REPO_ROOT / "scripts" / "make-trivy-sbom.py"
)
sbom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sbom)


def build_from_text(text: str) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "in.purls"
        path.write_text(text, encoding="utf-8")
        return sbom.build(path)


class TrivySbomTests(unittest.TestCase):
    def test_declares_alpine_os_and_apk_purls(self):
        doc = build_from_text(
            "pkg:apk/musl@1.2.6-r3?distro=alpine-3.24.3\n"
            "# comment\n\n"
            "pkg:apk/libncursesw@6.6_p20260516-r0?distro=alpine-3.24.3\n"
        )
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        os_component, *libs = doc["components"]
        self.assertEqual(os_component["type"], "operating-system")
        self.assertEqual((os_component["name"], os_component["version"]), ("alpine", "3.24.3"))
        self.assertEqual([c["name"] for c in libs], ["musl", "libncursesw"])
        self.assertEqual(libs[0]["purl"], "pkg:apk/alpine/musl@1.2.6-r3?distro=3.24.3")
        self.assertTrue(all(c["purl"].startswith("pkg:apk/alpine/") for c in libs))

    def test_rejects_malformed_purl(self):
        with self.assertRaises(SystemExit):
            build_from_text("pkg:deb/musl@1.0\n")

    def test_rejects_mixed_alpine_releases(self):
        with self.assertRaises(SystemExit):
            build_from_text(
                "pkg:apk/a@1-r0?distro=alpine-3.24.3\npkg:apk/b@1-r0?distro=alpine-3.23.0\n"
            )

    def test_rejects_empty_inventory(self):
        with self.assertRaises(SystemExit):
            build_from_text("# nothing\n")

    def test_real_inventory_builds(self):
        doc = sbom.build(REPO_ROOT / "security" / "alpine-runtime.purls")
        self.assertGreater(len(doc["components"]), 10)


if __name__ == "__main__":
    unittest.main()
