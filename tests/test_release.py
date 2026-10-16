"""Publication boundary tests; synthetic metadata never becomes a release."""
import copy
import importlib.util
import json
import os
import subprocess
import shutil
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("package_dwarf", ROOT / "scripts/package-dwarf.py")
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class DwarfReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "dist"
        self.report = {
            "ok": True,
            "checks": [{"name": name, "status": "ok", "detail": "valid"} for name in
                       ("ceph_abi", "target_paths", "rados_probes", "rgw_probe")]
                      + [{"name": "request_end_probe", "status": "warn", "detail": "missing D1/D2"}],
            "build_ids": [{"module": name, "status": "ok", "dwarf_build_id": "abcd",
                           "target_build_id": "abcd"} for name in
                          ("radosgw", "librados.so.2.0.0", "librbd.so.1.0.0", "libceph-common.so.2")],
        }
        self.write_report()
        (self.source / "native-dwarf.json").write_text(json.dumps({"arch": "amd64", "version": "19.2.4"}))
        packages = ("ceph-common", "ceph-common-dbg", "librados2", "librados2-dbg",
                    "librbd1", "librbd1-dbg", "radosgw", "radosgw-dbg")
        (self.source / "packages.txt").write_text("".join(f"{p}\t19.2.4-1jammy\tamd64\n" for p in packages))
        for name in ("os-release.txt", "repo-release.txt", "README.txt"):
            (self.source / name).write_text("fixture\n")

    def write_report(self):
        (self.source / "preflight.json").write_text(json.dumps(self.report))

    def package(self):
        return packager.package(self.source, self.output, "ubuntu", "22.04", "19.2.4", "amd64", "a" * 40, "19.2.4-1jammy")

    def test_centos_rpm_provenance_and_asset_name(self):
        packages = ("ceph-common", "ceph-common-debuginfo", "ceph-debuginfo",
                    "librados2", "librados2-debuginfo", "librbd1", "librbd1-debuginfo",
                    "ceph-radosgw", "ceph-radosgw-debuginfo")
        path = self.source / "packages.txt"
        path.write_text("".join(f"{p}\t19.2.4-0.el9\tx86_64\n" for p in packages))
        result = packager.package(self.source, self.output, "centos-stream", "9",
                                  "19.2.4", "amd64", "a" * 40, "19.2.4-0.el9")
        self.assertTrue(result["asset"].startswith("rgwtrace-dwarf-centos-stream-9-"))
        self.assertEqual(result["os"], "centos-stream")
        path.write_text(path.read_text().replace("x86_64", "aarch64"))
        with self.assertRaises(ValueError):
            packager.package(self.source, self.output, "centos-stream", "9",
                             "19.2.4", "amd64", "a" * 40, "19.2.4-0.el9")

    def test_optional_probe_warning_is_published_and_preserved(self):
        result = self.package()
        self.assertEqual(result["capabilities"]["request_end_probe"]["status"], "warn")
        with tarfile.open(self.output / result["asset"]) as archive:
            name = next(n for n in archive.getnames() if n.endswith("/manifest.json"))
            self.assertEqual(json.load(archive.extractfile(name))["build_ids"], result["build_ids"])

    def test_rejects_failed_missing_and_mismatched_validation(self):
        original = copy.deepcopy(self.report)
        for mutation in (lambda r: r.update(ok=False),
                         lambda r: r.update(checks=[]),
                         lambda r: r.update(build_ids=[]),
                         lambda r: r["build_ids"][0].update(target_build_id="dcba"),
                         lambda r: r["build_ids"][0].update(dwarf_build_id=None)):
            with self.subTest(mutation=mutation):
                self.report = copy.deepcopy(original)
                mutation(self.report)
                self.write_report()
                with self.assertRaises(ValueError):
                    self.package()
                self.assertFalse(self.output.exists())

    def test_rejects_wrong_arch_and_missing_packages(self):
        (self.source / "native-dwarf.json").write_text('{"arch":"arm64", "version":"19.2.4"}')
        with self.assertRaises(ValueError):
            self.package()
        (self.source / "native-dwarf.json").write_text('{"arch":"amd64", "version":"19.2.4"}')
        (self.source / "packages.txt").write_text("radosgw\t19.2.4-1jammy\tamd64\n")
        with self.assertRaises(ValueError):
            self.package()

    def test_repeated_export_is_stable_and_index_detects_corruption(self):
        first = self.package()
        tag = packager.index(self.output)
        self.assertEqual(self.package(), first)
        self.assertEqual(packager.index(self.output), tag)
        (self.output / first["asset"]).write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            packager.index(self.output)

    def test_new_build_gets_new_identity(self):
        first = self.package()
        self.report["build_ids"][0].update(dwarf_build_id="ffff", target_build_id="ffff")
        self.write_report()
        self.assertNotEqual(self.package()["asset"], first["asset"])

    def test_rejects_unpinned_package_revision(self):
        path = self.source / "packages.txt"
        path.write_text(path.read_text().replace("-1jammy", "-2jammy"))
        with self.assertRaises(ValueError):
            self.package()

    def test_empty_catalog_is_rejected(self):
        self.output.mkdir()
        with self.assertRaises(ValueError):
            packager.index(self.output)


class BinaryArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("LICENSE.GPL-2.0", "README.md", "RUNBOOK.md",
                     "tests/fixtures/minimal_dwarf.json", "release/BINARY-README.txt"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, target)
        self.binary = self.root / "rgwtrace"
        self.binary.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "rgwtrace 0.1.0"; else echo "{}"; fi\n')
        self.binary.chmod(0o755)
        self.ldd = self.root / "ldd"
        self.ldd.write_text('#!/bin/sh\necho "libelf.so.1 => /lib/libelf.so.1"\n')
        self.ldd.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"])

    def package(self, variant):
        return subprocess.run(["bash", str(ROOT / "scripts/package-binary.sh"),
                               str(self.binary), "v0.1.0", "aarch64-unknown-linux-gnu", variant],
                              cwd=self.root, env=self.env, capture_output=True, text=True)

    def test_variants_have_distinct_complete_executable_archives(self):
        for variant in ("", "centos9"):
            result = self.package(variant)
            self.assertEqual(result.returncode, 0, result.stderr)
        archives = list((self.root / "dist").glob("*.tar.gz"))
        self.assertEqual(len(archives), 2)
        for path in archives:
            stem = path.name.removesuffix(".tar.gz")
            with tarfile.open(path) as archive:
                executable = archive.getmember(stem + "/rgwtrace")
                self.assertTrue(executable.mode & 0o111)
                for name in ("INSTALL.txt", "LICENSE.GPL-2.0", "minimal_dwarf.json",
                             "shared-libraries.txt", "RUNBOOK.md"):
                    self.assertIn(stem + "/" + name, archive.getnames())
            result = subprocess.run(["bash", str(ROOT / "scripts/smoke-release-binary.sh"), str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_shared_library_blocks_packaging(self):
        self.ldd.write_text('#!/bin/sh\necho "libelf.so.1 => not found"\n')
        self.assertNotEqual(self.package("centos9").returncode, 0)
        self.assertEqual(list((self.root / "dist").glob("*.tar.gz")), [])

    def test_broken_executable_fails_smoke_test(self):
        self.binary.write_text("#!/bin/sh\nexit 1\n")
        self.assertEqual(self.package("centos9").returncode, 0)
        path = next((self.root / "dist").glob("*.tar.gz"))
        result = subprocess.run(["bash", str(ROOT / "scripts/smoke-release-binary.sh"), str(path)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


class MatrixTests(unittest.TestCase):
    def test_all_stable_reef_squid_and_latest_tentacle_on_both_platforms(self):
        rows = json.loads((ROOT / "release/dwarf-matrix.json").read_text())["include"]
        versions = {f"18.2.{n}" for n in (0, 1, 2, 4, 5, 6, 7, 8)}
        versions |= {f"19.2.{n}" for n in range(8)} | {"20.2.4"}
        expected = {(v, os) for v in versions for os in ("ubuntu", "centos-stream")}
        self.assertEqual({(r["ceph"], r["os"]) for r in rows}, expected)
        self.assertEqual(len(rows), len(expected))
        for row in rows:
            self.assertEqual(row["arch"], "amd64")
            suffix = "-1jammy" if row["os"] == "ubuntu" else "-0.el9"
            self.assertEqual(row["package_version"], row["ceph"] + suffix)
            self.assertEqual(row["image"], "ubuntu:22.04" if row["os"] == "ubuntu"
                             else "quay.io/centos/centos:stream9")


class PublishReleaseTests(unittest.TestCase):
    def run_publish(self, state="missing", fail_upload=False, mode="dwarf"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_gh = root / "gh"
            fake_gh.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[:2] == ["release", "view"]:
    state = os.environ["RELEASE_STATE"]
    if state == "missing": sys.exit(1)
    print(state)
if args[:2] == ["release", "upload"] and os.environ["FAIL_UPLOAD"] == "1":
    sys.exit(1)
""")
            fake_gh.chmod(0o755)
            assets = root / "assets"
            assets.mkdir()
            (assets / "bundle.tar.gz").write_bytes(b"fixture")
            notes = root / "notes.txt"
            notes.write_text("release notes")
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       CALLS=str(root / "calls"), RELEASE_STATE=state,
                       FAIL_UPLOAD=str(int(fail_upload)), GITHUB_SHA="a" * 40)
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/publish-release.sh"), "v0.1.0",
                 str(assets), str(notes), mode], env=env, capture_output=True, text=True)
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            return result, calls

    def test_published_release_is_never_mutated(self):
        result, calls = self.run_publish(state="false")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[1] for call in calls], ["view"])

    def test_failed_upload_leaves_a_draft(self):
        result, calls = self.run_publish(fail_upload=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[1] for call in calls], ["view", "create", "upload"])
        self.assertIn("--draft", calls[1])

    def test_retry_resumes_draft_without_changing_latest(self):
        result, calls = self.run_publish(state="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[1] for call in calls], ["view", "upload", "edit"])
        self.assertIn("--latest=false", calls[-1])

    def test_binary_requires_existing_tag_and_becomes_latest(self):
        result, calls = self.run_publish(mode="binary")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--verify-tag", calls[1])
        self.assertIn("--latest", calls[-1])


if __name__ == "__main__":
    unittest.main()
