#!/usr/bin/env python3
"""Validate an export and package immutable, build-ID-specific release assets."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def manifest(directory, os, os_version, ceph, arch, commit, package_version):
    if (os, os_version) not in {("ubuntu", "22.04"), ("centos-stream", "9")}:
        raise ValueError("unsupported distribution")
    report = json.loads((directory / "preflight.json").read_text())
    dwarf_bytes = (directory / "native-dwarf.json").read_bytes()
    dwarf = json.loads(dwarf_bytes)  # Never publish a truncated export.
    if dwarf.get("arch") != arch or dwarf.get("version") != ceph:
        raise ValueError("metadata version or architecture differs from matrix")
    if report.get("ok") is not True:
        raise ValueError("preflight did not succeed")
    checks = {check["name"]: check for check in report["checks"]}
    for name in ("ceph_abi", "target_paths", "rados_probes", "rgw_probe"):
        if checks.get(name, {}).get("status") != "ok":
            raise ValueError(f"required check failed or missing: {name}")
    build_ids = {}
    for check in report["build_ids"]:
        expected, actual = check.get("dwarf_build_id"), check.get("target_build_id")
        if (check.get("status") != "ok" or not expected or not actual
                or expected.lower() != actual.lower()
                or not re.fullmatch(r"[a-fA-F0-9]+", actual)):
            raise ValueError(f"unverified build ID: {check['module']}")
        if check["module"] in build_ids:
            raise ValueError("duplicate module build ID")
        build_ids[check["module"]] = actual.lower()
    # Preflight resolves library symlinks, so keys may have versioned sonames.
    for prefix in ("librados.so.", "librbd.so.", "libceph-common.so."):
        if not any(name.startswith(prefix) for name in build_ids):
            raise ValueError(f"missing build ID: {prefix}")
    if not any(name in build_ids for name in ("radosgw", "ceph-radosgw")):
        raise ValueError("missing RGW build ID")
    packages = (directory / "packages.txt").read_text().strip().splitlines()
    if not packages:
        raise ValueError("missing package provenance")
    package_names = set()
    for line in packages:
        name, version, package_arch = line.split("\t")
        package_names.add(name.split(":")[0])
        if version != package_version or not version.startswith(ceph + "-") or package_arch != ("x86_64" if os == "centos-stream" and arch == "amd64" else arch):
            raise ValueError("package version or architecture differs from matrix")
    required_packages = {"ceph-common", "ceph-common-dbg", "librados2", "librados2-dbg",
                         "librbd1", "librbd1-dbg", "radosgw", "radosgw-dbg"}
    if os == "centos-stream":
        required_packages = {"ceph-common", "ceph-common-debuginfo", "ceph-debuginfo",
                             "librados2", "librados2-debuginfo", "librbd1", "librbd1-debuginfo",
                             "ceph-radosgw", "ceph-radosgw-debuginfo"}
    if package_names != required_packages:
        raise ValueError("incomplete package provenance")
    return {
        "schema_version": 1,
        "source": "download.ceph.com",
        "os": os, "os_version": os_version, "ceph": ceph, "arch": arch,
        "package_version": package_version,
        "exporter_commit": commit,
        "build_ids": build_ids,
        "packages": packages,
        "metadata_sha256": sha256(dwarf_bytes),
        "capabilities": {
            name: checks.get(name, {"status": "warn", "detail": "check missing"})
            for name in ("request_end_probe", "cross_thread_operate_probe",
                         "cross_thread_reseed_probe")
        },
    }


def package(directory, output, os, os_version, ceph, arch, commit, package_version):
    metadata = manifest(directory, os, os_version, ceph, arch, commit, package_version)
    identity = sha256(encoded(metadata))[:20]
    stem = f"rgwtrace-dwarf-{os}-{os_version}-ceph-{ceph}-{arch}-{identity}"
    output.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    # Stable archive headers allow repeated exports to resolve to the same release.
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as archive:
            files = {"manifest.json": encoded(metadata)}
            for name in ("native-dwarf.json", "preflight.json", "packages.txt",
                         "os-release.txt", "repo-release.txt", "README.txt"):
                files[name] = (directory / name).read_bytes()
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(f"{stem}/{name}")
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
    payload = buffer.getvalue()
    asset = stem + ".tar.gz"
    (output / asset).write_bytes(payload)
    metadata.update(asset=asset, sha256=sha256(payload))
    (output / (stem + ".json")).write_bytes(encoded(metadata))
    return metadata


def index(directory):
    entries = [json.loads(path.read_text()) for path in sorted(directory.glob("rgwtrace-dwarf-*.json"))]
    if not entries:
        raise ValueError("no validated DWARF bundles")
    for entry in entries:
        if sha256((directory / entry["asset"]).read_bytes()) != entry["sha256"]:
            raise ValueError("bundle checksum mismatch")
    data = encoded({"schema_version": 1, "artifacts": entries})
    (directory / "index.json").write_bytes(data)
    checksums = "".join(f"{sha256(p.read_bytes())}  {p.name}\n" for p in sorted(directory.iterdir())
                        if p.is_file() and p.name != "SHA256SUMS")
    (directory / "SHA256SUMS").write_text(checksums)
    return "dwarf-" + sha256(data)[:20]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    bundle = sub.add_parser("bundle")
    bundle.add_argument("directory", type=Path)
    bundle.add_argument("output", type=Path)
    for name in ("os", "os-version", "ceph", "arch", "commit", "package-version"):
        bundle.add_argument("--" + name, required=True)
    catalog = sub.add_parser("index")
    catalog.add_argument("directory", type=Path)
    args = vars(parser.parse_args())
    command = args.pop("command")
    print(package(**args)["asset"] if command == "bundle" else index(**args))
