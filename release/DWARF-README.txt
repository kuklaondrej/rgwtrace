# rgwtrace DWARF catalog

Validated upstream Ceph DWARF metadata for the builds listed in [`index.json`](index.json). This is a metadata catalog, not a new `rgwtrace` binary release.

## Coverage

The catalog covers all official stable Reef and Squid point releases through 18.2.8 and 19.2.7, plus Tentacle 20.2.4, on Ubuntu 22.04 and CentOS Stream 9 (amd64).

- Reef 18.2.3 was re-tagged upstream as 18.2.4 and has no separate repository.
- CentOS entries use upstream EL9 RPMs, not Storage SIG rebuilds.

## Choose and use an artifact

Choose an artifact by package source, architecture, and **all module build IDs**. OS and Ceph version alone are not sufficient. Each index entry records exact package versions, exporter commit, checksums, and optional probe capabilities.

A warning for `request_end_probe` or `cross_thread_reseed_probe` indicates reduced capability. Review the recorded detail before use.

Download the chosen `.tar.gz` bundle and `SHA256SUMS`, then verify and inspect it:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf rgwtrace-dwarf-<build>.tar.gz
sudo rgwtrace --pid 12345 --import-json <bundle>/native-dwarf.json --preflight
sudo rgwtrace --pid 12345 --import-json <bundle>/native-dwarf.json --timeout 30 --output json
```

## Validation limits

The metadata passed offline preflight against its original binaries. This does not mean it passed a live attach test. Container deployments must match the binaries inside the RGW container.

If matching metadata is unavailable, extract it natively with matching debug symbols. Never bypass build-ID validation.
