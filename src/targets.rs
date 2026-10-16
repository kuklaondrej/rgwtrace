#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::cli::Cli;

#[derive(Clone, Debug, Serialize)]
pub struct ProbeTargets {
    pub librados: PathBuf,
    pub librbd: Option<PathBuf>,
    pub libceph_common: PathBuf,
    pub radosgw: PathBuf,
}

impl ProbeTargets {
    pub fn rados_libraries(&self) -> Vec<&Path> {
        let mut paths = vec![self.librados.as_path()];
        if let Some(librbd) = &self.librbd {
            paths.push(librbd.as_path());
        }
        paths.push(self.libceph_common.as_path());
        paths
    }

    pub fn all_paths(&self) -> Vec<&Path> {
        let mut paths = self.rados_libraries();
        paths.push(self.radosgw.as_path());
        paths
    }
}

pub fn discover(cli: &Cli) -> Result<ProbeTargets> {
    let maps = match cli.pid {
        Some(pid) => Some(read_process_maps(pid)?),
        None => None,
    };

    let librados = discover_library(
        "librados.so.2",
        cli.librados_path.clone(),
        cli.pid,
        maps.as_ref(),
    )?;
    let librbd = discover_optional_library(
        "librbd.so.1",
        cli.librbd_path.clone(),
        cli.pid,
        maps.as_ref(),
    )?;
    let libceph_common = discover_library(
        "libceph-common.so.2",
        cli.libceph_common_path.clone(),
        cli.pid,
        maps.as_ref(),
    )?;
    let radosgw = discover_radosgw(cli.radosgw_path.clone(), cli.pid)?;

    Ok(ProbeTargets {
        librados,
        librbd,
        libceph_common,
        radosgw,
    })
}

fn discover_library(
    soname: &str,
    explicit: Option<PathBuf>,
    pid: Option<i32>,
    maps: Option<&BTreeMap<String, PathBuf>>,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }

    if let Some(path) = maps.and_then(|maps| maps.get(soname)).cloned() {
        return Ok(path);
    }

    if let Some(pid) = pid {
        for path in common_library_paths(soname) {
            let path = pid_root_path(pid, &path);
            if path.exists() {
                return Ok(path);
            }
        }
    }

    for path in common_library_paths(soname) {
        if path.exists() {
            return Ok(canonical_or_original(path));
        }
    }

    if let Some(path) = ldconfig_path(soname) {
        return Ok(canonical_or_original(path));
    }

    let pid_hint = pid.map(|pid| format!(" for pid {pid}")).unwrap_or_default();
    let flag = soname_flag(soname);
    bail!("failed to discover {soname}{pid_hint}; pass --{flag}")
}

fn discover_optional_library(
    soname: &str,
    explicit: Option<PathBuf>,
    pid: Option<i32>,
    maps: Option<&BTreeMap<String, PathBuf>>,
) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit {
        return Ok(Some(path));
    }

    if let Some(path) = maps.and_then(|maps| maps.get(soname)).cloned() {
        return Ok(Some(path));
    }

    if let Some(pid) = pid {
        for path in common_library_paths(soname) {
            let path = pid_root_path(pid, &path);
            if path.exists() {
                return Ok(Some(path));
            }
        }
        return Ok(None);
    }

    for path in common_library_paths(soname) {
        if path.exists() {
            return Ok(Some(canonical_or_original(path)));
        }
    }

    Ok(ldconfig_path(soname).map(canonical_or_original))
}

fn discover_radosgw(explicit: Option<PathBuf>, pid: Option<i32>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }

    if let Some(pid) = pid {
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .with_context(|| format!("failed to read /proc/{pid}/exe"))?;
        let name = exe
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name == "radosgw" || name == "ceph-radosgw" {
            return Ok(pid_root_path(pid, &exe));
        }
    }

    for path in [
        "/usr/bin/radosgw",
        "/usr/bin/ceph-radosgw",
        "/usr/local/bin/radosgw",
        "/usr/local/bin/ceph-radosgw",
        "/snap/microceph/current/bin/radosgw",
    ] {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(canonical_or_original(path));
        }
    }

    bail!("failed to discover radosgw executable; pass --radosgw-path")
}

/// Resolve symlinks (the soname `librados.so.2` -> versioned `librados.so.2.0.0`
/// real file) so discovery yields the same versioned basename that `--pid`/maps
/// discovery reports from the mmap'd path and that the artifact keys modules by.
/// Falls back to the original path if canonicalization fails (e.g. a
/// `/proc/<pid>/root` path, or a path that does not resolve), so discovery never
/// fails on a resolvable-but-uncanonicalizable path.
fn canonical_or_original(path: PathBuf) -> PathBuf {
    fs::canonicalize(&path).unwrap_or(path)
}

fn read_process_maps(pid: i32) -> Result<BTreeMap<String, PathBuf>> {
    let contents = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("failed to read /proc/{pid}/maps"))?;
    Ok(parse_process_maps(pid, &contents))
}

fn parse_process_maps(pid: i32, contents: &str) -> BTreeMap<String, PathBuf> {
    let mut result = BTreeMap::new();

    for line in contents.lines() {
        let Some(path) = line.split_whitespace().last() else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        let basename = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if basename.starts_with("librados.so.2") {
            result
                .entry("librados.so.2".to_string())
                .or_insert_with(|| pid_root_path(pid, Path::new(path)));
        } else if basename.starts_with("librbd.so.1") {
            result
                .entry("librbd.so.1".to_string())
                .or_insert_with(|| pid_root_path(pid, Path::new(path)));
        } else if basename.starts_with("libceph-common.so.2") {
            result
                .entry("libceph-common.so.2".to_string())
                .or_insert_with(|| pid_root_path(pid, Path::new(path)));
        }
    }

    result
}

fn pid_root_path(pid: i32, path: &Path) -> PathBuf {
    let root = PathBuf::from(format!("/proc/{pid}/root"));
    if let Ok(relative) = path.strip_prefix("/") {
        root.join(relative)
    } else {
        root.join(path)
    }
}

fn common_library_paths(soname: &str) -> Vec<PathBuf> {
    [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/ceph",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/snap/microceph/current/lib",
    ]
    .into_iter()
    .map(|dir| Path::new(dir).join(soname))
    .collect()
}

fn ldconfig_path(soname: &str) -> Option<PathBuf> {
    let output = crate::host_tools::system_command(crate::host_tools::LDCONFIG)?
        .arg("-p")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.contains(soname) {
            continue;
        }
        let Some((_, path)) = line.rsplit_once(" => ") else {
            continue;
        };
        return Some(path.into());
    }
    None
}

fn soname_flag(soname: &str) -> &'static str {
    match soname {
        "librados.so.2" => "librados-path",
        "librbd.so.1" => "librbd-path",
        "libceph-common.so.2" => "libceph-common-path",
        _ => "library-path",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_paths_win() {
        let cli = Cli {
            import_json: Some("x.json".into()),
            dwarf_source: crate::cli::DwarfSource::Json,
            ceph_version: None,
            max_debug_file_bytes: crate::dwarf_native::DEFAULT_MAX_DEBUG_FILE_BYTES,
            output: crate::cli::OutputMode::Json,
            otlp_endpoint: "http://localhost:4318/v1/traces".to_string(),
            otlp_header: Vec::new(),
            otlp_header_file: None,
            otlp_ca_cert: None,
            otlp_timeout: std::time::Duration::from_secs(5),
            otlp_retries: 2,
            otlp_compression: crate::cli::OtlpCompression::None,
            otlp_max_spans_per_batch: 512,
            otlp_max_bytes_per_batch: 0,
            otlp_flush_interval: std::time::Duration::from_secs(30),
            otlp_diagnostics: false,
            redact_object_names: false,
            correlation_ttl: std::time::Duration::from_secs(120),
            correlate_inferred: false,
            correlate_cross_thread: false,
            disable_rgw_op_bridge_key: false,
            inference_window: std::time::Duration::from_secs(1),
            service_name: "rgwtrace".to_string(),
            log_level: "warn".to_string(),
            pid: None,
            timeout: None,
            dry_run: false,
            preflight: false,
            export_dwarf_json: false,
            strict_build_id: false,
            allow_build_id_mismatch: false,
            librados_path: Some("/tmp/librados.so.2".into()),
            librbd_path: Some("/tmp/librbd.so.1".into()),
            libceph_common_path: Some("/tmp/libceph-common.so.2".into()),
            radosgw_path: Some("/tmp/radosgw".into()),
        };

        let targets = discover(&cli).unwrap();

        assert_eq!(targets.librados, PathBuf::from("/tmp/librados.so.2"));
        assert_eq!(targets.librbd, Some(PathBuf::from("/tmp/librbd.so.1")));
        assert_eq!(targets.radosgw, PathBuf::from("/tmp/radosgw"));
    }

    #[test]
    fn rados_libraries_omit_missing_librbd() {
        let targets = ProbeTargets {
            librados: "/tmp/librados.so.2".into(),
            librbd: None,
            libceph_common: "/tmp/libceph-common.so.2".into(),
            radosgw: "/tmp/radosgw".into(),
        };

        let libraries = targets.rados_libraries();

        assert_eq!(libraries.len(), 2);
        assert_eq!(libraries[0], Path::new("/tmp/librados.so.2"));
        assert_eq!(libraries[1], Path::new("/tmp/libceph-common.so.2"));
    }

    #[test]
    fn optional_library_can_be_absent_for_pid_scoped_discovery() {
        let maps = BTreeMap::new();

        let path = discover_optional_library("librbd.so.1", None, Some(42), Some(&maps)).unwrap();

        assert_eq!(path, None);
    }

    #[test]
    fn process_maps_paths_are_rooted_for_pid_namespace() {
        let maps = parse_process_maps(
            42,
            "7f-8 r-xp 00000000 08:01 1 /usr/lib/librados.so.2.0.0\n\
             8f-9 r-xp 00000000 08:01 2 /usr/lib/libceph-common.so.2\n",
        );

        assert_eq!(
            maps.get("librados.so.2"),
            Some(&PathBuf::from("/proc/42/root/usr/lib/librados.so.2.0.0"))
        );
        assert_eq!(
            maps.get("libceph-common.so.2"),
            Some(&PathBuf::from("/proc/42/root/usr/lib/libceph-common.so.2"))
        );
    }

    #[test]
    fn pid_root_path_prefixes_absolute_namespace_path() {
        assert_eq!(
            pid_root_path(42, Path::new("/usr/bin/radosgw")),
            PathBuf::from("/proc/42/root/usr/bin/radosgw")
        );
    }
}
