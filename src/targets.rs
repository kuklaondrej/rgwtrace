#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
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

    for path in common_library_paths(soname) {
        if path.exists() {
            return Ok(path);
        }
    }

    if let Some(path) = ldconfig_path(soname) {
        return Ok(path);
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

    if pid.is_some() {
        return Ok(None);
    }

    for path in common_library_paths(soname) {
        if path.exists() {
            return Ok(Some(path));
        }
    }

    Ok(ldconfig_path(soname))
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
            return Ok(exe);
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
            return Ok(path);
        }
    }

    bail!("failed to discover radosgw executable; pass --radosgw-path")
}

fn read_process_maps(pid: i32) -> Result<BTreeMap<String, PathBuf>> {
    let contents = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("failed to read /proc/{pid}/maps"))?;
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
                .or_insert_with(|| path.into());
        } else if basename.starts_with("librbd.so.1") {
            result
                .entry("librbd.so.1".to_string())
                .or_insert_with(|| path.into());
        } else if basename.starts_with("libceph-common.so.2") {
            result
                .entry("libceph-common.so.2".to_string())
                .or_insert_with(|| path.into());
        }
    }

    Ok(result)
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
    let output = Command::new("ldconfig").arg("-p").output().ok()?;
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
            output: crate::cli::OutputMode::Json,
            otlp_endpoint: "http://localhost:4318/v1/traces".to_string(),
            otlp_header: Vec::new(),
            otlp_timeout: std::time::Duration::from_secs(5),
            otlp_retries: 2,
            otlp_compression: crate::cli::OtlpCompression::None,
            otlp_max_spans_per_batch: 512,
            otlp_max_bytes_per_batch: 0,
            otlp_flush_interval: std::time::Duration::from_secs(30),
            correlation_ttl: std::time::Duration::from_secs(120),
            correlate_inferred: false,
            service_name: "rgwtrace".to_string(),
            log_level: "warn".to_string(),
            pid: None,
            timeout: None,
            dry_run: false,
            preflight: false,
            export_dwarf_json: false,
            strict_build_id: false,
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
}
