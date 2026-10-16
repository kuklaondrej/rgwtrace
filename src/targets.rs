#![allow(dead_code)]

use std::{
    collections::{BTreeMap, VecDeque},
    ffi::OsString,
    fs, io,
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;
use tracing::debug;

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
    maps: Option<&BTreeMap<String, MappedFile>>,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }

    if let (Some(pid), Some(mapped)) = (pid, maps.and_then(|maps| maps.get(soname))) {
        return mapped_library_path(pid, soname, mapped);
    }

    if let Some(pid) = pid {
        return required_library_in_pid_root(pid, soname, common_library_paths(soname));
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
    maps: Option<&BTreeMap<String, MappedFile>>,
) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit {
        return Ok(Some(path));
    }

    if let (Some(pid), Some(mapped)) = (pid, maps.and_then(|maps| maps.get(soname))) {
        return mapped_library_path(pid, soname, mapped).map(Some);
    }

    if let Some(pid) = pid {
        if let Some(path) = first_existing_in_pid_root(pid, common_library_paths(soname)) {
            return Ok(Some(path));
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

    // With --pid the executable is whatever that process runs -- never a host
    // path guessed below, which may be a different build than the one mapped.
    if let Some(pid) = pid {
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .with_context(|| format!("failed to read /proc/{pid}/exe"))?;
        return radosgw_exe_path(pid, &exe);
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

/// The ` (deleted)` suffix the kernel appends to `/proc/<pid>/exe` and to a
/// `/proc/<pid>/maps` pathname once the mapped file has been unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// Map `/proc/<pid>/exe`'s target to the path to probe. The target must be the
/// file the process is running, so a deleted executable or one that is not
/// radosgw is an error rather than a reason to look elsewhere.
fn radosgw_exe_path(pid: i32, exe: &Path) -> Result<PathBuf> {
    let text = exe.to_string_lossy();
    if let Some(original) = text.strip_suffix(DELETED_SUFFIX) {
        bail!(
            "the radosgw executable of pid {pid} ({original}) was deleted or replaced on disk \
             after the process started (e.g. a package upgrade): the file now at that path is \
             not the binary that is running, and probes attached to it would never fire. \
             restart radosgw so it runs the installed binary, then rerun rgwtrace"
        );
    }
    let name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if name != "radosgw" && name != "ceph-radosgw" {
        bail!(
            "pid {pid} runs {}, not radosgw; pass the radosgw pid, or --radosgw-path if the \
             radosgw binary has a different name",
            exe.display()
        );
    }
    pid_root_path(pid, exe)
}

/// Resolve a soname's mapping from `/proc/<pid>/maps` to the path to probe,
/// refusing a mapping whose file has been deleted: the inode the process runs
/// is no longer reachable by name, and the file now at that name is another.
fn mapped_library_path(pid: i32, soname: &str, mapped: &MappedFile) -> Result<PathBuf> {
    if mapped.deleted {
        bail!(
            "{soname} mapped by pid {pid} ({}) was deleted or replaced on disk after the \
             process started (e.g. a package upgrade): the file now at that path is not the \
             library the process runs, and probes attached to it would never fire. restart the \
             daemon so it maps the installed library, then rerun rgwtrace",
            mapped.path.display()
        );
    }
    pid_root_path(pid, &mapped.path)
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

fn read_process_maps(pid: i32) -> Result<BTreeMap<String, MappedFile>> {
    let contents = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("failed to read /proc/{pid}/maps"))?;
    Ok(parse_process_maps(&contents))
}

/// One target library as `/proc/<pid>/maps` reports it: its path inside the
/// process's mount namespace, and whether that file has since been deleted.
#[derive(Clone, Debug, Eq, PartialEq)]
struct MappedFile {
    path: PathBuf,
    deleted: bool,
}

fn parse_process_maps(contents: &str) -> BTreeMap<String, MappedFile> {
    let mut result: BTreeMap<String, MappedFile> = BTreeMap::new();

    for line in contents.lines() {
        let Some(pathname) = maps_pathname(line) else {
            continue;
        };
        let (path, deleted) = match pathname.strip_suffix(DELETED_SUFFIX) {
            Some(path) => (path, true),
            None => (pathname, false),
        };
        if !path.starts_with('/') {
            continue;
        }
        let basename = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let Some(soname) = ["librados.so.2", "librbd.so.1", "libceph-common.so.2"]
            .into_iter()
            .find(|soname| basename.starts_with(soname))
        else {
            continue;
        };
        // A library can be mapped several times (one line per segment). If ANY
        // of its mappings is deleted the process runs an inode that is no longer
        // on disk, so the flag is sticky.
        let entry = result.entry(soname.to_string()).or_insert(MappedFile {
            path: PathBuf::from(path),
            deleted,
        });
        entry.deleted |= deleted;
    }

    result
}

/// The pathname column of a `/proc/<pid>/maps` line: everything after the
/// fifth field (address, perms, offset, dev, inode). Taken whole, so a path
/// containing spaces -- or the kernel's ` (deleted)` suffix -- survives intact.
fn maps_pathname(line: &str) -> Option<&str> {
    let mut rest = line;
    for _ in 0..5 {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace)?;
        rest = &rest[end..];
    }
    let pathname = rest.trim_start();
    (!pathname.is_empty()).then_some(pathname)
}

fn proc_root(pid: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/root"))
}

/// `path` (as the process sees it) under `/proc/<pid>/root`, with every symlink
/// resolved INSIDE that root -- see [`resolve_in_root`].
fn pid_root_path(pid: i32, path: &Path) -> Result<PathBuf> {
    resolve_in_root(&proc_root(pid), path)
}

/// The first of `candidates` (namespace paths) that exists inside the pid's
/// root. These are guesses, not what the process maps, so a location that cannot
/// be resolved (a symlink loop, an unreadable directory) is skipped rather than
/// failing discovery.
fn first_existing_in_pid_root(
    pid: i32,
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Option<PathBuf> {
    candidates
        .into_iter()
        .filter_map(|candidate| match pid_root_path(pid, &candidate) {
            Ok(path) => Some(path),
            Err(err) => {
                debug!(
                    pid,
                    candidate = %candidate.display(),
                    error = %format_args!("{err:#}"),
                    "skipping an unresolvable fallback library location"
                );
                None
            }
        })
        .find(|path| path.exists())
}

/// Resolve a required library only from the target's root. Once `--pid` is
/// selected, a host library is never a safe fallback for an absent mapping.
fn required_library_in_pid_root(
    pid: i32,
    soname: &str,
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Result<PathBuf> {
    first_existing_in_pid_root(pid, candidates).ok_or_else(|| {
        anyhow::anyhow!(
            "failed to discover {soname} inside pid {pid}'s root; pass --{}",
            soname_flag(soname)
        )
    })
}

/// Bound on symlink expansions, matching the kernel's `MAXSYMLINKS`.
const MAX_SYMLINK_HOPS: usize = 40;

/// Resolve `path` as if `root` were `/`, returning `root` joined with a path
/// that contains no symlinks and no `..`.
///
/// WHY. `/proc/<pid>/root` is a magic link to the process's root, but only the
/// FIRST hop through it is special. A symlink met further down is resolved by
/// the kernel against the CALLER's root, so a container's absolute
/// `/usr/lib/librados.so.2 -> /usr/lib/x86_64-linux-gnu/librados.so.2.0.0` opened
/// from the host by name lands on the HOST's file -- a different build, or a
/// file planted by whoever controls the container image -- and `..` can climb
/// out of the container the same way. Here every symlink is read and expanded
/// by hand: absolute targets restart from `root`, `..` never pops past it
/// (the semantics of `openat2(RESOLVE_IN_ROOT)`).
///
/// A component that does not exist is kept verbatim, as is everything after it
/// (there is nothing left to resolve; opening it later fails with a normal
/// not-found error) -- except a later `..`, which is an error: popping the
/// missing component would turn a path the kernel cannot open into another,
/// existing file. The result is still re-checked against `root` before it is
/// returned.
///
/// Residual race: a component can be swapped for a symlink between this walk
/// and the later open/attach. `openat2(RESOLVE_IN_ROOT)` on an fd, attached
/// through `/proc/self/fd/N`, would close that window; it is a follow-up.
pub fn resolve_in_root(root: &Path, path: &Path) -> Result<PathBuf> {
    let mut resolved: Vec<OsString> = Vec::new();
    // Components still to walk; `None` is `..`.
    let mut queue: VecDeque<Option<OsString>> = path_components(path);
    let mut hops = 0;
    // Set once a component does not exist (or is not a directory). From then on
    // nothing is resolved: the kernel would already have failed the lookup.
    let mut missing: Option<PathBuf> = None;

    while let Some(component) = queue.pop_front() {
        let Some(name) = component else {
            // `..` must not pop a component that failed to resolve: that would
            // turn a broken path (`missing/../x`) into a different, existing file.
            if let Some(missing) = &missing {
                bail!(
                    "{} cannot be resolved inside {}: {} does not exist or is not a directory",
                    path.display(),
                    root.display(),
                    missing.display()
                );
            }
            resolved.pop();
            continue;
        };
        if missing.is_some() {
            resolved.push(name);
            continue;
        }
        let candidate = join_under(root, &resolved).join(&name);
        match fs::symlink_metadata(&candidate) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    bail!(
                        "too many symlink levels resolving {} inside {}",
                        path.display(),
                        root.display()
                    );
                }
                let target = fs::read_link(&candidate)
                    .with_context(|| format!("failed to read symlink {}", candidate.display()))?;
                if target.has_root() {
                    resolved.clear();
                }
                for component in path_components(&target).into_iter().rev() {
                    queue.push_front(component);
                }
            }
            Ok(meta) => {
                // A non-directory ends the walk for any component after it,
                // exactly as ENOTDIR would.
                if !meta.is_dir() {
                    missing = Some(candidate);
                }
                resolved.push(name)
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                missing = Some(candidate);
                resolved.push(name)
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect {} while resolving {} inside {}",
                        candidate.display(),
                        path.display(),
                        root.display()
                    )
                })
            }
        }
    }

    let result = join_under(root, &resolved);
    ensure!(
        result.starts_with(root)
            && !result
                .strip_prefix(root)
                .unwrap_or(&result)
                .components()
                .any(|component| !matches!(component, Component::Normal(_))),
        "{} resolved to {}, outside {}",
        path.display(),
        result.display(),
        root.display()
    );
    Ok(result)
}

/// If `path` lies under `/proc/<pid>/root`, re-resolve it inside that root (see
/// [`resolve_in_root`]); any other path is returned unchanged. For paths built
/// by joining onto an already-resolved target path (debug-file candidates).
pub fn confine_to_proc_root(path: &Path) -> Result<PathBuf> {
    match proc_root_split(path) {
        Some((root, inner)) => resolve_in_root(&root, &inner),
        None => Ok(path.to_path_buf()),
    }
}

/// Split `/proc/<digits>/root/<rest>` into (`/proc/<digits>/root`, `/<rest>`).
fn proc_root_split(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal("proc".as_ref()))
    {
        return None;
    }
    let Some(Component::Normal(pid)) = components.next() else {
        return None;
    };
    let pid = pid.to_str()?;
    if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if components.next() != Some(Component::Normal("root".as_ref())) {
        return None;
    }
    let root = Path::new("/proc").join(pid).join("root");
    Some((root, Path::new("/").join(components.as_path())))
}

/// `path`'s components as names, with `..` as `None`; `/` and `.` are dropped
/// (the walk is always relative to the root).
fn path_components(path: &Path) -> VecDeque<Option<OsString>> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(Some(name.to_os_string())),
            Component::ParentDir => Some(None),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

fn join_under(root: &Path, names: &[OsString]) -> PathBuf {
    let mut path = root.to_path_buf();
    path.extend(names);
    path
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
            max_buffered_events: None,
            otlp_diagnostics: false,
            redact_object_names: false,
            correlation_ttl: std::time::Duration::from_secs(120),
            correlate_inferred: false,
            correlate_cross_thread: false,
            disable_rgw_op_bridge_key: false,
            inference_window: std::time::Duration::from_secs(1),
            inference_max_pending: crate::collector::DEFAULT_INFERENCE_MAX_PENDING,
            closed_request_grace: std::time::Duration::from_secs(5),
            service_name: "rgwtrace".to_string(),
            log_level: "warn".to_string(),
            pid: None,
            all_processes: false,
            timeout: None,
            ringbuf_size: 16 * 1024 * 1024,
            bpf_rados_ops_entries: 32768,
            rados_ops_stale_after: std::time::Duration::from_secs(300),
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

        let path =
            discover_optional_library("librbd.so.1", None, Some(i32::MAX), Some(&maps)).unwrap();

        assert_eq!(path, None);
    }

    #[test]
    fn process_maps_report_namespace_paths_per_soname() {
        let maps = parse_process_maps(
            "7f-8 r-xp 00000000 08:01 1 /usr/lib/librados.so.2.0.0\n\
             8f-9 r-xp 00000000 08:01 2 /usr/lib/libceph-common.so.2\n",
        );

        assert_eq!(
            maps.get("librados.so.2"),
            Some(&MappedFile {
                path: PathBuf::from("/usr/lib/librados.so.2.0.0"),
                deleted: false,
            })
        );
        assert_eq!(
            maps.get("libceph-common.so.2"),
            Some(&MappedFile {
                path: PathBuf::from("/usr/lib/libceph-common.so.2"),
                deleted: false,
            })
        );
    }

    /// F8: a mapping whose file was replaced on disk (package upgrade) ends in
    /// ` (deleted)`. It used to be skipped -- its last whitespace token is not a
    /// path -- and discovery fell back to the NEW on-disk file, which the process
    /// does not map: attach succeeded and zero events arrived.
    #[test]
    fn process_maps_flag_deleted_mappings() {
        let maps = parse_process_maps(
            "7f-8 r-xp 00000000 08:01 1                          \
             /usr/lib/librados.so.2.0.0 (deleted)\n",
        );

        assert_eq!(
            maps.get("librados.so.2"),
            Some(&MappedFile {
                path: PathBuf::from("/usr/lib/librados.so.2.0.0"),
                deleted: true,
            })
        );
    }

    #[test]
    fn process_maps_keep_paths_with_spaces() {
        let maps = parse_process_maps("7f-8 r-xp 00000000 08:01 1 /opt/my ceph/librbd.so.1.12.0\n");

        assert_eq!(
            maps.get("librbd.so.1").map(|mapped| mapped.path.clone()),
            Some(PathBuf::from("/opt/my ceph/librbd.so.1.12.0"))
        );
    }

    #[test]
    fn a_deleted_library_mapping_is_a_hard_error_naming_the_file() {
        let maps = BTreeMap::from([(
            "librados.so.2".to_string(),
            MappedFile {
                path: PathBuf::from("/usr/lib/librados.so.2.0.0"),
                deleted: true,
            },
        )]);

        let err = discover_library("librados.so.2", None, Some(42), Some(&maps))
            .unwrap_err()
            .to_string();

        assert!(err.contains("/usr/lib/librados.so.2.0.0"), "{err}");
        assert!(err.contains("deleted"), "{err}");
        assert!(err.contains("restart"), "{err}");
    }

    #[test]
    fn mapped_libraries_are_rooted_for_pid_namespace() {
        let maps = BTreeMap::from([(
            "librados.so.2".to_string(),
            MappedFile {
                path: PathBuf::from("/usr/lib/librados.so.2.0.0"),
                deleted: false,
            },
        )]);

        let path = discover_library("librados.so.2", None, Some(i32::MAX), Some(&maps)).unwrap();

        assert_eq!(
            path,
            PathBuf::from(format!("/proc/{}/root/usr/lib/librados.so.2.0.0", i32::MAX))
        );
    }

    #[test]
    fn missing_required_pid_root_library_is_an_error() {
        let pid = i32::MAX;
        let err = required_library_in_pid_root(
            pid,
            "librados.so.2",
            [PathBuf::from("/definitely-not-present/librados.so.2")],
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("inside pid"), "{err}");
        assert!(err.contains("--librados-path"), "{err}");
    }

    /// F8: `/proc/<pid>/exe` of an upgraded daemon reads `.../radosgw (deleted)`.
    /// That used to fail the basename check and fall back SILENTLY to the host's
    /// /usr/bin/radosgw -- a different inode from the one running.
    #[test]
    fn a_deleted_radosgw_executable_is_a_hard_error() {
        let err = radosgw_exe_path(42, Path::new("/usr/bin/radosgw (deleted)"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("/usr/bin/radosgw"), "{err}");
        assert!(err.contains("restart"), "{err}");
    }

    #[test]
    fn a_pid_that_is_not_radosgw_is_an_error_not_a_host_fallback() {
        let err = radosgw_exe_path(42, Path::new("/usr/bin/ceph-osd"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("/usr/bin/ceph-osd"), "{err}");
        assert!(err.contains("--radosgw-path"), "{err}");
    }

    #[test]
    fn a_radosgw_executable_is_rooted_for_pid_namespace() {
        let pid = i32::MAX;
        assert_eq!(
            radosgw_exe_path(pid, Path::new("/usr/bin/radosgw")).unwrap(),
            PathBuf::from(format!("/proc/{pid}/root/usr/bin/radosgw"))
        );
        assert_eq!(
            radosgw_exe_path(pid, Path::new("/usr/bin/ceph-radosgw")).unwrap(),
            PathBuf::from(format!("/proc/{pid}/root/usr/bin/ceph-radosgw"))
        );
    }

    #[test]
    fn pid_root_path_prefixes_absolute_namespace_path() {
        let pid = i32::MAX;
        assert_eq!(
            pid_root_path(pid, Path::new("/usr/bin/radosgw")).unwrap(),
            PathBuf::from(format!("/proc/{pid}/root/usr/bin/radosgw"))
        );
    }

    /// A scratch directory standing in for a container root.
    struct FakeRoot(PathBuf);

    impl FakeRoot {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("rgwtrace-root-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("usr/lib")).unwrap();
            fs::write(dir.join("usr/lib/librados.so.2.0.0"), b"x").unwrap();
            Self(dir)
        }
    }

    impl Drop for FakeRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// F20: a container's ABSOLUTE symlink means "from the container root". Opened
    /// by name under /proc/<pid>/root, the kernel resolves it against the HOST
    /// root instead -- probing (or parsing DWARF from) a host file the container
    /// never maps.
    #[test]
    fn absolute_symlinks_resolve_inside_the_root() {
        let root = FakeRoot::new("abs");
        std::os::unix::fs::symlink(
            "/usr/lib/librados.so.2.0.0",
            root.0.join("usr/lib/librados.so.2"),
        )
        .unwrap();

        let resolved = resolve_in_root(&root.0, Path::new("/usr/lib/librados.so.2")).unwrap();

        assert_eq!(resolved, root.0.join("usr/lib/librados.so.2.0.0"));
    }

    #[test]
    fn dot_dot_cannot_climb_out_of_the_root() {
        let root = FakeRoot::new("dotdot");
        std::os::unix::fs::symlink(
            "../../../../../../usr/lib/librados.so.2.0.0",
            root.0.join("usr/lib/escape"),
        )
        .unwrap();

        let via_link = resolve_in_root(&root.0, Path::new("/usr/lib/escape")).unwrap();
        let via_path =
            resolve_in_root(&root.0, Path::new("/../../usr/lib/librados.so.2.0.0")).unwrap();

        assert_eq!(via_link, root.0.join("usr/lib/librados.so.2.0.0"));
        assert_eq!(via_path, root.0.join("usr/lib/librados.so.2.0.0"));
    }

    #[test]
    fn relative_symlinks_resolve_against_their_own_directory() {
        let root = FakeRoot::new("rel");
        fs::create_dir_all(root.0.join("lib64")).unwrap();
        std::os::unix::fs::symlink(
            "../usr/lib/librados.so.2.0.0",
            root.0.join("lib64/librados.so.2"),
        )
        .unwrap();

        let resolved = resolve_in_root(&root.0, Path::new("/lib64/librados.so.2")).unwrap();

        assert_eq!(resolved, root.0.join("usr/lib/librados.so.2.0.0"));
    }

    #[test]
    fn symlink_loops_are_an_error() {
        let root = FakeRoot::new("loop");
        std::os::unix::fs::symlink("/usr/lib/b", root.0.join("usr/lib/a")).unwrap();
        std::os::unix::fs::symlink("/usr/lib/a", root.0.join("usr/lib/b")).unwrap();

        let err = resolve_in_root(&root.0, Path::new("/usr/lib/a")).unwrap_err();

        assert!(err.to_string().contains("symlink"), "{err}");
    }

    /// Greptile #2 on PR #10: `missing/../x` must not resolve to an existing `x`.
    /// The kernel fails the lookup at `missing`; a walker that lets the later
    /// `..` pop the missing component turns a broken path into another file.
    #[test]
    fn dot_dot_after_a_missing_component_does_not_resolve() {
        let root = FakeRoot::new("missingdotdot");
        std::os::unix::fs::symlink(
            "missing/../librados.so.2.0.0",
            root.0.join("usr/lib/broken"),
        )
        .unwrap();

        assert!(resolve_in_root(&root.0, Path::new("/usr/lib/broken")).is_err());
        assert!(
            resolve_in_root(&root.0, Path::new("/usr/lib/missing/../librados.so.2.0.0")).is_err()
        );
        // A file used as a directory fails the same way.
        assert!(resolve_in_root(
            &root.0,
            Path::new("/usr/lib/librados.so.2.0.0/../librados.so.2.0.0")
        )
        .is_err());
    }

    /// Greptile #1 on PR #10: one unresolvable FALLBACK location (here a symlink
    /// loop) must be skipped, not abort discovery, when a later location holds
    /// the file. Linux-only: it needs a real `/proc/<pid>/root`.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unresolvable_fallback_location_is_skipped() {
        let root = FakeRoot::new("fallbackloop");
        std::os::unix::fs::symlink("loop", root.0.join("usr/loop")).unwrap();
        let pid = i32::try_from(std::process::id()).unwrap();
        let inside = root.0.strip_prefix("/").unwrap();
        let candidates = vec![
            Path::new("/").join(inside).join("usr/loop/librados.so.2"),
            Path::new("/")
                .join(inside)
                .join("usr/lib/librados.so.2.0.0"),
        ];

        let found = first_existing_in_pid_root(pid, candidates);

        assert_eq!(
            found,
            Some(
                proc_root(pid)
                    .join(inside)
                    .join("usr/lib/librados.so.2.0.0")
            )
        );
    }

    #[test]
    fn missing_components_are_kept_verbatim() {
        let root = FakeRoot::new("missing");

        let resolved = resolve_in_root(&root.0, Path::new("/opt/ceph/librados.so.2")).unwrap();

        assert_eq!(resolved, root.0.join("opt/ceph/librados.so.2"));
    }

    #[test]
    fn only_proc_root_paths_are_confined() {
        assert_eq!(
            confine_to_proc_root(Path::new("/usr/lib/debug/radosgw.debug")).unwrap(),
            PathBuf::from("/usr/lib/debug/radosgw.debug")
        );
        assert_eq!(
            proc_root_split(Path::new("/proc/42/root/usr/bin/radosgw")),
            Some((
                PathBuf::from("/proc/42/root"),
                PathBuf::from("/usr/bin/radosgw")
            ))
        );
        assert_eq!(proc_root_split(Path::new("/proc/self/root/usr")), None);
        assert_eq!(proc_root_split(Path::new("/proc/42/cwd/usr")), None);
    }
}
