//! Where the OTLP request headers come from, and how the sources combine.
//!
//! Three sources, merged by header name (case-insensitive) with a fixed
//! precedence -- a name present in more than one source takes the value from
//! the highest:
//!
//! ```text
//! --otlp-header-file <path>              highest   one `Name: Value` per line
//! OTEL_EXPORTER_OTLP_TRACES_HEADERS,               `k=v,k2=v2`, percent-encoded
//!   else OTEL_EXPORTER_OTLP_HEADERS                (the OpenTelemetry spec's form)
//! --otlp-header 'Name:Value' (repeatable) lowest    visible to every local user
//! ```
//!
//! The order is the inverse of how exposed each source is. A flag is on argv,
//! readable by every local user through `/proc/<pid>/cmdline`, so it is the
//! right place for a tenant id and the wrong place for an API key; a secret
//! that reaches us through a file or the environment must not be overridden
//! by whatever happens to be on the command line. Merging (rather than
//! "first source wins outright") lets the secret live in the file and the
//! non-secret headers stay on the command line.
//!
//! No function here ever puts a header VALUE into an error or a log line: an
//! error names the source, the line or entry number and the header name only.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::cli::Cli;

/// The OpenTelemetry generic headers variable, applied to every signal.
pub const HEADERS_ENV: &str = "OTEL_EXPORTER_OTLP_HEADERS";

/// The traces-specific variable. Per the spec it REPLACES the generic one when
/// set (the two are not merged).
pub const TRACES_HEADERS_ENV: &str = "OTEL_EXPORTER_OTLP_TRACES_HEADERS";

/// The effective headers for this run: flags, environment and file, merged.
/// Reads the environment and the file, so a malformed, missing, or exposed
/// source fails here -- at startup, before anything is attached.
pub fn load(cli: &Cli) -> Result<Vec<(String, String)>> {
    let env = env_headers()?;
    let file = cli
        .otlp_header_file
        .as_deref()
        .map(read_header_file)
        .transpose()?
        .unwrap_or_default();
    Ok(merge(&cli.otlp_header, env, file))
}

/// Headers from the environment: the traces-specific variable if set, else
/// the generic one, else none.
fn env_headers() -> Result<Vec<(String, String)>> {
    for name in [TRACES_HEADERS_ENV, HEADERS_ENV] {
        match std::env::var(name) {
            Ok(value) => {
                return parse_env_headers(&value).with_context(|| format!("invalid {name}"))
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid UTF-8"),
        }
    }
    Ok(Vec::new())
}

/// Merge the three sources: later arguments win over earlier ones for the
/// same header name, compared case-insensitively (HTTP header names are).
/// The relative order of distinct names follows first appearance.
pub fn merge(
    flags: &[(String, String)],
    env: Vec<(String, String)>,
    file: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut merged: Vec<(String, String)> = Vec::new();
    for (name, value) in flags.iter().cloned().chain(env).chain(file) {
        match merged
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(&name))
        {
            Some(slot) => slot.1 = value,
            None => merged.push((name, value)),
        }
    }
    merged
}

/// Parse the OpenTelemetry environment form: comma-separated `key=value`
/// pairs, each key and value percent-encoded (W3C Baggage style), whitespace
/// around either stripped. An entry is reported by its position only.
pub fn parse_env_headers(value: &str) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for (index, entry) in value.split(',').enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let position = index + 1;
        let Some((name, value)) = entry.split_once('=') else {
            bail!("entry {position} is not a key=value pair");
        };
        let name = percent_decode(name.trim()).with_context(|| {
            format!("entry {position}: header name is not valid percent-encoding")
        })?;
        let value = percent_decode(value.trim()).with_context(|| {
            format!("entry {position}: value of {name:?} is not valid percent-encoding")
        })?;
        if name.is_empty() || value.is_empty() {
            bail!("entry {position}: header name and value must be non-empty");
        }
        headers.push((name, value));
    }
    Ok(headers)
}

/// Parse the header file form: one `Name: Value` per line; blank lines and
/// lines starting with `#` are ignored. A bad line is reported by number, and
/// never quoted -- it may be the secret, mistyped.
pub fn parse_header_file(contents: &str) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let Some((name, value)) = line.split_once(':') else {
            bail!("line {number} is not a `Name: Value` header");
        };
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() || value.is_empty() {
            bail!("line {number}: header name and value must be non-empty");
        }
        headers.push((name.to_string(), value.to_string()));
    }
    Ok(headers)
}

/// Read and parse `--otlp-header-file`. The file exists to keep credentials
/// off argv, so one that any local user can read defeats its purpose and is
/// refused outright rather than warned about: a warning scrolls past, and the
/// secret is already exposed by the time it does.
fn read_header_file(path: &Path) -> Result<Vec<(String, String)>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to read --otlp-header-file {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "--otlp-header-file {} is not a regular file",
            path.display()
        );
    }
    refuse_world_readable(path, &metadata)?;
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read --otlp-header-file {}", path.display()))?;
    parse_header_file(&contents)
        .with_context(|| format!("invalid --otlp-header-file {}", path.display()))
}

#[cfg(unix)]
fn refuse_world_readable(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o004 != 0 {
        bail!(
            "--otlp-header-file {} is world-readable (mode {mode:03o}); it holds credentials, \
             so restrict it (chmod 600 or 640) and retry",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_world_readable(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

/// Decode `%XX` escapes. Only percent-encoding: `+` is a literal plus (this is
/// the Baggage/URI form, not `application/x-www-form-urlencoded`).
fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let digits = bytes
                .get(index + 1..index + 3)
                .and_then(|pair| std::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok());
            let Some(byte) = digits else {
                bail!("incomplete percent-escape at byte {index}");
            };
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).context("percent-decoded bytes are not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[test]
    fn parses_the_otel_env_form_with_percent_decoding() {
        let headers =
            parse_env_headers(" X-Api-Key=abc%20def , X-Scope-OrgID=tenant%2F1,,").unwrap();
        assert_eq!(
            headers,
            vec![
                header("X-Api-Key", "abc def"),
                header("X-Scope-OrgID", "tenant/1")
            ]
        );
        // `+` is a literal, and `=` may appear in a value (base64 padding).
        let headers = parse_env_headers("Authorization=Basic+Zm9v==").unwrap();
        assert_eq!(headers, vec![header("Authorization", "Basic+Zm9v==")]);
    }

    #[test]
    fn env_form_errors_name_the_entry_and_never_the_value() {
        let err = parse_env_headers("X-Api-Key=ok,hunter2-no-equals").unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("entry 2"), "{message}");
        assert!(!message.contains("hunter2"), "leaked: {message}");

        let err = parse_env_headers("X-Api-Key=hunter2%zz").unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("percent-encoding"), "{message}");
        assert!(!message.contains("hunter2"), "leaked: {message}");
    }

    #[test]
    fn parses_the_header_file_form() {
        let headers = parse_header_file(
            "# collector auth\n\nX-Api-Key: hunter2 \n  X-Scope-OrgID:tenant-1\n# trailing\n",
        )
        .unwrap();
        assert_eq!(
            headers,
            vec![
                header("X-Api-Key", "hunter2"),
                header("X-Scope-OrgID", "tenant-1")
            ]
        );
    }

    #[test]
    fn header_file_errors_name_the_line_and_never_its_content() {
        let err = parse_header_file("X-Api-Key: ok\nX-Api-Key hunter2-forgot-colon\n").unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("line 2"), "{message}");
        assert!(!message.contains("hunter2"), "leaked: {message}");

        let err = parse_header_file("X-Api-Key:\n").unwrap_err();
        assert!(format!("{err:#}").contains("line 1"));
    }

    #[test]
    fn file_beats_env_beats_flags_by_case_insensitive_name() {
        let flags = vec![header("X-Api-Key", "from-flag"), header("X-Flag-Only", "f")];
        let env = vec![header("x-api-key", "from-env"), header("X-Env-Only", "e")];
        let file = vec![header("X-API-KEY", "from-file"), header("X-File-Only", "g")];

        let merged = merge(&flags, env, file);

        assert_eq!(
            merged,
            vec![
                // Keeps the first-seen spelling and position; takes the highest
                // source's value.
                header("X-Api-Key", "from-file"),
                header("X-Flag-Only", "f"),
                header("X-Env-Only", "e"),
                header("X-File-Only", "g"),
            ]
        );
        assert_eq!(
            merge(&[], vec![header("A", "env")], vec![]),
            vec![header("A", "env")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_world_readable_header_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwtrace-headers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("headers");
        std::fs::write(&path, "X-Api-Key: hunter2\n").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_header_file(&path).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("world-readable"), "{message}");
        assert!(message.contains("644"), "{message}");
        assert!(!message.contains("hunter2"), "leaked: {message}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            read_header_file(&path).unwrap(),
            vec![header("X-Api-Key", "hunter2")]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_header_file_names_the_flag() {
        let err = read_header_file(Path::new("/nonexistent/rgwtrace/headers")).unwrap_err();
        assert!(format!("{err:#}").contains("--otlp-header-file"));
    }
}
