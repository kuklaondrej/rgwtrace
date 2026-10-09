//! Startup validation of the OTLP export configuration: `--output otlp` must
//! refuse a bad CA certificate, header file, or header value BEFORE DWARF
//! loading and probe attach, with an error that names the flag.

use std::process::Command;

fn rgwtrace() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rgwtrace"));
    command.args([
        "--import-json",
        "tests/fixtures/minimal_dwarf.json",
        "--dry-run",
        "--output",
        "otlp",
    ]);
    // The environment is part of the configuration under test.
    command.env_remove("OTEL_EXPORTER_OTLP_HEADERS");
    command.env_remove("OTEL_EXPORTER_OTLP_TRACES_HEADERS");
    command
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn rejects_a_ca_cert_that_is_not_pem_at_startup() {
    let output = rgwtrace()
        .args(["--otlp-ca-cert", "tests/fixtures/minimal_dwarf.json"])
        .output()
        .expect("failed to run rgwtrace");

    assert!(
        !output.status.success(),
        "a non-PEM CA file must be refused"
    );
    let stderr = stderr_of(&output);
    assert!(stderr.contains("PEM"), "the error must say why: {stderr}");
    assert!(
        !stderr.contains("loading DWARF"),
        "the refusal must come before DWARF loading: {stderr}"
    );
}

#[test]
fn rejects_a_missing_ca_cert_file_at_startup() {
    let output = rgwtrace()
        .args(["--otlp-ca-cert", "tests/fixtures/does-not-exist.pem"])
        .output()
        .expect("failed to run rgwtrace");

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("--otlp-ca-cert"), "{stderr}");
}

#[test]
fn accepts_a_pem_ca_cert() {
    // A dry run exports nothing (no spans, diagnostics off), so this exercises
    // only the startup validation and never touches the network.
    let output = rgwtrace()
        .args(["--otlp-ca-cert", "tests/fixtures/otlp_test_ca.pem"])
        .output()
        .expect("failed to run rgwtrace");

    assert!(output.status.success(), "{}", stderr_of(&output));
}

#[cfg(unix)]
#[test]
fn refuses_a_world_readable_header_file_at_startup() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("rgwtrace-cli-headers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("headers");
    std::fs::write(&path, "X-Api-Key: hunter2-cli-secret\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = rgwtrace()
        .args(["--otlp-header-file", path.to_str().unwrap()])
        .output()
        .expect("failed to run rgwtrace");

    assert!(
        !output.status.success(),
        "a world-readable header file must be refused"
    );
    let stderr = stderr_of(&output);
    assert!(stderr.contains("world-readable"), "{stderr}");
    assert!(
        !stderr.contains("hunter2"),
        "the secret leaked into stderr: {stderr}"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = rgwtrace()
        .args(["--otlp-header-file", path.to_str().unwrap()])
        .output()
        .expect("failed to run rgwtrace");
    assert!(output.status.success(), "{}", stderr_of(&output));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rejects_malformed_otel_headers_env_at_startup() {
    let output = rgwtrace()
        .env(
            "OTEL_EXPORTER_OTLP_HEADERS",
            "X-Api-Key=ok,hunter2-env-secret",
        )
        .output()
        .expect("failed to run rgwtrace");

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("OTEL_EXPORTER_OTLP_HEADERS"), "{stderr}");
    assert!(
        !stderr.contains("hunter2"),
        "the secret leaked into stderr: {stderr}"
    );
}

#[test]
fn accepts_otel_headers_env() {
    let output = rgwtrace()
        .env(
            "OTEL_EXPORTER_OTLP_HEADERS",
            "X-Api-Key=abc%20def,X-Scope-OrgID=t1",
        )
        .output()
        .expect("failed to run rgwtrace");

    assert!(output.status.success(), "{}", stderr_of(&output));
}
