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

    assert!(!output.status.success(), "a non-PEM CA file must be refused");
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
