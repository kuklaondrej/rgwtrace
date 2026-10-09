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

// ---------------------------------------------------------------------------
// CA TRUST, end to end. Parsing a PEM proves nothing about trust; these run
// the binary against a local HTTPS collector whose certificate is signed by
// the fixture CA. `--otlp-diagnostics` makes the dry run's final export put a
// run-summary batch on the wire, so a real TLS handshake and request happen.
//
// Fixtures (tests/fixtures/otlp_test_*): a self-signed CA (certificate only;
// its key was discarded after signing), an UNRELATED self-signed CA, and a
// server certificate for IP 127.0.0.1 with its PKCS#8 key. The key is
// test-only material: it signs nothing but this loopback server.
// ---------------------------------------------------------------------------

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
    time::Duration,
};

/// What the TLS collector saw on its one connection.
#[derive(Debug)]
enum TlsOutcome {
    /// The handshake (or the read after it) failed; carries the error text.
    Rejected(String),
    /// A request arrived and was answered 200; carries the body length.
    Served(usize),
}

fn tls_server_config() -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let certificate =
        CertificateDer::from(include_bytes!("fixtures/otlp_test_server.der").as_slice());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/otlp_test_server_key.der").as_slice(),
    ));
    // The same provider reqwest's rustls-tls uses; built explicitly so no
    // process-global provider is installed.
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate], key)
    .unwrap();
    Arc::new(config)
}

/// An HTTPS collector that accepts ONE connection, serves one request and
/// reports what happened. Returns the endpoint URL and the outcome handle.
fn spawn_tls_collector() -> (String, thread::JoinHandle<TlsOutcome>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("https://{}/v1/traces", listener.local_addr().unwrap());
    let config = tls_server_config();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("the client always connects");
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut connection = rustls::ServerConnection::new(config).unwrap();
        let mut tls = rustls::Stream::new(&mut connection, &mut tcp);

        // The handshake runs inside the first read; a client that distrusts
        // the certificate aborts it with an alert, which surfaces here.
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        let body_len = loop {
            match tls.read(&mut chunk) {
                Ok(0) => return TlsOutcome::Rejected("connection closed".to_string()),
                Ok(n) => request.extend_from_slice(&chunk[..n]),
                Err(err) => return TlsOutcome::Rejected(err.to_string()),
            }
            let Some(headers_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..headers_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= headers_end + 4 + content_length {
                break content_length;
            }
        };
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        tls.conn.send_close_notify();
        tls.flush().ok();
        TlsOutcome::Served(body_len)
    });
    (endpoint, handle)
}

/// Run the binary against `endpoint` with `extra` args; the export is forced
/// onto the wire by `--otlp-diagnostics`.
fn run_against(endpoint: &str, extra: &[&str]) -> std::process::Output {
    rgwtrace()
        .args([
            "--otlp-diagnostics",
            "--otlp-retries",
            "0",
            "--otlp-endpoint",
            endpoint,
        ])
        .args(extra)
        .output()
        .expect("failed to run rgwtrace")
}

#[test]
fn https_collector_is_rejected_without_the_ca() {
    let (endpoint, collector) = spawn_tls_collector();

    let output = run_against(&endpoint, &[]);

    assert!(
        !output.status.success(),
        "an unknown CA must not be trusted"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("certificate"),
        "the error must name the cause: {stderr}"
    );
    expect_rejected(collector.join().unwrap());
}

/// The collector must have seen the handshake aborted, with rustls saying why.
fn expect_rejected(outcome: TlsOutcome) {
    match outcome {
        TlsOutcome::Rejected(reason) => {
            assert!(!reason.is_empty(), "rustls reports the alert it received")
        }
        served => panic!("the client must abort the handshake, not send the request: {served:?}"),
    }
}

#[test]
fn https_collector_is_rejected_with_an_unrelated_ca() {
    let (endpoint, collector) = spawn_tls_collector();

    let output = run_against(
        &endpoint,
        &["--otlp-ca-cert", "tests/fixtures/otlp_test_other_ca.pem"],
    );

    assert!(
        !output.status.success(),
        "a CA that did not sign the server must not vouch for it"
    );
    assert!(stderr_of(&output).contains("certificate"));
    expect_rejected(collector.join().unwrap());
}

#[test]
fn https_collector_is_trusted_with_the_ca_cert() {
    let (endpoint, collector) = spawn_tls_collector();

    let output = run_against(
        &endpoint,
        &["--otlp-ca-cert", "tests/fixtures/otlp_test_ca.pem"],
    );

    assert!(output.status.success(), "{}", stderr_of(&output));
    match collector.join().unwrap() {
        TlsOutcome::Served(body_len) => {
            assert!(
                body_len > 0,
                "the run-summary batch must have been delivered"
            )
        }
        rejected => panic!("the export must reach the collector over TLS: {rejected:?}"),
    }
}
