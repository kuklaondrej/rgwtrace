use std::{error::Error as StdError, io::Write, thread, time::Duration};

use anyhow::{bail, Context, Result};
use flate2::{write::GzEncoder, Compression as GzipCompression};
use opentelemetry_proto::tonic::{
    collector::trace::v1::ExportTraceServiceRequest,
    common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue},
    resource::v1::Resource,
    trace::v1::{span, ResourceSpans, ScopeSpans, Span},
};
use prost::Message;
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_ENCODING, CONTENT_TYPE},
    StatusCode, Url,
};
use tracing::{debug, info, warn};

use crate::{
    cli::OtlpCompression,
    collector::{Attribute, AttributeValue, SpanDocument, SpanEvent, TraceDocument},
};

const OTLP_PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";

#[derive(Clone, Copy, Debug, Default)]
pub struct ExportDiagnostics {
    pub batches: u64,
    pub attempts: u64,
    pub failures: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ExportConfig<'a> {
    pub endpoint: &'a str,
    pub headers: &'a [(String, String)],
    pub compression: OtlpCompression,
    pub max_spans_per_batch: usize,
    pub max_bytes_per_batch: usize,
    pub timeout: Duration,
    pub retries: u32,
}

pub fn export_otlp_http(
    config: ExportConfig<'_>,
    document: &TraceDocument,
) -> Result<ExportDiagnostics> {
    validate_otlp_endpoint(config.endpoint)?;
    if config.max_spans_per_batch == 0 {
        bail!("OTLP max spans per batch must be at least 1");
    }

    let batches = otlp_batches(
        document,
        config.max_spans_per_batch,
        config.max_bytes_per_batch,
    )?;
    let client = Client::builder()
        .timeout(config.timeout)
        .build()
        .context("failed to build OTLP HTTP client")?;

    let max_attempts = config.retries.saturating_add(1);
    let mut diagnostics = ExportDiagnostics {
        batches: batches.len() as u64,
        ..ExportDiagnostics::default()
    };
    for (batch_idx, batch) in batches.iter().enumerate() {
        let protobuf_body = to_otlp_protobuf(batch)?;
        let body = encode_body(protobuf_body, config.compression)?;
        let headers = otlp_headers(config.headers, body.content_encoding)?;
        for attempt in 1..=max_attempts {
            diagnostics.attempts += 1;
            debug!(
                attempt,
                max_attempts,
                batch = batch_idx + 1,
                batches = batches.len(),
                endpoint = config.endpoint,
                timeout_ms = config.timeout.as_millis(),
                spans = batch.spans.len(),
                body_bytes = body.bytes.len(),
                uncompressed_body_bytes = body.uncompressed_len,
                compression = ?config.compression,
                "exporting OTLP traces"
            );
            match send_once(
                &client,
                config.endpoint,
                headers.clone(),
                body.bytes.clone(),
            ) {
                Ok(()) => {
                    info!(
                        spans = batch.spans.len(),
                        batch = batch_idx + 1,
                        batches = batches.len(),
                        attempt,
                        "exported OTLP traces"
                    );
                    break;
                }
                Err(err) if attempt < max_attempts && err.retryable => {
                    diagnostics.failures += 1;
                    warn!(attempt, error = %err.message, "OTLP export failed; retrying");
                    thread::sleep(retry_delay(attempt));
                }
                Err(err) => {
                    diagnostics.failures += 1;
                    bail!(
                        "{}; export batches: {}, export attempts: {}, export failures: {}",
                        err.message,
                        diagnostics.batches,
                        diagnostics.attempts,
                        diagnostics.failures
                    )
                }
            }
        }
    }

    Ok(diagnostics)
}

pub fn to_otlp_protobuf(document: &TraceDocument) -> Result<Vec<u8>> {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![string_key_value("service.name", &document.service_name)],
                dropped_attributes_count: 0,
                entity_refs: Vec::new(),
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "rgwtrace".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    attributes: Vec::new(),
                    dropped_attributes_count: 0,
                }),
                spans: document
                    .spans
                    .iter()
                    .map(span_to_otlp)
                    .collect::<Result<_>>()?,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    };

    Ok(request.encode_to_vec())
}

fn send_once(
    client: &Client,
    endpoint: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> Result<(), ExportError> {
    let response = client
        .post(endpoint)
        .headers(headers)
        .body(body)
        .send()
        .map_err(|err| {
            ExportError::retryable(format!(
                "failed to send OTLP request to {endpoint}: {}",
                error_chain(&err)
            ))
        })?;
    let status = response.status();

    if status.is_success() {
        return Ok(());
    }

    let body = response
        .text()
        .unwrap_or_else(|err| format!("failed to read response body: {err}"));
    let message = format!("OTLP endpoint returned {status}: {body}");
    if is_retryable_status(status) {
        Err(ExportError::retryable(message))
    } else {
        Err(ExportError::fatal(message))
    }
}

fn span_to_otlp(span: &SpanDocument) -> Result<Span> {
    Ok(Span {
        trace_id: decode_hex_id(&span.trace_id, 16, "trace_id")?,
        span_id: decode_hex_id(&span.span_id, 8, "span_id")?,
        trace_state: String::new(),
        parent_span_id: match &span.parent_span_id {
            Some(parent_span_id) => decode_hex_id(parent_span_id, 8, "parent_span_id")?,
            None => Vec::new(),
        },
        flags: 0,
        name: span.name.clone(),
        kind: span::SpanKind::Internal as i32,
        start_time_unix_nano: span.start_ns,
        end_time_unix_nano: span.end_ns,
        attributes: span.attributes.iter().map(attribute_to_otlp).collect(),
        dropped_attributes_count: 0,
        events: span.events.iter().map(event_to_otlp).collect(),
        dropped_events_count: 0,
        links: Vec::new(),
        dropped_links_count: 0,
        status: None,
    })
}

fn event_to_otlp(event: &SpanEvent) -> span::Event {
    span::Event {
        time_unix_nano: event.time_ns,
        name: event.name.clone(),
        attributes: event.attributes.iter().map(attribute_to_otlp).collect(),
        dropped_attributes_count: 0,
    }
}

fn attribute_to_otlp(attribute: &Attribute) -> KeyValue {
    match &attribute.value {
        AttributeValue::String(value) => string_key_value(&attribute.key, value),
        AttributeValue::U64(value) => match i64::try_from(*value) {
            // In-range values are emitted as OTLP int attributes as before.
            Ok(int_value) => KeyValue {
                key: attribute.key.clone(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::IntValue(int_value)),
                }),
                key_strindex: 0,
            },
            // OTLP int attributes are signed 64-bit. Values above i64::MAX
            // (large offsets/lengths/pool ids/durations) cannot be represented
            // without silently clamping and corrupting the reported value, so
            // emit them as a decimal string to preserve data integrity.
            Err(_) => string_key_value(&attribute.key, &value.to_string()),
        },
    }
}

fn string_key_value(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
        key_strindex: 0,
    }
}

fn otlp_headers(
    headers: &[(String, String)],
    content_encoding: Option<&'static str>,
) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid OTLP header name {name:?}"))?;
        let value = HeaderValue::from_str(value)
            .with_context(|| format!("invalid OTLP header value for {name}"))?;
        map.insert(name, value);
    }
    map.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(OTLP_PROTOBUF_CONTENT_TYPE),
    );
    if let Some(content_encoding) = content_encoding {
        map.insert(CONTENT_ENCODING, HeaderValue::from_static(content_encoding));
    }
    Ok(map)
}

fn encode_body(bytes: Vec<u8>, compression: OtlpCompression) -> Result<EncodedBody> {
    let uncompressed_len = bytes.len();
    match compression {
        OtlpCompression::None => Ok(EncodedBody {
            bytes,
            content_encoding: None,
            uncompressed_len,
        }),
        OtlpCompression::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), GzipCompression::default());
            encoder
                .write_all(&bytes)
                .context("failed to gzip OTLP protobuf body")?;
            let bytes = encoder
                .finish()
                .context("failed to finish gzip OTLP protobuf body")?;
            Ok(EncodedBody {
                bytes,
                content_encoding: Some("gzip"),
                uncompressed_len,
            })
        }
    }
}

fn otlp_batches(
    document: &TraceDocument,
    max_spans_per_batch: usize,
    max_bytes_per_batch: usize,
) -> Result<Vec<TraceDocument>> {
    if document.spans.is_empty() {
        return Ok(Vec::new());
    }

    // Fixed cost of a batch carrying the resource/scope envelope but no spans.
    // Cloning the accumulated span vec and re-encoding the whole candidate
    // batch for every appended span is O(n^2) on large drains; instead we
    // encode each span's marginal size once and keep a running total. See
    // `batch_size_estimate` for why the running total is a safe upper bound on
    // the real encoded batch size, so a batch flushed under
    // `max_bytes_per_batch` still respects the limit once actually encoded.
    let base_len = to_otlp_protobuf(&trace_batch(document, Vec::new()))?.len();

    let mut batches = Vec::new();
    let mut spans = Vec::new();
    let mut running_span_bytes = 0usize;
    for span in &document.spans {
        let span_bytes = span_marginal_len(span)?;

        let over_count = !spans.is_empty() && spans.len() >= max_spans_per_batch;
        let over_bytes = max_bytes_per_batch > 0
            && !spans.is_empty()
            && batch_size_estimate(base_len, running_span_bytes + span_bytes) > max_bytes_per_batch;

        if over_count || over_bytes {
            batches.push(trace_batch(document, std::mem::take(&mut spans)));
            running_span_bytes = 0;
        }

        running_span_bytes += span_bytes;
        spans.push(span.clone());
    }
    if !spans.is_empty() {
        batches.push(trace_batch(document, spans));
    }
    Ok(batches)
}

/// Conservative slack (bytes) covering the growth of the two nested protobuf
/// length prefixes (the `scope_spans` and `resource_spans` embedded-message
/// length varints) as spans accumulate. Each such varint is at most 10 bytes,
/// so 10 per nesting level (20 total) always dominates the real growth.
const OTLP_BATCH_FRAMING_SLACK: usize = 20;

/// Upper bound on the wire-tag length for the repeated `spans` field. The real
/// tag is a single byte; 2 leaves headroom against future field renumbering.
const OTLP_SPAN_TAG_MAX: usize = 2;

/// Marginal encoded cost of appending `span` to a batch: its own encoded
/// length plus the framing (field tag + length varint) it contributes to the
/// repeated `spans` field. Each span is encoded exactly once here.
fn span_marginal_len(span: &SpanDocument) -> Result<usize> {
    let encoded = span_to_otlp(span)?.encoded_len();
    Ok(OTLP_SPAN_TAG_MAX + varint_len(encoded) + encoded)
}

/// Upper bound on the fully encoded batch size given the empty-envelope size
/// and the summed marginal span bytes. The real encoded size is
/// `base_len + sum(marginal spans) + growth of the two outer length varints`;
/// the framing slack covers that growth, so this never underestimates.
fn batch_size_estimate(base_len: usize, running_span_bytes: usize) -> usize {
    base_len + OTLP_BATCH_FRAMING_SLACK + running_span_bytes
}

/// Number of bytes a protobuf base-128 varint encoding of `value` occupies.
fn varint_len(value: usize) -> usize {
    let mut len = 1;
    let mut remaining = value >> 7;
    while remaining > 0 {
        len += 1;
        remaining >>= 7;
    }
    len
}

fn trace_batch(document: &TraceDocument, spans: Vec<SpanDocument>) -> TraceDocument {
    TraceDocument {
        service_name: document.service_name.clone(),
        spans,
        diagnostics: document.diagnostics.clone(),
    }
}

struct EncodedBody {
    bytes: Vec<u8>,
    content_encoding: Option<&'static str>,
    uncompressed_len: usize,
}

fn validate_otlp_endpoint(endpoint: &str) -> Result<()> {
    let url =
        Url::parse(endpoint).with_context(|| format!("invalid OTLP endpoint {endpoint:?}"))?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => bail!("unsupported OTLP endpoint scheme {scheme:?}; use http:// or https://"),
    }
}

fn decode_hex_id(value: &str, expected_len: usize, field: &str) -> Result<Vec<u8>> {
    // Operate on raw bytes rather than string slices: `&value[idx..idx + 2]`
    // panics when `idx + 2` falls inside a multibyte UTF-8 char, and the input
    // (trace/span ids) can be arbitrary. Working on bytes makes every branch a
    // recoverable error; non-ASCII bytes simply fail the hex-digit check.
    let bytes = value.as_bytes();
    if bytes.len() != expected_len * 2 {
        bail!("{field} must be {} hex characters", expected_len * 2);
    }

    bytes
        .chunks_exact(2)
        .map(|pair| match (hex_digit(pair[0]), hex_digit(pair[1])) {
            (Some(hi), Some(lo)) => Ok((hi << 4) | lo),
            _ => bail!("{field} contains non-hex data"),
        })
        .collect()
}

/// Decode a single ASCII hex digit byte into its 0..=15 value, or `None`.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn retry_delay(attempt: u32) -> Duration {
    Duration::from_millis(250 * u64::from(attempt.min(8)))
}

fn error_chain(error: &dyn StdError) -> String {
    let mut messages = vec![error.to_string()];
    let mut source = error.source();
    while let Some(error) = source {
        messages.push(error.to_string());
        source = error.source();
    }
    messages.join(": ")
}

struct ExportError {
    message: String,
    retryable: bool,
}

impl ExportError {
    fn retryable(message: String) -> Self {
        Self {
            message,
            retryable: true,
        }
    }

    fn fatal(message: String) -> Self {
        Self {
            message,
            retryable: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::net::{TcpListener, TcpStream};

    use flate2::read::GzDecoder;

    use crate::collector::{AttributeValue, SpanDocument, TraceDiagnostics, TraceDocument};

    #[test]
    fn encodes_otlp_protobuf() {
        let document = trace_document(1);

        let bytes = to_otlp_protobuf(&document).unwrap();
        let request = ExportTraceServiceRequest::decode(bytes.as_slice()).unwrap();

        assert_eq!(request.resource_spans.len(), 1);
        assert_eq!(request.resource_spans[0].scope_spans[0].spans.len(), 1);
        assert_eq!(
            request.resource_spans[0].scope_spans[0].spans[0]
                .trace_id
                .len(),
            16
        );
    }

    #[test]
    fn accepts_http_and_https_endpoints() {
        assert!(validate_otlp_endpoint("http://localhost:4318/v1/traces").is_ok());
        assert!(validate_otlp_endpoint("https://localhost:4318/v1/traces").is_ok());
    }

    #[test]
    fn rejects_unsupported_otlp_endpoints() {
        assert!(validate_otlp_endpoint("grpc://localhost:4317").is_err());
        assert!(validate_otlp_endpoint("localhost:4318/v1/traces").is_err());
    }

    #[test]
    fn leaves_otlp_body_uncompressed_by_default() {
        let bytes = b"protobuf".to_vec();

        let encoded = encode_body(bytes.clone(), OtlpCompression::None).unwrap();

        assert_eq!(encoded.bytes, bytes);
        assert_eq!(encoded.content_encoding, None);
        assert_eq!(encoded.uncompressed_len, 8);
    }

    #[test]
    fn gzips_otlp_body_when_requested() {
        let bytes = b"protobuf protobuf protobuf".to_vec();

        let encoded = encode_body(bytes.clone(), OtlpCompression::Gzip).unwrap();
        let mut decoder = GzDecoder::new(encoded.bytes.as_slice());
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();

        assert_eq!(decoded, bytes);
        assert_eq!(encoded.content_encoding, Some("gzip"));
        assert_eq!(encoded.uncompressed_len, 26);
    }

    #[test]
    fn sets_otlp_content_headers() {
        let headers = otlp_headers(&[], Some("gzip")).unwrap();

        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap(),
            OTLP_PROTOBUF_CONTENT_TYPE
        );
        assert_eq!(headers.get(CONTENT_ENCODING).unwrap(), "gzip");
    }

    #[test]
    fn batches_otlp_spans_by_count() {
        let document = trace_document(5);

        let batches = otlp_batches(&document, 2, 0).unwrap();

        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].spans.len(), 2);
        assert_eq!(batches[1].spans.len(), 2);
        assert_eq!(batches[2].spans.len(), 1);
        assert_eq!(all_span_ids(&batches), all_span_ids(&[document]));
    }

    #[test]
    fn batches_otlp_spans_by_encoded_size() {
        let document = trace_document(3);
        let one_span_size = to_otlp_protobuf(&trace_document(1)).unwrap().len();
        let max_bytes = one_span_size + 8;

        let batches = otlp_batches(&document, 512, max_bytes).unwrap();

        assert_eq!(batches.len(), 3);
        assert!(batches.iter().all(|batch| batch.spans.len() == 1));
        assert_eq!(all_span_ids(&batches), all_span_ids(&[document]));
    }

    #[test]
    fn emits_in_range_u64_attribute_as_int() {
        let attribute = Attribute {
            key: "rgw.length".to_string(),
            value: AttributeValue::U64(42),
        };

        let key_value = attribute_to_otlp(&attribute);

        assert_eq!(
            key_value.value.unwrap().value,
            Some(any_value::Value::IntValue(42))
        );
    }

    #[test]
    fn emits_out_of_range_u64_attribute_as_string() {
        // i64::MAX + 1 cannot be represented as a signed OTLP int; it must be
        // preserved as a string rather than silently clamped.
        let value = i64::MAX as u64 + 1;
        let attribute = Attribute {
            key: "rgw.offset".to_string(),
            value: AttributeValue::U64(value),
        };

        let key_value = attribute_to_otlp(&attribute);

        assert_eq!(
            key_value.value.unwrap().value,
            Some(any_value::Value::StringValue(value.to_string()))
        );
    }

    #[test]
    fn emits_max_u64_attribute_as_string() {
        let attribute = Attribute {
            key: "rgw.duration_ns".to_string(),
            value: AttributeValue::U64(u64::MAX),
        };

        let key_value = attribute_to_otlp(&attribute);

        assert_eq!(
            key_value.value.unwrap().value,
            Some(any_value::Value::StringValue(u64::MAX.to_string()))
        );
    }

    #[test]
    fn decode_hex_id_accepts_valid_input() {
        let decoded = decode_hex_id("00ff01aabbccddee", 8, "span_id").unwrap();

        assert_eq!(
            decoded,
            vec![0x00, 0xff, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
        );
    }

    #[test]
    fn decode_hex_id_rejects_bad_input_without_panicking() {
        // Table of adversarial inputs; none may panic (the previous slice-based
        // implementation panicked on multibyte input at a non-char boundary).
        let cases: &[(&str, usize, &str)] = &[
            // Wrong length.
            ("abc", 8, "too short"),
            ("", 8, "empty"),
            ("00112233445566778899", 8, "too long"),
            // Correct length, non-hex ASCII.
            ("zzzzzzzzzzzzzzzz", 8, "non-hex ascii"),
            ("00112233445566g7", 8, "single non-hex char"),
            // Correct byte length but non-ASCII/multibyte: "a" + "€"*5 = 16 bytes.
            ("a€€€€€", 8, "multibyte utf-8, non-char-boundary slice"),
            // Multibyte with the right byte length for a trace id (32 bytes).
            ("aa€€€€€€€€€€", 16, "multibyte utf-8 trace id"),
        ];

        for (value, expected_len, label) in cases {
            let result = decode_hex_id(value, *expected_len, "field");
            assert!(result.is_err(), "expected error for case: {label}");
        }
    }

    #[test]
    fn batching_estimate_never_underestimates_final_encoded_size() {
        // Vary span sizes so encoded lengths differ and the running estimate is
        // exercised across several batch boundaries.
        let document = trace_document_with_varied_sizes(40);
        let one_span_size = to_otlp_protobuf(&trace_batch(&document, Vec::new()))
            .unwrap()
            .len()
            + 128;
        let max_bytes = one_span_size * 3;

        let batches = otlp_batches(&document, 512, max_bytes).unwrap();

        assert!(batches.len() > 1, "test should exercise multiple batches");
        assert_eq!(all_span_ids(&batches), all_span_ids(&[document]));
        for batch in &batches {
            let encoded = to_otlp_protobuf(batch).unwrap().len();
            assert!(
                batch.spans.len() == 1 || encoded <= max_bytes,
                "flushed batch of {} spans encoded to {} bytes, exceeding max {}",
                batch.spans.len(),
                encoded,
                max_bytes
            );
        }
    }

    #[test]
    fn exports_otlp_traces_on_success() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(200)]);
        let document = trace_document(1);

        let diagnostics = export_otlp_http(export_config(&endpoint, 2), &document).unwrap();

        assert_eq!(diagnostics.batches, 1);
        assert_eq!(diagnostics.attempts, 1);
        assert_eq!(diagnostics.failures, 0);
        assert_eq!(handle.join().unwrap(), 1);
    }

    #[test]
    fn retries_otlp_export_after_retryable_failure() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(503), http_response(200)]);
        let document = trace_document(1);

        let diagnostics = export_otlp_http(export_config(&endpoint, 3), &document).unwrap();

        assert_eq!(diagnostics.attempts, 2, "expected exactly one retry");
        assert_eq!(diagnostics.failures, 1);
        assert_eq!(handle.join().unwrap(), 2, "server should see two requests");
    }

    #[test]
    fn surfaces_non_retryable_otlp_error() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(400)]);
        let document = trace_document(1);

        let err = export_otlp_http(export_config(&endpoint, 3), &document).unwrap_err();

        assert!(
            err.to_string().contains("400"),
            "error should surface status: {err}"
        );
        assert_eq!(handle.join().unwrap(), 1, "must not retry a 4xx");
    }

    #[test]
    fn surfaces_exhausted_retries_otlp_error() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(503), http_response(503)]);
        let document = trace_document(1);

        let err = export_otlp_http(export_config(&endpoint, 1), &document).unwrap_err();

        assert!(
            err.to_string().contains("503"),
            "error should surface status: {err}"
        );
        assert_eq!(handle.join().unwrap(), 2, "should exhaust both attempts");
    }

    fn export_config(endpoint: &str, retries: u32) -> ExportConfig<'_> {
        ExportConfig {
            endpoint,
            headers: &[],
            compression: OtlpCompression::None,
            max_spans_per_batch: 512,
            max_bytes_per_batch: 0,
            timeout: Duration::from_secs(5),
            retries,
        }
    }

    fn http_response(status: u16) -> &'static str {
        // `Connection: close` forces the blocking reqwest client to open a fresh
        // TCP connection per attempt so the mock server can count requests via
        // successive `accept()` calls deterministically.
        match status {
            200 => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            400 => "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            503 => {
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            other => panic!("unhandled mock status {other}"),
        }
    }

    /// Bind a mock HTTP server to an ephemeral loopback port and reply with the
    /// scripted responses in order, one per accepted connection. Returns the
    /// endpoint URL and a handle that yields the number of requests served.
    fn spawn_mock_server(responses: Vec<&'static str>) -> (String, thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{addr}/v1/traces");
        let handle = thread::spawn(move || {
            let mut served = 0usize;
            for response in responses {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        read_http_request(&stream);
                        stream.write_all(response.as_bytes()).unwrap();
                        stream.flush().ok();
                        served += 1;
                    }
                    Err(_) => break,
                }
            }
            served
        });
        (endpoint, handle)
    }

    /// Consume a full HTTP request (headers + Content-Length body) so the
    /// client considers the request delivered before we respond.
    fn read_http_request(stream: &TcpStream) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(value) = lower.strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).ok();
    }

    fn trace_document_with_varied_sizes(span_count: usize) -> TraceDocument {
        let mut document = trace_document(span_count);
        for (idx, span) in document.spans.iter_mut().enumerate() {
            // Give spans differing encoded sizes so batching crosses boundaries
            // at uneven totals rather than a fixed stride.
            span.attributes.push(Attribute {
                key: "rgw.detail".to_string(),
                value: AttributeValue::String("x".repeat(idx % 7 * 16)),
            });
        }
        document
    }

    fn trace_document(span_count: usize) -> TraceDocument {
        TraceDocument {
            service_name: "rgwtrace".to_string(),
            spans: (0..span_count)
                .map(|idx| SpanDocument {
                    trace_id: format!("1111111111111111222222222222{idx:04x}"),
                    span_id: format!("333333333333{idx:04x}"),
                    parent_span_id: None,
                    name: "rgw.request".to_string(),
                    start_ns: 10,
                    end_ns: 20,
                    attributes: vec![Attribute {
                        key: "rgw.trans_id".to_string(),
                        value: AttributeValue::String(format!("tx{idx}")),
                    }],
                    events: Vec::new(),
                })
                .collect(),
            diagnostics: TraceDiagnostics::default(),
        }
    }

    fn all_span_ids(documents: &[TraceDocument]) -> Vec<String> {
        documents
            .iter()
            .flat_map(|document| document.spans.iter().map(|span| span.span_id.clone()))
            .collect()
    }
}
