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
    pub attempts: u64,
    pub failures: u64,
}

pub fn export_otlp_http(
    endpoint: &str,
    headers: &[(String, String)],
    compression: OtlpCompression,
    timeout: Duration,
    retries: u32,
    document: &TraceDocument,
) -> Result<ExportDiagnostics> {
    validate_otlp_endpoint(endpoint)?;

    let protobuf_body = to_otlp_protobuf(document)?;
    let body = encode_body(protobuf_body, compression)?;
    let headers = otlp_headers(headers, body.content_encoding)?;
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build OTLP HTTP client")?;

    let max_attempts = retries.saturating_add(1);
    let mut diagnostics = ExportDiagnostics::default();
    for attempt in 1..=max_attempts {
        diagnostics.attempts += 1;
        debug!(
            attempt,
            max_attempts,
            endpoint,
            timeout_ms = timeout.as_millis(),
            spans = document.spans.len(),
            body_bytes = body.bytes.len(),
            uncompressed_body_bytes = body.uncompressed_len,
            compression = ?compression,
            "exporting OTLP traces"
        );
        match send_once(&client, endpoint, headers.clone(), body.bytes.clone()) {
            Ok(()) => {
                info!(
                    spans = document.spans.len(),
                    attempt, "exported OTLP traces"
                );
                return Ok(diagnostics);
            }
            Err(err) if attempt < max_attempts && err.retryable => {
                diagnostics.failures += 1;
                warn!(attempt, error = %err.message, "OTLP export failed; retrying");
                thread::sleep(retry_delay(attempt));
            }
            Err(err) => {
                diagnostics.failures += 1;
                bail!(
                    "{}; export attempts: {}, export failures: {}",
                    err.message,
                    diagnostics.attempts,
                    diagnostics.failures
                )
            }
        }
    }

    unreachable!("OTLP export loop always returns")
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
        AttributeValue::U64(value) => KeyValue {
            key: attribute.key.clone(),
            value: Some(AnyValue {
                value: Some(any_value::Value::IntValue(
                    i64::try_from(*value).unwrap_or(i64::MAX),
                )),
            }),
            key_strindex: 0,
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
    if value.len() != expected_len * 2 {
        bail!("{field} must be {} hex characters", expected_len * 2);
    }

    (0..value.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&value[idx..idx + 2], 16)
                .with_context(|| format!("{field} contains non-hex data"))
        })
        .collect()
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
    use std::io::Read;

    use flate2::read::GzDecoder;

    use crate::collector::{AttributeValue, SpanDocument, TraceDiagnostics, TraceDocument};

    #[test]
    fn encodes_otlp_protobuf() {
        let document = TraceDocument {
            service_name: "rgwtrace".to_string(),
            spans: vec![SpanDocument {
                trace_id: "11111111111111112222222222222222".to_string(),
                span_id: "3333333333333333".to_string(),
                parent_span_id: None,
                name: "rgw.request".to_string(),
                start_ns: 10,
                end_ns: 20,
                attributes: vec![Attribute {
                    key: "rgw.trans_id".to_string(),
                    value: AttributeValue::String("tx1".to_string()),
                }],
                events: Vec::new(),
            }],
            diagnostics: TraceDiagnostics::default(),
        };

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
}
