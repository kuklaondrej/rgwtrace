use std::io::{Read, Write};
use std::net::TcpStream;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::collector::{Attribute, AttributeValue, SpanDocument, SpanEvent, TraceDocument};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OtlpRequest {
    resource_spans: Vec<ResourceSpans>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceSpans {
    resource: Resource,
    scope_spans: Vec<ScopeSpans>,
}

#[derive(Debug, Serialize)]
struct Resource {
    attributes: Vec<OtlpAttribute>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeSpans {
    scope: Scope,
    spans: Vec<OtlpSpan>,
}

#[derive(Debug, Serialize)]
struct Scope {
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OtlpSpan {
    trace_id: String,
    span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_span_id: Option<String>,
    name: String,
    kind: i32,
    start_time_unix_nano: String,
    end_time_unix_nano: String,
    attributes: Vec<OtlpAttribute>,
    events: Vec<OtlpEvent>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OtlpEvent {
    time_unix_nano: String,
    name: String,
    attributes: Vec<OtlpAttribute>,
}

#[derive(Debug, Serialize)]
struct OtlpAttribute {
    key: String,
    value: OtlpValue,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
enum OtlpValue {
    StringValue(String),
    IntValue(String),
}

pub fn to_otlp_json(document: &TraceDocument) -> Result<String> {
    let request = OtlpRequest {
        resource_spans: vec![ResourceSpans {
            resource: Resource {
                attributes: vec![OtlpAttribute {
                    key: "service.name".to_string(),
                    value: OtlpValue::StringValue(document.service_name.clone()),
                }],
            },
            scope_spans: vec![ScopeSpans {
                scope: Scope {
                    name: "rgwtrace".to_string(),
                },
                spans: document.spans.iter().map(span_to_otlp).collect(),
            }],
        }],
    };

    Ok(serde_json::to_string_pretty(&request)?)
}

pub fn export_otlp_http(endpoint: &str, document: &TraceDocument) -> Result<()> {
    let (host, port, path) = parse_http_endpoint(endpoint)?;
    let body = to_otlp_json(document)?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .with_context(|| format!("failed to connect to {host}:{port}"))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if !(response.starts_with("HTTP/1.1 2") || response.starts_with("HTTP/1.0 2")) {
        bail!("OTLP endpoint returned non-success response: {response}");
    }

    Ok(())
}

fn span_to_otlp(span: &SpanDocument) -> OtlpSpan {
    OtlpSpan {
        trace_id: span.trace_id.clone(),
        span_id: span.span_id.clone(),
        parent_span_id: span.parent_span_id.clone(),
        name: span.name.clone(),
        kind: 1,
        start_time_unix_nano: span.start_ns.to_string(),
        end_time_unix_nano: span.end_ns.to_string(),
        attributes: span.attributes.iter().map(attribute_to_otlp).collect(),
        events: span.events.iter().map(event_to_otlp).collect(),
    }
}

fn event_to_otlp(event: &SpanEvent) -> OtlpEvent {
    OtlpEvent {
        time_unix_nano: event.time_ns.to_string(),
        name: event.name.clone(),
        attributes: event.attributes.iter().map(attribute_to_otlp).collect(),
    }
}

fn attribute_to_otlp(attribute: &Attribute) -> OtlpAttribute {
    OtlpAttribute {
        key: attribute.key.clone(),
        value: match &attribute.value {
            AttributeValue::String(value) => OtlpValue::StringValue(value.clone()),
            AttributeValue::U64(value) => OtlpValue::IntValue(value.to_string()),
        },
    }
}

fn parse_http_endpoint(endpoint: &str) -> Result<(String, u16, String)> {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        bail!("only http:// OTLP endpoints are supported by the minimal exporter")
    };
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, "v1/traces"));
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse()?),
        None => (host_port.to_string(), 80),
    };

    Ok((host, port, format!("/{path}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_otlp_http_endpoint() {
        let (host, port, path) = parse_http_endpoint("http://localhost:4318/v1/traces").unwrap();

        assert_eq!(host, "localhost");
        assert_eq!(port, 4318);
        assert_eq!(path, "/v1/traces");
    }
}
