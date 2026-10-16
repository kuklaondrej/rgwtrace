use std::{error::Error as StdError, io::Write, path::Path, thread, time::Duration};

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
    cli::{Cli, OtlpCompression},
    collector::{
        span_id, trace_id, Attribute, AttributeValue, SpanDocument, SpanEvent, TraceDiagnostics,
        TraceDocument,
    },
};

const OTLP_PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";

#[derive(Clone, Copy, Debug, Default)]
pub struct ExportDiagnostics {
    pub batches: u64,
    pub attempts: u64,
    pub failures: u64,
}

/// The HTTP half of an exporter: the reqwest client (connection pool, TLS
/// configuration, timeout, redirect policy) and the operator's headers, built
/// ONCE and reused for every document and batch the exporter sends.
///
/// It used to be built per exported document. Each build is a new connection
/// pool, so every periodic drain paid a TCP connect and, over https, a full TLS
/// handshake, and an operator's misconfigured header or CA file surfaced only
/// when the first export ran -- after DWARF extraction and probe attach. Now
/// one client lives as long as its exporter, and the configuration is
/// validated when the client is built, at startup.
#[derive(Clone, Debug)]
pub struct ExportClient {
    client: Client,
    /// The operator's headers, validated as HTTP header names/values. Per
    /// request, `Content-Type` and (when compressing) `Content-Encoding` are
    /// added on a copy.
    headers: HeaderMap,
    /// The header VALUES, kept so that anything the far end echoes back -- a
    /// proxy that repeats the request's `Authorization` in its error page --
    /// can be scrubbed out of the error text before it is logged.
    secret_values: Vec<String>,
    timeout: Duration,
}

impl ExportClient {
    /// The client for a `--output otlp` run, from the CLI: the headers from
    /// every source (`crate::otlp_headers`) and the optional `--otlp-ca-cert`
    /// PEM bundle. Reads the files and environment they name, so a missing,
    /// malformed or exposed one fails here, at startup.
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let headers = crate::otlp_headers::load(cli)?;
        let ca_cert_pem = cli
            .otlp_ca_cert
            .as_deref()
            .map(read_ca_cert_file)
            .transpose()?;
        Self::new(cli.otlp_timeout, &headers, ca_cert_pem.as_deref())
    }

    /// Build the client. `ca_cert_pem` is a PEM bundle of extra root
    /// certificates to trust, for collectors behind a private PKI; the bundled
    /// web roots stay trusted alongside it.
    pub fn new(
        timeout: Duration,
        headers: &[(String, String)],
        ca_cert_pem: Option<&[u8]>,
    ) -> Result<Self> {
        let secret_values = headers.iter().map(|(_, value)| value.clone()).collect();
        let headers = validated_headers(headers)?;
        let mut builder = Client::builder()
            .timeout(timeout)
            // Never follow a redirect. reqwest's default (up to ten) would re-send
            // the request -- the operator's auth headers AND the trace body -- to
            // whatever host `Location` names, including an https -> http
            // downgrade. A moved collector is an `--otlp-endpoint` change, made
            // by the operator; see `send_once` for the error a 3xx turns into.
            .redirect(reqwest::redirect::Policy::none());
        if let Some(pem) = ca_cert_pem {
            let certificates = reqwest::Certificate::from_pem_bundle(pem)
                .context("OTLP CA certificate is not a PEM certificate bundle")?;
            if certificates.is_empty() {
                bail!("OTLP CA certificate file contains no PEM certificate");
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder
            .build()
            .context("failed to build OTLP HTTP client")?;
        Ok(Self {
            client,
            headers,
            secret_values,
            timeout,
        })
    }
}

fn read_ca_cert_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("failed to read --otlp-ca-cert {}", path.display()))
}

#[derive(Clone, Copy, Debug)]
pub struct ExportConfig<'a> {
    pub endpoint: &'a str,
    pub client: &'a ExportClient,
    pub compression: OtlpCompression,
    pub max_spans_per_batch: usize,
    pub max_bytes_per_batch: usize,
    pub retries: u32,
    /// Opt-in: carry the run-summary counters into the OTLP stream.
    ///
    /// When `false` (the default) the resource carries only `service.name` and no
    /// `rgwtrace.run_summary` span is emitted -- normal tracing, unpolluted by the
    /// cumulative debug counters. When `true`, every batch's resource carries the
    /// `rgwtrace.diag.*` attributes and the final export appends the
    /// `rgwtrace.run_summary` span (and is therefore always delivered, even when
    /// the final drain left no spans). The counters remain in the shutdown log and
    /// the JSON output regardless of this flag.
    pub diagnostics: bool,
}

/// One periodic drain of expired spans, mid-run. Sends nothing when the drain is
/// empty; the run summary rides along on the resource of whatever batches it does
/// send, and is superseded by the final export.
#[cfg(any(target_os = "linux", test))]
pub fn export_otlp_http(
    config: ExportConfig<'_>,
    document: &TraceDocument,
) -> Result<ExportDiagnostics> {
    export(config, document, Export::Periodic)
}

/// The LAST export of a run. With `config.diagnostics` on it ALWAYS puts at least
/// one batch on the wire, and that batch carries the complete, final run summary
/// -- both on the resource and as a synthetic [`RUN_SUMMARY_SPAN_NAME`] span. With
/// `config.diagnostics` off (the default) it carries no run summary, so an empty
/// final drain sends nothing at all (the pre-diagnostics behavior) and a non-empty
/// one exports its spans exactly like a periodic drain.
///
/// WHY THIS IS NOT JUST `export_otlp_http` (when diagnostics are on). The final BPF counters are merged out
/// of the BPF maps only after the poll loop exits, so the end-of-run document is
/// the ONLY one that carries the run's true totals. But by then the periodic
/// drains have usually taken every span, leaving that document with ZERO spans --
/// and an empty span set produced no batches, so the export was skipped entirely.
/// The last batch a backend actually saw then carried an EARLIER counter snapshot,
/// and the final totals arrived nowhere. With `--output otlp` the JSON document is
/// never printed, so that made a live validation run unable to read the numbers it
/// exists to produce (`bpf_operate_seed_hits_reqstate` vs
/// `bpf_operate_seed_hits_rgwop`: does Phase B recover ops, and is the RGWOp
/// alternate key load-bearing?).
///
/// The run summary is delivered TWICE, in two different OTLP fields, because the
/// two have different failure modes:
///
/// * on the `ResourceSpans.resource` attributes, as `rgwtrace.diag.*` -- the
///   canonical place, but a span-less batch carries no data most trace backends
///   will store, so on an empty final trace the resource alone can be dropped on
///   the floor by the backend even though the collector received it;
/// * on a synthetic zero-duration span named `rgwtrace.run_summary`, with the same
///   `rgwtrace.diag.*` attribute names -- a real span, so every backend stores and
///   indexes it, and the operator can find the final counters by searching for one
///   span name.
pub fn export_final_otlp_http(
    config: ExportConfig<'_>,
    document: &TraceDocument,
) -> Result<ExportDiagnostics> {
    export(config, document, Export::Final)
}

/// Which export a call is: a mid-run drain, or the run's last word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Export {
    #[cfg(any(target_os = "linux", test))]
    Periodic,
    Final,
}

fn export(
    config: ExportConfig<'_>,
    document: &TraceDocument,
    kind: Export,
) -> Result<ExportDiagnostics> {
    let endpoint = validate_otlp_endpoint(config.endpoint)?;
    // The only form of the endpoint that reaches a log line.
    let logged_endpoint = redact_url(&endpoint);
    if config.max_spans_per_batch == 0 {
        bail!("OTLP max spans per batch must be at least 1");
    }

    let resource_attributes = resource_attributes(document, config.diagnostics);
    let mut batches = otlp_batches(
        document,
        config.max_spans_per_batch,
        config.max_bytes_per_batch,
        config.diagnostics,
    )?;
    if kind == Export::Final && config.diagnostics {
        // Its OWN batch, appended last: it is therefore the final batch on the
        // wire (so a consumer reading "the last batch's resource" reads the final
        // counters), and it exists even when `batches` is empty -- which is the
        // whole point, because an empty final trace is the common case.
        //
        // Gated on `diagnostics`: this span is the ONLY reason a diagnostics-off
        // final export would ever force an empty batch onto the wire. With
        // diagnostics off there is nothing to deliver, so an empty final drain
        // sends nothing -- the pre-diagnostics behavior -- and a non-empty final
        // drain still exports its spans below.
        batches.push(vec![run_summary_span(document)?]);
    }
    let max_attempts = config.retries.saturating_add(1);
    let batch_count = batches.len();
    let mut diagnostics = ExportDiagnostics {
        batches: batch_count as u64,
        ..ExportDiagnostics::default()
    };
    for (batch_idx, batch) in batches.into_iter().enumerate() {
        let span_count = batch.len();
        let protobuf_body = spans_to_otlp_protobuf(&resource_attributes, batch);
        let body = encode_body(protobuf_body, config.compression)?;
        let headers = request_headers(&config.client.headers, body.content_encoding);
        for attempt in 1..=max_attempts {
            diagnostics.attempts += 1;
            debug!(
                attempt,
                max_attempts,
                batch = batch_idx + 1,
                batches = batch_count,
                endpoint = %logged_endpoint,
                timeout_ms = config.client.timeout.as_millis(),
                spans = span_count,
                body_bytes = body.bytes.len(),
                uncompressed_body_bytes = body.uncompressed_len,
                compression = ?config.compression,
                "exporting OTLP traces"
            );
            match send_once(
                config.client,
                &endpoint,
                headers.clone(),
                body.bytes.clone(),
            ) {
                Ok(()) => {
                    info!(
                        spans = span_count,
                        batch = batch_idx + 1,
                        batches = batch_count,
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

/// Resource attributes for the export: `service.name`, plus the run's summary
/// diagnostics ONLY when opted in via `diagnostics`.
///
/// The diagnostics are opt-in (`--otlp-diagnostics`, default off). When on they
/// are the channel through which an OTLP-only run can be evaluated: with
/// `--output otlp` the JSON document (which carries the full `trace.diagnostics`
/// block) is never printed, so correlation coverage, the cross-thread bridge hit
/// rate, and request-end-probe coverage would otherwise be invisible to the
/// backend. They are cumulative run totals repeated on every batch, so a consumer
/// should read the LAST batch's values (or simply the end-of-run summary log),
/// not sum them.
///
/// When off (the default) the resource carries just `service.name`: the counters
/// are cumulative debug data, not request telemetry, and shipping them onto every
/// span's resource pollutes the tracing backend. They remain available in the
/// shutdown log and JSON output regardless.
fn resource_attributes(document: &TraceDocument, diagnostics: bool) -> Vec<KeyValue> {
    let mut attributes = vec![string_key_value("service.name", &document.service_name)];
    if diagnostics {
        attributes.extend(diagnostic_attributes(&document.diagnostics));
    }
    attributes
}

/// Prefix every run-summary diagnostic carries on the OTLP resource.
pub const OTLP_DIAGNOSTIC_PREFIX: &str = "rgwtrace.diag.";

/// Name of the synthetic span that carries the complete run summary at shutdown.
pub const RUN_SUMMARY_SPAN_NAME: &str = "rgwtrace.run_summary";

/// EVERY run-summary counter, as OTLP resource attributes.
///
/// NOT a curated subset. It used to be one, and the subset had rotted: it omitted
/// `bpf_operate_seed_*`, `bpf_operate_miss_ctx_cleared`, `bpf_rgw_op_key_*`,
/// `bpf_sendop_unbridged_ctx_drops` and `emitted_request_keys` -- i.e. precisely
/// the counters that say whether the cross-thread bridge is WORKING. An
/// `--output otlp` run never prints the JSON document, so those omissions made a
/// live validation run unable to tell a working Phase B from an inert one: seeds
/// hitting nothing and seeds never attempted look identical from the span data
/// alone.
///
/// `TraceDiagnostics::counters()` is derived from the struct's own serde
/// representation, so a counter added to the struct appears here automatically and
/// the subset cannot rot again.
fn diagnostic_attributes(diagnostics: &TraceDiagnostics) -> Vec<KeyValue> {
    diagnostics
        .counters()
        .into_iter()
        .map(|(key, value)| {
            attribute_to_otlp(&Attribute {
                key: format!("{OTLP_DIAGNOSTIC_PREFIX}{key}"),
                value: AttributeValue::U64(value),
            })
        })
        .collect()
}

/// The synthetic span that carries the final run summary, as OTLP protobuf.
fn run_summary_span(document: &TraceDocument) -> Result<Span> {
    span_to_otlp(&run_summary_span_document(document, now_unix_nanos()))
}

/// The final run summary as a zero-duration span: every counter of
/// [`TraceDiagnostics`], under the same `rgwtrace.diag.*` names the resource
/// attributes use, so an operator greps ONE set of names regardless of which OTLP
/// field their backend surfaces.
///
/// Its trace id is its own (the summary belongs to no request), derived from the
/// service name, pid and end-of-run timestamp so that two runs -- and two
/// concurrent gateways' tracers -- never collide on one trace id.
fn run_summary_span_document(document: &TraceDocument, time_ns: u64) -> SpanDocument {
    let key = format!(
        "rgwtrace.run_summary:{}:{}:{time_ns}",
        document.service_name,
        std::process::id()
    );

    let counters = document.diagnostics.counters();
    let mut attributes = Vec::with_capacity(counters.len() + 2);
    // A marker so the summary span is findable by attribute as well as by name,
    // and the span count of the FINAL export -- which is not `spans_produced`
    // (that is the run total) and would otherwise be unknowable from this span.
    attributes.push(Attribute {
        key: "rgwtrace.run_summary".to_string(),
        value: AttributeValue::String("final".to_string()),
    });
    attributes.push(Attribute {
        key: "rgwtrace.final_export_spans".to_string(),
        value: AttributeValue::U64(document.spans.len() as u64),
    });
    attributes.extend(counters.into_iter().map(|(key, value)| Attribute {
        key: format!("{OTLP_DIAGNOSTIC_PREFIX}{key}"),
        value: AttributeValue::U64(value),
    }));

    SpanDocument {
        trace_id: trace_id(&key),
        span_id: span_id(&key),
        parent_span_id: None,
        name: RUN_SUMMARY_SPAN_NAME.to_string(),
        // Zero duration: this is a point-in-time record of the run's totals, not a
        // measured interval. Span timestamps elsewhere are unix-epoch nanos (the
        // BPF boottime clock is offset onto it at decode), so this must be too.
        start_ns: time_ns,
        end_ns: time_ns,
        attributes,
        events: Vec::new(),
    }
}

/// Wall-clock nanoseconds since the unix epoch, the timebase every emitted span
/// uses. Saturates to 0 only if the clock is before the epoch.
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Encode the OTLP request envelope around already-built protobuf `spans`. The
/// batching path builds each span's protobuf object once and moves it in here,
/// so a batch is assembled without re-converting or cloning any span.
fn spans_to_otlp_protobuf(resource_attributes: &[KeyValue], spans: Vec<Span>) -> Vec<u8> {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: resource_attributes.to_vec(),
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
                spans,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    };

    request.encode_to_vec()
}

fn send_once(
    client: &ExportClient,
    endpoint: &Url,
    headers: HeaderMap,
    body: Vec<u8>,
) -> Result<(), ExportError> {
    // Everything that originates on the far end or in reqwest -- never our own
    // words -- passes through this before it can reach a log line.
    let scrub = |text: String| {
        scrub_header_values(scrub_url_secrets(text, endpoint), &client.secret_values)
    };
    let response = client
        .client
        .post(endpoint.clone())
        .headers(headers)
        .body(body)
        .send()
        .map_err(|err| {
            ExportError::retryable(format!(
                "failed to send OTLP request to {}: {}",
                redact_url(endpoint),
                scrub(error_chain(&err))
            ))
        })?;
    let status = response.status();

    if status.is_success() {
        return Ok(());
    }

    if status.is_redirection() {
        // Fatal, not retried: the same endpoint answers the same way again, and
        // following it ourselves is exactly what the no-redirect client policy
        // exists to prevent (credentials and payload re-sent to another host).
        return Err(ExportError::fatal(format!(
            "OTLP endpoint returned {status}: redirects are not followed because they would \
             re-send the configured headers and the trace body to another location; point \
             --otlp-endpoint at the final URL"
        )));
    }

    // The body is the collector's (or an intermediary's) to write, and some
    // echo the request they rejected -- URL, query string, auth header and all.
    let body = scrub(read_error_body(response));
    let message = format!("OTLP endpoint returned {status}: {body}");
    if is_retryable_status(status) {
        Err(ExportError::retryable(message))
    } else {
        Err(ExportError::fatal(message))
    }
}

/// How much of an error response body is kept for the log. A collector's error
/// page is a sentence; anything longer is an HTML error page or a proxy's
/// splash, and this message is repeated on every retry.
const ERROR_BODY_EXCERPT_BYTES: usize = 1024;

/// The error response body as a log-safe excerpt. Reads at most one byte past
/// the excerpt limit off the socket -- enough to know the body was longer --
/// so a misconfigured endpoint that answers with megabytes of HTML costs
/// neither memory nor a verbatim dump of itself on every attempt.
fn read_error_body(response: reqwest::blocking::Response) -> String {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    match response
        .take(ERROR_BODY_EXCERPT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
    {
        Ok(_) => body_excerpt(&bytes),
        Err(err) => format!("failed to read response body: {err}"),
    }
}

/// `bytes` as a bounded, single-line-safe string: lossily decoded, cut to
/// [`ERROR_BODY_EXCERPT_BYTES`] on a character boundary, control characters
/// (newlines, escape sequences a hostile body could use to forge log lines)
/// rendered as escapes, and a marker saying how much was dropped.
fn body_excerpt(bytes: &[u8]) -> String {
    let truncated = bytes.len() > ERROR_BODY_EXCERPT_BYTES;
    let kept = &bytes[..bytes.len().min(ERROR_BODY_EXCERPT_BYTES)];
    let text = String::from_utf8_lossy(kept);
    let mut excerpt = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            excerpt.extend(ch.escape_default());
        } else {
            excerpt.push(ch);
        }
    }
    if truncated {
        // Only the excerpt was read, so the real length is unknown; say so
        // rather than inventing a byte count.
        excerpt.push_str(" [truncated]");
    }
    excerpt
}

/// Remove every form of `url`'s secrets from `text`, an error chain that was
/// not written by us. reqwest's Display appends ` for url (<url>)` with the
/// userinfo already stripped but the query string intact, and a future version
/// may print it differently again, so this does not depend on one rendering:
/// it replaces the URL as given and as reqwest renders it, then the query
/// string and the password on their own wherever they occur.
fn scrub_url_secrets(text: String, url: &Url) -> String {
    let redacted = redact_url(url);
    let mut without_userinfo = url.clone();
    let _ = without_userinfo.set_password(None);
    let _ = without_userinfo.set_username("");
    let mut text = text
        .replace(url.as_str(), &redacted)
        .replace(without_userinfo.as_str(), &redacted);
    if let Some(query) = url.query().filter(|query| !query.is_empty()) {
        text = text.replace(&format!("?{query}"), "");
    }
    if let Some(password) = url.password().filter(|password| !password.is_empty()) {
        text = text.replace(password, "<redacted>");
    }
    text
}

/// Replace every configured header value found in `text` with a marker. The
/// values are the credentials; an error page that echoes the request's headers
/// would otherwise carry them into the log on every retry.
fn scrub_header_values(mut text: String, values: &[String]) -> String {
    for value in values.iter().filter(|value| !value.is_empty()) {
        text = text.replace(value.as_str(), "<redacted>");
    }
    text
}

/// `url` as it may appear in a log line or an error: scheme, host, port and
/// path only. Userinfo (`user:pass@`) and the query string are where
/// credentials live when an operator puts them in the endpoint URL
/// (`?api-key=...`), and the endpoint is logged on every export attempt.
fn redact_url(url: &Url) -> String {
    let mut redacted = url.clone();
    // Both setters only fail for cannot-be-a-base URLs; the endpoint is
    // validated to be http(s), which can always carry (and drop) userinfo.
    let _ = redacted.set_password(None);
    let _ = redacted.set_username("");
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
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

/// The operator's headers as a validated `HeaderMap`. The error names the
/// header, never its value: values are where the secrets are.
fn validated_headers(headers: &[(String, String)]) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid OTLP header name {name:?}"))?;
        let value = HeaderValue::from_str(value)
            .with_context(|| format!("invalid OTLP header value for {name}"))?;
        map.insert(name, value);
    }
    Ok(map)
}

/// The headers of one request: the operator's, plus the content headers the
/// body's encoding dictates.
fn request_headers(base: &HeaderMap, content_encoding: Option<&'static str>) -> HeaderMap {
    let mut map = base.clone();
    map.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(OTLP_PROTOBUF_CONTENT_TYPE),
    );
    if let Some(content_encoding) = content_encoding {
        map.insert(CONTENT_ENCODING, HeaderValue::from_static(content_encoding));
    }
    map
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

/// A span's OTLP protobuf object paired with the marginal byte cost of adding it
/// to a batch. The protobuf object is built exactly once (here) and then moved
/// into a batch, so neither the size arithmetic nor the final assembly re-builds
/// or clones it.
struct SizedSpan {
    span: Span,
    marginal_len: usize,
}

/// Convert every document span to its OTLP protobuf object once, recording the
/// marginal batch cost alongside each. A conversion failure surfaces here as the
/// same `Err` the export path would previously have produced.
fn build_sized_spans(document: &TraceDocument) -> Result<Vec<SizedSpan>> {
    document
        .spans
        .iter()
        .map(|span| {
            let span = span_to_otlp(span)?;
            let marginal_len = span_marginal_len(span.encoded_len());
            Ok(SizedSpan { span, marginal_len })
        })
        .collect()
}

fn otlp_batches(
    document: &TraceDocument,
    max_spans_per_batch: usize,
    max_bytes_per_batch: usize,
    diagnostics: bool,
) -> Result<Vec<Vec<Span>>> {
    let sized_spans = build_sized_spans(document)?;
    if sized_spans.is_empty() {
        return Ok(Vec::new());
    }

    // Fixed cost of a batch carrying the resource/scope envelope but no spans.
    // Cloning the accumulated span vec and re-encoding the whole candidate
    // batch for every appended span is O(n^2) on large drains; instead we
    // sum each span's precomputed marginal size and keep a running total. See
    // `batch_size_estimate` for why the running total is a safe upper bound on
    // the real encoded batch size, so a batch flushed under
    // `max_bytes_per_batch` still respects the limit once actually encoded.
    // Built from the same resource attributes the real batches carry (including
    // the diagnostics, when opted in), so the empty-envelope cost is not
    // underestimated.
    let base_len =
        spans_to_otlp_protobuf(&resource_attributes(document, diagnostics), Vec::new()).len();

    let mut batches = Vec::new();
    let mut spans: Vec<Span> = Vec::new();
    let mut running_span_bytes = 0usize;
    for SizedSpan { span, marginal_len } in sized_spans {
        let over_count = !spans.is_empty() && spans.len() >= max_spans_per_batch;
        let over_bytes = max_bytes_per_batch > 0
            && !spans.is_empty()
            && batch_size_estimate(base_len, running_span_bytes + marginal_len)
                > max_bytes_per_batch;

        if over_count || over_bytes {
            batches.push(std::mem::take(&mut spans));
            running_span_bytes = 0;
        }

        running_span_bytes += marginal_len;
        spans.push(span);
    }
    if !spans.is_empty() {
        batches.push(spans);
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

/// Marginal encoded cost of appending a span to a batch, given its own encoded
/// length: that length plus the framing (field tag + length varint) it
/// contributes to the repeated `spans` field.
fn span_marginal_len(encoded_len: usize) -> usize {
    OTLP_SPAN_TAG_MAX + varint_len(encoded_len) + encoded_len
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

struct EncodedBody {
    bytes: Vec<u8>,
    content_encoding: Option<&'static str>,
    uncompressed_len: usize,
}

/// Parse and check the endpoint. The error for an unparseable endpoint quotes
/// it verbatim: nothing has been redacted yet because nothing could be parsed,
/// and the operator who typed it needs to see what was wrong with it.
fn validate_otlp_endpoint(endpoint: &str) -> Result<Url> {
    let url =
        Url::parse(endpoint).with_context(|| format!("invalid OTLP endpoint {endpoint:?}"))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
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

    /// Full document -> encoded OTLP bytes, mirroring the production encode path
    /// (per-span conversion followed by envelope encoding). Lets the encoding
    /// tests assert against a whole `TraceDocument` in one step.
    fn to_otlp_protobuf(document: &TraceDocument) -> Result<Vec<u8>> {
        let spans = document
            .spans
            .iter()
            .map(span_to_otlp)
            .collect::<Result<Vec<_>>>()?;
        Ok(spans_to_otlp_protobuf(
            &resource_attributes(document, true),
            spans,
        ))
    }

    /// A `TraceDiagnostics` with EVERY field populated, built without naming a
    /// single field: take the struct's own serde shape, fill each scalar with a
    /// distinct value and each counter map with an entry, and read it back. A
    /// hand-listed fixture would rot exactly the way the OTLP attribute list did.
    fn fully_populated_diagnostics() -> TraceDiagnostics {
        let shape = serde_json::to_value(TraceDiagnostics::default()).unwrap();
        let serde_json::Value::Object(fields) = shape else {
            panic!("TraceDiagnostics must serialize as an object");
        };

        let mut populated = serde_json::Map::new();
        for (idx, (name, value)) in fields.into_iter().enumerate() {
            let filled = match value {
                serde_json::Value::Number(_) => serde_json::json!(idx as u64 + 1),
                serde_json::Value::Object(_) => serde_json::json!({ "some-key": idx as u64 + 1 }),
                other => panic!(
                    "diagnostics field {name} is neither a counter nor a counter map: {other:?} -- \
                     `TraceDiagnostics::counters()` would silently DROP it from the log and OTLP \
                     outputs. Make it a u64 (or a BTreeMap<String, u64>), or teach `counters()` \
                     how to carry it."
                ),
            };
            populated.insert(name, filled);
        }
        serde_json::from_value(serde_json::Value::Object(populated)).unwrap()
    }

    #[test]
    fn every_diagnostics_field_reaches_every_output_path() {
        // THE TRIPWIRE. The run summary has three sinks -- the JSON document, the
        // end-of-run log line, and (opt-in) the OTLP resource attributes / summary
        // span -- and only the JSON one is free (serde). The other two were CURATED
        // LISTS, and the curated OTLP list had rotted: it omitted
        // `bpf_operate_seed_*`, `bpf_operate_miss_ctx_cleared`, `bpf_rgw_op_key_*`,
        // `bpf_sendop_unbridged_ctx_drops` and `emitted_request_keys` -- i.e. every
        // counter that says whether the cross-thread bridge is actually WORKING.
        //
        // The OTLP sinks are now opt-in (`--otlp-diagnostics`, default off), so this
        // test asserts the two invariants that survive the flag:
        //   * with the flag ON, every counter reaches ALL sinks (as today);
        //   * JSON + log carry every counter ALWAYS, regardless of the flag, so a
        //     live validation can always read the numbers off the shutdown log.
        //
        // It is deliberately name-driven, not value-driven: it must break for a
        // field that does not exist yet.
        let diagnostics = fully_populated_diagnostics();

        // Source of truth: the struct's own serde representation.
        let serde_json::Value::Object(json) = serde_json::to_value(&diagnostics).unwrap() else {
            panic!("diagnostics must serialize as an object");
        };
        let counters = diagnostics.counters();
        let summary = diagnostics.summary();

        // 1. `counters()` covers every field of the struct (maps flattened).
        let mut expected: Vec<String> = Vec::new();
        for (name, value) in &json {
            match value {
                serde_json::Value::Object(entries) => {
                    expected.extend(entries.keys().map(|key| format!("{name}.{key}")));
                }
                _ => expected.push(name.clone()),
            }
        }
        let counter_names: Vec<String> = counters.iter().map(|(name, _)| name.clone()).collect();
        assert_eq!(
            counter_names
                .iter()
                .collect::<std::collections::BTreeSet<_>>(),
            expected.iter().collect::<std::collections::BTreeSet<_>>(),
            "TraceDiagnostics::counters() does not cover every field of the struct"
        );
        assert!(
            counters.len() > 50,
            "sanity: the run summary should carry every counter, got {}",
            counters.len()
        );

        let document = TraceDocument {
            service_name: "rgwtrace".to_string(),
            spans: Vec::new(),
            diagnostics: diagnostics.clone(),
        };

        // 2. WITH THE FLAG ON: the OTLP resource carries service.name plus every
        //    counter, and nothing else.
        let resource_on = resource_attributes(&document, true);
        for (name, value) in &counters {
            let key = format!("{OTLP_DIAGNOSTIC_PREFIX}{name}");
            let attribute = resource_on
                .iter()
                .find(|kv| kv.key == key)
                .unwrap_or_else(|| {
                    panic!(
                        "diagnostics counter {name} is NOT exported over OTLP with \
                         --otlp-diagnostics. A live-validation run cannot see it, so the feature \
                         it measures cannot be validated. Export it via TraceDiagnostics::counters()."
                    )
                });
            assert_eq!(
                attribute.value.as_ref().unwrap().value,
                Some(any_value::Value::IntValue(*value as i64)),
                "OTLP attribute {key} carries the wrong value"
            );
        }
        assert_eq!(
            resource_on.len(),
            counters.len() + 1,
            "with the flag on the resource must be service.name plus exactly the run-summary counters"
        );

        // 2b. WITH THE FLAG OFF (the default): the OTLP resource carries NO
        //     diagnostics -- just service.name. This is the opt-in's whole point.
        let resource_off = resource_attributes(&document, false);
        assert_eq!(
            resource_off.len(),
            1,
            "with the flag off the resource must be service.name alone"
        );
        assert!(
            !resource_off
                .iter()
                .any(|kv| kv.key.starts_with(OTLP_DIAGNOSTIC_PREFIX)),
            "no rgwtrace.diag.* attribute may reach OTLP when the flag is off"
        );

        // 3. THE LOG LINE ALWAYS carries every counter, with its value, regardless
        //    of the flag -- `summary()` takes no flag, so an operator can always
        //    read the numbers off the shutdown log without polluting OTLP.
        for (name, value) in &counters {
            assert!(
                summary.contains(&format!("{name}={value}")),
                "diagnostics counter {name} is missing from the end-of-run log summary"
            );
        }

        // 3b. THE JSON DOCUMENT ALWAYS carries every counter, regardless of the
        //     flag. serde takes no flag; `expected` above is literally the struct's
        //     serde shape, and section 1 proved `counters()` equals it, so every
        //     counter is in the JSON `trace.diagnostics` block unconditionally.
        assert_eq!(
            expected.len(),
            counters.len(),
            "the JSON diagnostics block must carry exactly the run-summary counters"
        );

        // 4. WITH THE FLAG ON: the run-summary SPAN carries every counter, with its
        //    value. This is the sink that survives an empty final trace: a span-less
        //    batch's resource attributes reach the collector but are stored by
        //    nothing.
        let span = run_summary_span_document(&document, 1_000);
        for (name, value) in &counters {
            let key = format!("{OTLP_DIAGNOSTIC_PREFIX}{name}");
            let attribute = span
                .attributes
                .iter()
                .find(|attribute| attribute.key == key)
                .unwrap_or_else(|| {
                    panic!(
                        "diagnostics counter {name} is NOT on the run-summary span, so an \
                         --output otlp run whose final drain had no spans cannot see it."
                    )
                });
            match attribute.value {
                AttributeValue::U64(actual) => assert_eq!(
                    actual, *value,
                    "run-summary span attribute {key} carries the wrong value"
                ),
                ref other => panic!("run-summary span attribute {key} is not a counter: {other:?}"),
            }
        }
    }

    #[test]
    fn otlp_resource_carries_the_service_name_alongside_the_diagnostics() {
        let document = trace_document(1);

        // Diagnostics ON (`--otlp-diagnostics`): service.name plus every counter.
        let attributes = resource_attributes(&document, true);

        assert_eq!(attributes[0].key, "service.name");
        assert_eq!(
            attributes.len(),
            1 + document.diagnostics.counters().len(),
            "the resource must be service.name plus every run-summary counter"
        );
    }

    /// Diagnostics OFF (the default): the resource carries JUST `service.name` --
    /// no `rgwtrace.diag.*` attributes. This is the whole point of the opt-in: a
    /// normal tracing run does not pollute the backend's resource with cumulative
    /// debug counters.
    #[test]
    fn otlp_resource_omits_the_diagnostics_by_default() {
        let mut document = trace_document(1);
        // Non-zero counters so a leak would be visible, not masked by zeros.
        document.diagnostics.bpf_operate_seed_hits_reqstate = 41;
        document.diagnostics.rados_ops = 128;

        let attributes = resource_attributes(&document, false);

        assert_eq!(
            attributes.len(),
            1,
            "with diagnostics off the resource must be service.name alone"
        );
        assert_eq!(attributes[0].key, "service.name");
        assert!(
            !attributes
                .iter()
                .any(|kv| kv.key.starts_with(OTLP_DIAGNOSTIC_PREFIX)),
            "no rgwtrace.diag.* attribute may appear when diagnostics are off"
        );
    }

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
        let base =
            validated_headers(&[("X-Scope-OrgID".to_string(), "tenant".to_string())]).unwrap();
        let headers = request_headers(&base, Some("gzip"));

        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap(),
            OTLP_PROTOBUF_CONTENT_TYPE
        );
        assert_eq!(headers.get(CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(headers.get("x-scope-orgid").unwrap(), "tenant");
        assert!(
            base.get(CONTENT_TYPE).is_none(),
            "the base map is not mutated"
        );
    }

    /// Configuration errors surface when the client is BUILT (at startup), not
    /// on the first export minutes later.
    #[test]
    fn export_client_validates_headers_when_built() {
        let err = ExportClient::new(
            Duration::from_secs(1),
            &[("not a header".to_string(), "x".to_string())],
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid OTLP header name"),
            "{err:#}"
        );
    }

    #[test]
    fn export_client_rejects_a_bad_ca_certificate() {
        let err = ExportClient::new(Duration::from_secs(1), &[], Some(b"not a pem")).unwrap_err();
        assert!(err.to_string().contains("PEM"), "{err:#}");

        // A PEM file with no CERTIFICATE block is just as wrong: the operator
        // pointed the flag at a key or an empty file.
        let err = ExportClient::new(Duration::from_secs(1), &[], Some(b"")).unwrap_err();
        assert!(err.to_string().contains("PEM"), "{err:#}");
    }

    #[test]
    fn export_client_accepts_a_pem_ca_certificate() {
        let pem = include_bytes!("../tests/fixtures/otlp_test_ca.pem");
        ExportClient::new(Duration::from_secs(1), &[], Some(pem)).unwrap();
    }

    /// ONE connection pool per exporter. Two documents exported through the same
    /// client reuse the same keep-alive connection; a client built per document
    /// (the old shape) would open a second connection -- and, over https, pay a
    /// second TLS handshake -- for every periodic drain.
    #[test]
    fn one_client_is_reused_across_documents() {
        let (endpoint, handle) = spawn_keepalive_mock_server(2);
        let client = ExportClient::new(Duration::from_secs(5), &[], None).unwrap();
        let config = ExportConfig {
            client: &client,
            ..export_config(&endpoint, 0)
        };

        export_otlp_http(config, &trace_document(1)).unwrap();
        export_otlp_http(config, &trace_document(1)).unwrap();

        assert_eq!(
            handle.join().unwrap().len(),
            2,
            "both documents must arrive on the ONE accepted connection"
        );
    }

    #[test]
    fn batches_otlp_spans_by_count() {
        let document = trace_document(5);

        let batches = otlp_batches(&document, 2, 0, true).unwrap();

        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 2);
        assert_eq!(batches[2].len(), 1);
        assert_eq!(batched_span_ids(&batches), document_span_ids(&document));
    }

    #[test]
    fn batches_otlp_spans_by_encoded_size() {
        let document = trace_document(3);
        let one_span_size = to_otlp_protobuf(&trace_document(1)).unwrap().len();
        let max_bytes = one_span_size + 8;

        let batches = otlp_batches(&document, 512, max_bytes, true).unwrap();

        assert_eq!(batches.len(), 3);
        assert!(batches.iter().all(|batch| batch.len() == 1));
        assert_eq!(batched_span_ids(&batches), document_span_ids(&document));
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
        // Diagnostics ON: the resource carries every counter, the largest
        // envelope the batcher must size against.
        let attributes = resource_attributes(&document, true);
        let base_len = spans_to_otlp_protobuf(&attributes, Vec::new()).len();

        // SIZE THE CAP OFF THE SPAN PAYLOAD, NOT THE ENVELOPE. The resource
        // attributes carry EVERY diagnostics counter, so `base_len` grows whenever a
        // counter is added -- and a cap derived from it (this was `(base_len + 128) *
        // 3`) grows with it, until all 40 spans fit in one batch and the test stops
        // testing batching at all while still passing. Deriving the cap from the span
        // bytes keeps the number of batches stable no matter how many counters exist.
        let all_spans: Vec<Span> = build_sized_spans(&document)
            .unwrap()
            .into_iter()
            .map(|sized| sized.span)
            .collect();
        let span_bytes = spans_to_otlp_protobuf(&attributes, all_spans).len() - base_len;
        let max_bytes = base_len + span_bytes / 4;

        let batches = otlp_batches(&document, 512, max_bytes, true).unwrap();

        assert!(batches.len() > 1, "test should exercise multiple batches");
        assert_eq!(batched_span_ids(&batches), document_span_ids(&document));
        for batch in &batches {
            let span_count = batch.len();
            // Encode the batch exactly as the export path would and compare the
            // real wire size against the estimate-derived flush threshold.
            let encoded =
                spans_to_otlp_protobuf(&resource_attributes(&document, true), batch.clone()).len();
            assert!(
                span_count == 1 || encoded <= max_bytes,
                "flushed batch of {span_count} spans encoded to {encoded} bytes, exceeding max {max_bytes}"
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
        assert_eq!(handle.join().unwrap().len(), 1);
    }

    /// THE EMPTY-FINAL-TRACE HOLE.
    ///
    /// A live `--output otlp` run drains spans periodically. By shutdown, the
    /// periodic drains have usually taken EVERY span, so the final trace document
    /// holds zero spans -- but it is the only document that holds the FINAL BPF
    /// counters (they are merged from the BPF maps after the poll loop exits).
    /// The old code skipped the export entirely for a span-less document, so the
    /// last OTLP batch a backend saw carried an EARLIER diagnostics snapshot, and
    /// the final totals never arrived at all.
    ///
    /// That is fatal for the live-rig validation this feature exists for: the
    /// go/no-go number is `bpf_operate_seed_hits_reqstate` vs
    /// `bpf_operate_seed_hits_rgwop` (does Phase B recover ops, and is the RGWOp
    /// alternate key load-bearing?), and with `--output otlp` the JSON document is
    /// never printed, so OTLP is the only channel carrying it.
    ///
    /// This asserts DELIVERY, not construction: it reads the bytes off a real
    /// socket and decodes them. `every_diagnostics_field_reaches_every_output_path`
    /// only ever checked that the attributes were BUILT correctly -- which is
    /// exactly why an export that was never sent slipped past it.
    #[test]
    fn final_export_delivers_the_run_summary_when_the_last_drain_left_no_spans() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(200)]);
        // The shape of a real end-of-run document: every span already went out in
        // a periodic drain, and only the final counters remain.
        let mut trace = trace_document(0);
        trace.diagnostics.bpf_operate_seed_hits_reqstate = 41;
        trace.diagnostics.bpf_operate_seed_hits_rgwop = 7;
        trace.diagnostics.rados_ops = 128;
        assert!(trace.spans.is_empty(), "this is the empty-final-trace case");
        let document = serde_json::json!({ "trace": &trace });
        let mut out = Vec::new();

        crate::export_trace_otlp(export_config(&endpoint, 2), &trace, &document, &mut out).unwrap();

        let bodies = handle.join().unwrap();
        assert_eq!(
            bodies.len(),
            1,
            "an empty final trace MUST still deliver a final OTLP batch -- otherwise the last \
             batch the backend saw carries stale counters and the live validation run is worthless"
        );
        let request = decode_export_request(&bodies[0]);

        // 1. The resource of the delivered batch carries the FINAL counters.
        let resource = only_resource_spans(&request).resource.as_ref().unwrap();
        assert_eq!(
            int_attribute(
                &resource.attributes,
                "rgwtrace.diag.bpf_operate_seed_hits_reqstate"
            ),
            Some(41),
        );
        assert_eq!(
            int_attribute(
                &resource.attributes,
                "rgwtrace.diag.bpf_operate_seed_hits_rgwop"
            ),
            Some(7),
        );

        // 2. And so does the run-summary SPAN. Resource attributes alone are not
        //    enough: a batch with no spans carries no data a trace backend will
        //    store, so the counters would reach the collector and stop there. The
        //    summary span is what makes them queryable in Jaeger/Tempo.
        let spans = request_spans(&request);
        let summary = spans
            .iter()
            .find(|span| span.name == RUN_SUMMARY_SPAN_NAME)
            .expect("the final batch must carry the run-summary span");
        assert_eq!(
            int_attribute(
                &summary.attributes,
                "rgwtrace.diag.bpf_operate_seed_hits_reqstate"
            ),
            Some(41),
        );
        assert_eq!(
            int_attribute(
                &summary.attributes,
                "rgwtrace.diag.bpf_operate_seed_hits_rgwop"
            ),
            Some(7),
        );
        assert_eq!(
            int_attribute(&summary.attributes, "rgwtrace.diag.rados_ops"),
            Some(128),
        );

        // 3. A successful export does not dump the JSON document to stdout.
        assert!(
            out.is_empty(),
            "a successful export must not dump the trace"
        );
    }

    /// FLAG OFF (the default): a final export carries a CLEAN resource
    /// (service.name only, no `rgwtrace.diag.*`) and NO `rgwtrace.run_summary`
    /// span, while the run's own spans still go out normally -- and the JSON
    /// document for the same run still carries the full diagnostics block. This is
    /// the whole point of the opt-in: validation stays possible off OTLP without
    /// polluting the tracing backend with cumulative debug counters.
    #[test]
    fn flag_off_final_export_carries_a_clean_resource_and_no_run_summary_span() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(200)]);
        let mut trace = trace_document(2);
        trace.diagnostics.bpf_operate_seed_hits_reqstate = 41;
        trace.diagnostics.rados_ops = 128;

        let diagnostics =
            export_final_otlp_http(export_config_no_diagnostics(&endpoint, 2), &trace).unwrap();

        // One batch: the run's spans, and NO extra run-summary batch.
        assert_eq!(
            diagnostics.batches, 1,
            "no run-summary batch is appended with the flag off"
        );
        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), 1);
        let request = decode_export_request(&bodies[0]);

        // The resource is service.name ALONE -- no rgwtrace.diag.* attributes.
        let resource = only_resource_spans(&request).resource.as_ref().unwrap();
        assert!(
            resource
                .attributes
                .iter()
                .all(|kv| kv.key == "service.name"),
            "with the flag off the OTLP resource must carry no rgwtrace.diag.* attributes"
        );
        assert_eq!(
            int_attribute(&resource.attributes, "rgwtrace.diag.rados_ops"),
            None,
            "no diagnostics counter may reach the resource with the flag off"
        );

        // No rgwtrace.run_summary span rode along; only the run's own spans.
        let spans = request_spans(&request);
        assert_eq!(spans.len(), 2, "only the run's own spans are exported");
        assert!(
            spans.iter().all(|span| span.name != RUN_SUMMARY_SPAN_NAME),
            "the run-summary span must not be emitted with the flag off"
        );

        // ...but the JSON document for the same run still carries every counter.
        let json = serde_json::to_value(&trace.diagnostics).unwrap();
        assert_eq!(json["bpf_operate_seed_hits_reqstate"], 41);
        assert_eq!(json["rados_ops"], 128);
    }

    /// FLAG OFF, THE EMPTY-FINAL-DRAIN CASE. With `--otlp-diagnostics` off there is
    /// no run summary to deliver, so an empty final drain -- the normal end to a
    /// live run once the periodic drains have taken every span -- sends NOTHING at
    /// all. This is the pre-diagnostics behavior: an empty batch carrying only a
    /// service.name resource is worth nothing to a backend, so there is no reason
    /// to contact the endpoint. Contrast
    /// `final_export_delivers_the_run_summary_when_the_last_drain_left_no_spans`,
    /// which is the flag-ON case and MUST still deliver a batch.
    #[test]
    fn flag_off_final_export_of_an_empty_drain_sends_nothing() {
        // No scripted responses: the server accepts nothing and returns at once.
        // A spurious empty batch would surface as a body here (and would also fail
        // the client, which has no response queued). Nothing must be sent.
        let (endpoint, handle) = spawn_mock_server(vec![]);
        let mut trace = trace_document(0);
        trace.diagnostics.bpf_operate_seed_hits_reqstate = 41;
        assert!(trace.spans.is_empty(), "this is the empty-final-trace case");

        let diagnostics =
            export_final_otlp_http(export_config_no_diagnostics(&endpoint, 2), &trace).unwrap();

        assert_eq!(
            diagnostics.batches, 0,
            "an empty final drain with the flag off must put nothing on the wire"
        );
        assert_eq!(diagnostics.attempts, 0, "no request may be attempted");
        let bodies = handle.join().unwrap();
        assert!(
            bodies.is_empty(),
            "with the flag off there is nothing to deliver, so no batch is sent"
        );
    }

    /// The final export still delivers the spans it was given -- the run summary is
    /// ADDED to the final export, it does not replace it -- and the summary batch
    /// goes LAST, so "read the last batch's resource" yields the final counters.
    #[test]
    fn final_export_sends_the_run_summary_last_after_the_span_batches() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(200), http_response(200)]);
        let mut trace = trace_document(2);
        trace.diagnostics.bpf_operate_seed_hits_reqstate = 9;

        let diagnostics = export_final_otlp_http(export_config(&endpoint, 2), &trace).unwrap();

        assert_eq!(diagnostics.batches, 2, "one span batch, one summary batch");
        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), 2);

        // First batch: the real spans, and NOT the summary.
        let first = decode_export_request(&bodies[0]);
        let spans = request_spans(&first);
        assert_eq!(spans.len(), 2, "the run's spans must still be exported");
        assert!(spans.iter().all(|span| span.name != RUN_SUMMARY_SPAN_NAME));

        // Last batch: the run summary.
        let last = decode_export_request(&bodies[1]);
        let summary = request_spans(&last);
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].name, RUN_SUMMARY_SPAN_NAME);
        assert_eq!(
            int_attribute(
                &summary[0].attributes,
                "rgwtrace.diag.bpf_operate_seed_hits_reqstate"
            ),
            Some(9),
        );
    }

    /// A mid-run drain must NOT emit a run-summary span: it would put one summary
    /// span per flush interval into the backend, and every one of them but the last
    /// would carry counters that are not the run's totals.
    #[test]
    fn a_periodic_drain_does_not_emit_a_run_summary_span() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(200)]);
        let trace = trace_document(1);

        export_otlp_http(export_config(&endpoint, 2), &trace).unwrap();

        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), 1);
        let request = decode_export_request(&bodies[0]);
        let spans = request_spans(&request);
        assert_eq!(spans.len(), 1);
        assert_ne!(
            spans[0].name, RUN_SUMMARY_SPAN_NAME,
            "the run summary belongs to the FINAL export only"
        );
    }

    /// The summary span must be a valid, self-consistent OTLP span: real ids of the
    /// right width, its own trace, and a unique id per run (two runs, or two
    /// tracers, must not collide on one trace id).
    #[test]
    fn the_run_summary_span_has_valid_unique_ids() {
        let trace = trace_document(0);

        let first = run_summary_span_document(&trace, 1_000);
        let second = run_summary_span_document(&trace, 2_000);

        assert_eq!(first.trace_id.len(), 32);
        assert_eq!(first.span_id.len(), 16);
        assert_eq!(first.parent_span_id, None);
        assert_eq!(first.start_ns, 1_000);
        assert_eq!(first.end_ns, 1_000);
        assert_ne!(
            first.trace_id, second.trace_id,
            "two runs must not share the summary span's trace id"
        );
        // And it encodes to OTLP without error (ids decode as hex).
        let span = run_summary_span(&trace).unwrap();
        assert_eq!(span.trace_id.len(), 16);
        assert_eq!(span.span_id.len(), 8);
        assert_eq!(span.name, RUN_SUMMARY_SPAN_NAME);
    }

    #[test]
    fn retries_otlp_export_after_retryable_failure() {
        let (endpoint, handle) = spawn_mock_server(vec![http_response(503), http_response(200)]);
        let document = trace_document(1);

        let diagnostics = export_otlp_http(export_config(&endpoint, 3), &document).unwrap();

        assert_eq!(diagnostics.attempts, 2, "expected exactly one retry");
        assert_eq!(diagnostics.failures, 1);
        assert_eq!(
            handle.join().unwrap().len(),
            2,
            "server should see two requests"
        );
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
        assert_eq!(handle.join().unwrap().len(), 1, "must not retry a 4xx");
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
        assert_eq!(
            handle.join().unwrap().len(),
            2,
            "should exhaust both attempts"
        );
    }

    #[test]
    fn redacts_userinfo_and_query_from_logged_urls() {
        let url = Url::parse("https://alice:s3cr3t@tempo.example.net:4318/v1/traces?api-key=k3y#x")
            .unwrap();
        assert_eq!(redact_url(&url), "https://tempo.example.net:4318/v1/traces");

        // Nothing to redact: the URL passes through unchanged, so the log stays
        // useful for the common case.
        let plain = Url::parse("http://localhost:4318/v1/traces").unwrap();
        assert_eq!(redact_url(&plain), "http://localhost:4318/v1/traces");
    }

    #[test]
    fn error_body_excerpt_is_capped_and_escaped() {
        // A hostile or merely verbose body: a forged log line, an ANSI escape, and
        // more than the cap.
        let mut body = b"bad request\r\n\x1b[31mFAKE LOG LINE\n".to_vec();
        body.extend(std::iter::repeat_n(b'x', 2 * ERROR_BODY_EXCERPT_BYTES));

        let excerpt = body_excerpt(&body);

        assert!(
            !excerpt.contains('\n') && !excerpt.contains('\r') && !excerpt.contains('\x1b'),
            "control characters must be escaped: {excerpt:?}"
        );
        assert!(
            excerpt.starts_with("bad request\\r\\n\\u{1b}[31mFAKE LOG LINE\\n"),
            "{excerpt}"
        );
        assert!(excerpt.ends_with(" [truncated]"), "{excerpt}");
        // The cap bounds the excerpt; escaping can only add a few bytes per
        // control character, so 2x is a generous ceiling.
        assert!(
            excerpt.len() < 2 * ERROR_BODY_EXCERPT_BYTES,
            "{}",
            excerpt.len()
        );

        // Cutting inside a multi-byte character must not panic; the lossy decode
        // of the cut tail is acceptable, a crash is not.
        let mut straddle = vec![b'a'; ERROR_BODY_EXCERPT_BYTES - 1];
        straddle.extend("é".as_bytes());
        straddle.push(b'z');
        let excerpt = body_excerpt(&straddle);
        assert!(excerpt.ends_with(" [truncated]"), "{excerpt}");
    }

    /// The cap holds on the wire, not just in the helper: an 8 KiB error page
    /// yields an error of about 1 KiB.
    #[test]
    fn error_response_body_is_capped() {
        let page = "x".repeat(8 * 1024);
        let response = Box::leak(
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                page.len()
            )
            .into_boxed_str(),
        );
        let (endpoint, handle) = spawn_mock_server(vec![response]);
        let document = trace_document(1);

        let err = export_otlp_http(export_config(&endpoint, 0), &document).unwrap_err();

        let message = err.to_string();
        assert!(message.contains("400"), "{message}");
        assert!(message.contains("[truncated]"), "{message}");
        assert!(
            message.len() < ERROR_BODY_EXCERPT_BYTES + 512,
            "the error must carry an excerpt, not the page: {} bytes",
            message.len()
        );
        assert_eq!(handle.join().unwrap().len(), 1);
    }

    /// An error body is written by the far end, and a proxy that rejects a
    /// request may echo it back -- URL, query string and auth header included.
    /// Such a body must reach the log and the error with the secrets removed.
    #[test]
    fn error_bodies_that_echo_secrets_are_scrubbed() {
        const HEADER_SECRET: &str = "hunter2-echoed-apikey";
        const QUERY_SECRET: &str = "query-key-echoed";
        let headers = vec![("X-Api-Key".to_string(), HEADER_SECRET.to_string())];
        let (endpoint, _handle) = {
            let page = format!(
                "400 Bad Request: rejected POST /v1/traces?api-key={QUERY_SECRET} \
                 with X-Api-Key: {HEADER_SECRET}"
            );
            let response = Box::leak(
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                    page.len()
                )
                .into_boxed_str(),
            );
            spawn_mock_server(vec![response])
        };
        let secret_endpoint = format!("{endpoint}?api-key={QUERY_SECRET}");
        let client = ExportClient::new(Duration::from_secs(5), &headers, None).unwrap();
        let config = ExportConfig {
            client: &client,
            ..export_config(&secret_endpoint, 0)
        };

        let mut error = String::new();
        let logged = capture_log(|| {
            error = format!(
                "{:#}",
                export_otlp_http(config, &trace_document(1)).unwrap_err()
            );
        });

        assert!(error.contains("400"), "{error}");
        assert!(
            error.contains("<redacted>"),
            "the echo is marked, not dropped: {error}"
        );
        for secret in [HEADER_SECRET, QUERY_SECRET] {
            assert!(
                !error.contains(secret),
                "{secret:?} leaked into the error: {error}"
            );
            assert!(
                !logged.contains(secret),
                "{secret:?} leaked into the log:\n{logged}"
            );
        }
    }

    /// NOTHING SECRET REACHES THE LOG. The operator's header values (API keys,
    /// tenant ids) and anything they put in the endpoint URL (userinfo, an
    /// `?api-key=` query) must not appear in any log line or error message on
    /// any path: the per-attempt debug line, the retry warning, the final error,
    /// and the connection-failure error whose text comes from reqwest (which
    /// prints the full URL it was given). Asserts on captured log TEXT at debug
    /// level, the most verbose an operator can turn on.
    #[test]
    fn header_values_and_endpoint_secrets_never_reach_the_log() {
        const HEADER_SECRET: &str = "hunter2-apikey-secret";
        const USERINFO_SECRET: &str = "basic-pass-secret";
        const QUERY_SECRET: &str = "query-key-secret";
        let headers = vec![
            ("X-Api-Key".to_string(), HEADER_SECRET.to_string()),
            ("X-Scope-OrgID".to_string(), "tenant-secret".to_string()),
        ];
        let document = trace_document(1);

        // A retry then success: exercises the debug, warn and info lines.
        let (endpoint, handle) = spawn_mock_server(vec![http_response(503), http_response(200)]);
        let secret_endpoint = endpoint
            .replace("http://", &format!("http://alice:{USERINFO_SECRET}@"))
            + &format!("?api-key={QUERY_SECRET}");
        let client = ExportClient::new(Duration::from_secs(5), &headers, None).unwrap();
        let config = ExportConfig {
            client: &client,
            ..export_config(&secret_endpoint, 3)
        };
        let logged = capture_log(|| {
            export_otlp_http(config, &document).unwrap();
        });
        assert_eq!(handle.join().unwrap().len(), 2);
        assert!(
            logged.contains("exporting OTLP traces") && logged.contains("retrying"),
            "the capture must have seen the export: {logged}"
        );
        assert!(
            logged.contains("/v1/traces"),
            "the host and path stay: {logged}"
        );
        for secret in [
            HEADER_SECRET,
            "tenant-secret",
            USERINFO_SECRET,
            QUERY_SECRET,
            "alice",
        ] {
            assert!(
                !logged.contains(secret),
                "{secret:?} leaked into the log:\n{logged}"
            );
        }

        // A connection failure: the error text is reqwest's, URL included.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_endpoint = format!(
            "http://alice:{USERINFO_SECRET}@{}/v1/traces?api-key={QUERY_SECRET}",
            closed.local_addr().unwrap()
        );
        drop(closed);
        let config = ExportConfig {
            client: &client,
            ..export_config(&closed_endpoint, 0)
        };
        let mut error = String::new();
        let logged = capture_log(|| {
            error = format!("{:#}", export_otlp_http(config, &document).unwrap_err());
        });
        assert!(error.contains("failed to send OTLP request"), "{error}");
        for secret in [HEADER_SECRET, USERINFO_SECRET, QUERY_SECRET, "alice"] {
            assert!(
                !error.contains(secret),
                "{secret:?} leaked into the error: {error}"
            );
            assert!(
                !logged.contains(secret),
                "{secret:?} leaked into the log:\n{logged}"
            );
        }
    }

    /// Run `body` with the log captured at DEBUG and return what this thread
    /// logged.
    ///
    /// The subscriber is installed GLOBALLY, once per test binary, and writes to a
    /// thread-local buffer. A scoped (`with_default`) subscriber is not reliable
    /// under the parallel test runner: a test on another thread that logs with no
    /// subscriber of its own makes tracing-core recompute the shared callsite
    /// cache from THAT thread's (absent) default, caching the callsite as "never
    /// interested" for every thread -- and the capture here comes back empty
    /// whenever such a test happens to run concurrently. With a global default,
    /// every thread's recomputation sees a real subscriber. Per-thread buffers
    /// keep the captures of concurrently running tests apart; the exporter runs
    /// synchronously on the calling thread, so its log lands in this thread's
    /// buffer.
    fn capture_log(body: impl FnOnce()) -> String {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(|| ThreadLocalSink)
                .with_max_level(tracing::Level::DEBUG)
                .finish();
            // Another test module may have installed its own global first; its
            // subscriber then receives the events, which the assertions below
            // report as an empty capture rather than silently passing.
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
        CAPTURED_LOG.with(|log| log.borrow_mut().clear());
        body();
        CAPTURED_LOG.with(|log| String::from_utf8(log.borrow().clone()).expect("log must be UTF-8"))
    }

    thread_local! {
        static CAPTURED_LOG: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    struct ThreadLocalSink;

    impl Write for ThreadLocalSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            CAPTURED_LOG.with(|log| log.borrow_mut().extend_from_slice(buf));
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A 3xx is an ERROR, never followed. reqwest's default policy follows up to
    /// ten redirects and re-sends the request -- the custom auth headers
    /// (`X-Api-Key`, `X-Scope-OrgID`, ...) AND the trace body -- to wherever
    /// `Location` points: another host, or https down to plain http. A collector
    /// that moved is an operator decision (`--otlp-endpoint`), not something the
    /// exporter resolves on its own with the credentials in hand.
    #[test]
    fn refuses_to_follow_otlp_redirects() {
        // The redirect target. Nothing ever answers it; the test only checks
        // whether anyone CONNECTED to it.
        let decoy = TcpListener::bind("127.0.0.1:0").unwrap();
        decoy.set_nonblocking(true).unwrap();
        let decoy_endpoint = format!("http://{}/v1/traces", decoy.local_addr().unwrap());
        let redirect = Box::leak(
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {decoy_endpoint}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_boxed_str(),
        );
        let (endpoint, handle) = spawn_mock_server(vec![redirect]);
        let document = trace_document(1);

        let err = export_otlp_http(export_config(&endpoint, 3), &document).unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("307"),
            "must surface the status: {message}"
        );
        assert!(
            message.contains("redirect"),
            "must name the cause: {message}"
        );
        assert_eq!(handle.join().unwrap().len(), 1, "a redirect is not retried");
        assert!(
            matches!(decoy.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock),
            "the exporter must never connect to the redirect target"
        );
    }

    /// A config with OTLP diagnostics ON -- the flag-on behavior the run-summary
    /// delivery tests assert against. The default in production is OFF; tests that
    /// exercise the off path build their own config or call `diagnostics_off`.
    fn export_config(endpoint: &str, retries: u32) -> ExportConfig<'_> {
        ExportConfig {
            endpoint,
            client: test_client(),
            compression: OtlpCompression::None,
            max_spans_per_batch: 512,
            max_bytes_per_batch: 0,
            retries,
            diagnostics: true,
        }
    }

    /// One plain client (no headers, no CA, 5 s timeout) shared by the tests
    /// that do not care about the client's configuration.
    fn test_client() -> &'static ExportClient {
        static CLIENT: std::sync::OnceLock<ExportClient> = std::sync::OnceLock::new();
        CLIENT.get_or_init(|| ExportClient::new(Duration::from_secs(5), &[], None).unwrap())
    }

    /// A mock server that accepts ONE connection and serves `requests` requests
    /// on it, keep-alive, replying 200 to each. Returns the bodies it read off
    /// that single connection: a client that opened a second connection for its
    /// second request leaves this server waiting on the first until its read
    /// timeout, and the count comes back short.
    fn spawn_keepalive_mock_server(requests: usize) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{addr}/v1/traces");
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            let mut served: Vec<Vec<u8>> = Vec::new();
            let deadline = std::time::Instant::now() + MOCK_SERVER_ACCEPT_TIMEOUT;
            let Some(mut stream) = accept_before(&listener, deadline) else {
                return served;
            };
            // Short: a second connection is the failure being tested for, and it
            // must fail fast rather than after the full accept timeout.
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            for _ in 0..requests {
                let body = read_http_request(&stream);
                if body.is_empty() {
                    break;
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
                stream.flush().ok();
                served.push(body);
            }
            served
        });
        (endpoint, handle)
    }

    /// The same config with OTLP diagnostics OFF -- the default -- so the flag-off
    /// tests assert the clean-resource, no-summary-span behavior.
    fn export_config_no_diagnostics(endpoint: &str, retries: u32) -> ExportConfig<'_> {
        ExportConfig {
            diagnostics: false,
            ..export_config(endpoint, retries)
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
    /// endpoint URL and a handle that yields the BODY of every request served, in
    /// order -- so a test can assert what actually reached the wire, not merely
    /// how many requests did.
    ///
    /// Accepting is DEADLINED rather than blocking. A test whose subject fails to
    /// export sends fewer requests than it scripted, and a blocking `accept()`
    /// would hang the harness forever on `join()` -- turning "the export never
    /// happened" (the exact bug
    /// `final_export_delivers_the_run_summary_when_the_last_drain_left_no_spans`
    /// exists to catch) into a hung test run instead of a failing assertion. On
    /// the deadline the server returns the bodies it did receive, so the test
    /// asserts against the truth: fewer requests than expected.
    fn spawn_mock_server(
        responses: Vec<&'static str>,
    ) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{addr}/v1/traces");
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            let mut served: Vec<Vec<u8>> = Vec::new();
            let deadline = std::time::Instant::now() + MOCK_SERVER_ACCEPT_TIMEOUT;
            for response in responses {
                let Some(mut stream) = accept_before(&listener, deadline) else {
                    // Deadline hit: the subject sent fewer requests than scripted.
                    break;
                };
                let body = read_http_request(&stream);
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().ok();
                served.push(body);
            }
            served
        });
        (endpoint, handle)
    }

    /// How long the mock server waits for a request that may never come.
    const MOCK_SERVER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Accept one connection, or `None` once `deadline` passes.
    fn accept_before(listener: &TcpListener, deadline: std::time::Instant) -> Option<TcpStream> {
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Only the listener is nonblocking; make the accepted socket
                    // blocking (with a read timeout) so the request read below is
                    // a plain blocking read that still cannot hang.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(MOCK_SERVER_ACCEPT_TIMEOUT))
                        .ok();
                    return Some(stream);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return None,
            }
        }
    }

    /// Consume a full HTTP request (headers + Content-Length body) so the
    /// client considers the request delivered before we respond, returning the
    /// body bytes.
    fn read_http_request(stream: &TcpStream) -> Vec<u8> {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            // A closed connection (`Ok(0)`) or a read timeout must not panic the
            // server thread: return what we have so the test still gets a verdict.
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return Vec::new(),
                Ok(_) => {}
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
        body
    }

    /// The OTLP request a mock-server body decodes to. Panics on a malformed body:
    /// an export that did not put a decodable OTLP request on the wire is a bug,
    /// not a test-input problem.
    fn decode_export_request(body: &[u8]) -> ExportTraceServiceRequest {
        ExportTraceServiceRequest::decode(body).expect("exported body must be an OTLP request")
    }

    /// The int value of `key` among `attributes`, or `None` if absent. Used to
    /// read diagnostics counters back off the wire.
    fn int_attribute(attributes: &[KeyValue], key: &str) -> Option<i64> {
        attributes.iter().find(|kv| kv.key == key).and_then(|kv| {
            match kv.value.as_ref()?.value.as_ref()? {
                any_value::Value::IntValue(value) => Some(*value),
                _ => None,
            }
        })
    }

    /// The single `ResourceSpans` of a decoded export request.
    fn only_resource_spans(request: &ExportTraceServiceRequest) -> &ResourceSpans {
        assert_eq!(
            request.resource_spans.len(),
            1,
            "an export request carries exactly one ResourceSpans"
        );
        &request.resource_spans[0]
    }

    /// Every span of a decoded export request.
    fn request_spans(request: &ExportTraceServiceRequest) -> &[Span] {
        &only_resource_spans(request).scope_spans[0].spans
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

    /// Span ids, in order, of the built protobuf spans across all batches.
    fn batched_span_ids(batches: &[Vec<Span>]) -> Vec<Vec<u8>> {
        batches
            .iter()
            .flat_map(|batch| batch.iter().map(|span| span.span_id.clone()))
            .collect()
    }

    /// Span ids, in order, of a source document decoded to their wire bytes, so
    /// they can be compared directly against `batched_span_ids`.
    fn document_span_ids(document: &TraceDocument) -> Vec<Vec<u8>> {
        document
            .spans
            .iter()
            .map(|span| decode_hex_id(&span.span_id, 8, "span_id").unwrap())
            .collect()
    }
}
