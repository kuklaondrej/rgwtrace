#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    classify::{classify_rados, classify_request, RadosRole, RequestClass},
    events::{RadosEvent, RequestEvent, TraceEvent},
};

#[derive(Debug, Default)]
pub struct Collector {
    starts_by_tid: BTreeMap<u32, RequestEvent>,
    requests: BTreeMap<String, RequestBuilder>,
    background: Vec<RadosEvent>,
    diagnostics: TraceDiagnostics,
}

#[derive(Debug, Default)]
struct RequestBuilder {
    request: Option<RequestEvent>,
    rados: Vec<RadosEvent>,
    last_seen_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceDocument {
    pub service_name: String,
    pub spans: Vec<SpanDocument>,
    pub diagnostics: TraceDiagnostics,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TraceDiagnostics {
    pub events_decoded: u64,
    pub decode_errors: u64,
    pub request_markers: u64,
    pub rados_ops: u64,
    pub correlated_rados_ops: u64,
    pub background_rados_ops: u64,
    pub same_thread_correlations: u64,
    pub missing_trans_id_background_ops: u64,
    pub spans_produced: u64,
    pub expired_request_groups: u64,
    pub expired_background_rados_ops: u64,
    pub truncated_trans_ids: u64,
    pub truncated_object_names: u64,
    pub truncated_acting_sets: u64,
    pub truncated_rados_ops: u64,
    pub truncated_cls_names: u64,
    pub truncated_method_names: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SpanDocument {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub start_ns: u64,
    pub end_ns: u64,
    pub attributes: Vec<Attribute>,
    pub events: Vec<SpanEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SpanEvent {
    pub name: String,
    pub time_ns: u64,
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Attribute {
    pub key: String,
    pub value: AttributeValue,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    U64(u64),
}

impl Collector {
    pub fn push(&mut self, event: TraceEvent) {
        self.diagnostics.events_decoded += 1;
        match event {
            TraceEvent::RequestStart(request) => {
                self.diagnostics.request_markers += 1;
                record_truncation(&mut self.diagnostics, request.truncation);
                self.starts_by_tid.insert(request.tid, request);
            }
            TraceEvent::RequestEnd(mut request) => {
                self.diagnostics.request_markers += 1;
                record_truncation(&mut self.diagnostics, request.truncation);
                if let Some(start) = self.starts_by_tid.remove(&request.tid) {
                    request.start_ns = start.start_ns;
                }
                let key = request_key(&request);
                let last_seen_ns = request.end_ns.max(request.start_ns);
                let builder = self.requests.entry(key).or_default();
                builder.last_seen_ns = builder.last_seen_ns.max(last_seen_ns);
                builder.request = Some(request);
            }
            TraceEvent::RadosOp(rados) => {
                self.diagnostics.rados_ops += 1;
                record_truncation(&mut self.diagnostics, rados.truncation);
                if rados.trans_id.is_empty() {
                    self.diagnostics.background_rados_ops += 1;
                    self.diagnostics.missing_trans_id_background_ops += 1;
                    self.background.push(rados);
                } else {
                    self.diagnostics.correlated_rados_ops += 1;
                    self.diagnostics.same_thread_correlations += 1;
                    let last_seen_ns = rados.finish_ns.max(rados.sent_ns);
                    let builder = self.requests.entry(rados.trans_id.clone()).or_default();
                    builder.last_seen_ns = builder.last_seen_ns.max(last_seen_ns);
                    builder.rados.push(rados);
                }
            }
        }
    }

    pub fn record_decode_error(&mut self) {
        self.diagnostics.decode_errors += 1;
    }

    pub fn drain_expired(
        &mut self,
        service_name: impl Into<String>,
        now_ns: u64,
        ttl_ns: u64,
    ) -> Option<TraceDocument> {
        let cutoff_ns = now_ns.saturating_sub(ttl_ns);
        let mut spans = Vec::new();
        let mut remaining_requests = BTreeMap::new();

        for (key, request) in std::mem::take(&mut self.requests) {
            if request.last_seen_ns != 0 && request.last_seen_ns <= cutoff_ns {
                self.diagnostics.expired_request_groups += 1;
                spans.extend(request_spans(key, request));
            } else {
                remaining_requests.insert(key, request);
            }
        }
        self.requests = remaining_requests;

        let mut remaining_background = Vec::new();
        for rados in std::mem::take(&mut self.background) {
            if rados_event_time_ns(&rados) <= cutoff_ns {
                self.diagnostics.expired_background_rados_ops += 1;
                spans.push(background_span(rados));
            } else {
                remaining_background.push(rados);
            }
        }
        self.background = remaining_background;

        if spans.is_empty() {
            return None;
        }

        let mut diagnostics = self.diagnostics.clone();
        diagnostics.spans_produced = spans.len() as u64;
        Some(TraceDocument {
            service_name: service_name.into(),
            spans,
            diagnostics,
        })
    }

    pub fn into_trace_document(mut self, service_name: impl Into<String>) -> TraceDocument {
        let mut spans = Vec::new();

        for (key, request) in self.requests {
            spans.extend(request_spans(key, request));
        }

        for rados in self.background {
            spans.push(background_span(rados));
        }
        self.diagnostics.spans_produced = spans.len() as u64;

        TraceDocument {
            service_name: service_name.into(),
            spans,
            diagnostics: self.diagnostics,
        }
    }
}

fn rados_event_time_ns(rados: &RadosEvent) -> u64 {
    rados.finish_ns.max(rados.sent_ns)
}

fn request_key(request: &RequestEvent) -> String {
    if request.trans_id.is_empty() {
        format!(
            "pid:{}:tid:{}:start:{}",
            request.pid, request.tid, request.start_ns
        )
    } else {
        request.trans_id.clone()
    }
}

fn request_spans(key: String, builder: RequestBuilder) -> Vec<SpanDocument> {
    let start_ns = builder
        .request
        .as_ref()
        .map(|request| request.start_ns)
        .or_else(|| builder.rados.iter().map(|event| event.sent_ns).min())
        .unwrap_or_default();
    let end_ns = builder
        .request
        .as_ref()
        .map(|request| request.end_ns)
        .or_else(|| builder.rados.iter().map(|event| event.finish_ns).max())
        .unwrap_or(start_ns);
    let trans_id = builder
        .request
        .as_ref()
        .map(|request| request.trans_id.as_str())
        .filter(|trans_id| !trans_id.is_empty())
        .unwrap_or(key.as_str());
    let request_class = classify_request(
        trans_id,
        builder
            .rados
            .first()
            .map(|event| event.object_name.as_str()),
    );
    let trace_id = trace_id(trans_id);
    let request_span_id = span_id(&format!("request:{trans_id}"));

    let mut spans = vec![SpanDocument {
        trace_id: trace_id.clone(),
        span_id: request_span_id.clone(),
        parent_span_id: None,
        name: "rgw.request".to_string(),
        start_ns,
        end_ns,
        attributes: vec![
            string_attr("rgw.trans_id", trans_id),
            string_attr("rgw.request_class", request_class_name(request_class)),
        ],
        events: Vec::new(),
    }];

    spans.extend(
        builder
            .rados
            .into_iter()
            .map(|rados| rados_child_span(rados, trace_id.clone(), request_span_id.clone())),
    );

    spans
}

fn background_span(rados: RadosEvent) -> SpanDocument {
    let start_ns = rados.sent_ns;
    let end_ns = rados.finish_ns;
    let trace_key = format!("background:{}:{}:{}", rados.pid, rados.tid, rados.sent_ns);
    let attributes = rados_attributes(&rados, "none", Some("missing_trans_id"));

    SpanDocument {
        trace_id: trace_id(&trace_key),
        span_id: span_id(&trace_key),
        parent_span_id: None,
        name: "rgw.background.rados_op".to_string(),
        start_ns,
        end_ns,
        attributes: attributes.clone(),
        events: vec![rados_span_event(rados, attributes)],
    }
}

fn rados_span_event(rados: RadosEvent, attributes: Vec<Attribute>) -> SpanEvent {
    let time_ns = rados.finish_ns;

    SpanEvent {
        name: "rados.op".to_string(),
        time_ns,
        attributes,
    }
}

fn rados_child_span(rados: RadosEvent, trace_id: String, parent_span_id: String) -> SpanDocument {
    let span_key = format!(
        "rados:{}:{}:{}:{}",
        rados.pid, rados.cid, rados.tid, rados.sent_ns
    );
    SpanDocument {
        trace_id,
        span_id: span_id(&span_key),
        parent_span_id: Some(parent_span_id),
        name: "rados.op".to_string(),
        start_ns: rados.sent_ns,
        end_ns: rados.finish_ns,
        attributes: rados_attributes(&rados, "same_thread", None),
        events: Vec::new(),
    }
}

fn rados_attributes(
    rados: &RadosEvent,
    correlation: &'static str,
    correlation_reason: Option<&'static str>,
) -> Vec<Attribute> {
    let role = classify_rados(rados);
    let ops = rados
        .ops
        .iter()
        .map(|op| match (&op.class, &op.method) {
            (Some(class), Some(method)) => format!("call({class}.{method})"),
            _ => op.name.clone(),
        })
        .collect::<Vec<_>>()
        .join(" ");

    let mut attributes = vec![
        u64_attr("ceph.rados.duration_ns", rados.duration_ns),
        u64_attr("ceph.rados.pool", rados.pool),
        string_attr("ceph.rados.pg", pg_name(rados.pool, rados.pg_seed)),
        u64_attr("ceph.rados.pg_seed", rados.pg_seed as u64),
        u64_attr("ceph.rados.target_osd", rados.target_osd as u64),
        string_attr("ceph.rados.acting", acting_set(&rados.acting)),
        string_attr("ceph.rados.object", &rados.object_name),
        string_attr("ceph.rados.ops", &ops),
        string_attr("ceph.rados.rw", format!("{:?}", rados.rw).to_lowercase()),
        u64_attr("ceph.rados.offset", rados.offset),
        u64_attr("ceph.rados.length", rados.length),
        string_attr("rgw.rados_role", rados_role_name(role)),
        string_attr("rgw.correlation", correlation),
    ];
    if let Some(reason) = correlation_reason {
        attributes.push(string_attr("rgw.correlation_reason", reason));
    }
    let truncation = rados.truncation.names();
    if !truncation.is_empty() {
        attributes.push(string_attr("rgwtrace.truncated", truncation.join(",")));
    }
    attributes
}

fn record_truncation(
    diagnostics: &mut TraceDiagnostics,
    truncation: crate::events::CaptureTruncation,
) {
    if truncation.trans_id {
        diagnostics.truncated_trans_ids += 1;
    }
    if truncation.object_name {
        diagnostics.truncated_object_names += 1;
    }
    if truncation.acting {
        diagnostics.truncated_acting_sets += 1;
    }
    if truncation.rados_ops {
        diagnostics.truncated_rados_ops += 1;
    }
    if truncation.cls_name {
        diagnostics.truncated_cls_names += 1;
    }
    if truncation.method_name {
        diagnostics.truncated_method_names += 1;
    }
}

fn pg_name(pool: u64, pg_seed: u32) -> String {
    format!("{pool}.{pg_seed:x}")
}

fn acting_set(acting: &[i32]) -> String {
    format!(
        "[{}]",
        acting
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn string_attr(key: impl Into<String>, value: impl Into<String>) -> Attribute {
    Attribute {
        key: key.into(),
        value: AttributeValue::String(value.into()),
    }
}

fn u64_attr(key: impl Into<String>, value: u64) -> Attribute {
    Attribute {
        key: key.into(),
        value: AttributeValue::U64(value),
    }
}

fn request_class_name(class: RequestClass) -> &'static str {
    match class {
        RequestClass::S3Request => "s3_request",
        RequestClass::RgwBackground => "rgw_background",
        RequestClass::RgwStartup => "rgw_startup",
        RequestClass::Unknown => "unknown",
    }
}

fn rados_role_name(role: RadosRole) -> &'static str {
    match role {
        RadosRole::Data => "data",
        RadosRole::BucketIndex => "bucket_index",
        RadosRole::BucketMeta => "bucket_meta",
        RadosRole::UserMeta => "user_meta",
        RadosRole::AuthMeta => "auth_meta",
        RadosRole::Gc => "gc",
        RadosRole::Notify => "notify",
        RadosRole::Sync => "sync",
        RadosRole::Config => "config",
        RadosRole::Unknown => "unknown",
    }
}

fn trace_id(key: &str) -> String {
    format!(
        "{:016x}{:016x}",
        fnv1a64(key.as_bytes()),
        fnv1a64_with_seed(key.as_bytes(), 1)
    )
}

fn span_id(key: &str) -> String {
    format!("{:016x}", fnv1a64(key.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_with_seed(bytes, 0)
}

fn fnv1a64_with_seed(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64 ^ seed;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CaptureTruncation, RadosDirection, RadosEvent, RequestEvent};

    fn rados(object_name: &str, trans_id: &str) -> RadosEvent {
        RadosEvent {
            pid: 42,
            cid: 1,
            tid: 2,
            sent_ns: 10,
            finish_ns: 20,
            duration_ns: 10,
            pool: 16,
            target_osd: 7,
            pg_seed: 1,
            acting: vec![1, 2, 3],
            rw: RadosDirection::Read,
            object_name: object_name.to_string(),
            trans_id: trans_id.to_string(),
            truncation: CaptureTruncation::default(),
            ops: Vec::new(),
            offset: 0,
            length: 0,
        }
    }

    #[test]
    fn emits_rados_ops_as_request_child_spans() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("object", "tx1")));
        collector.push(TraceEvent::RequestEnd(RequestEvent {
            start_ns: 1,
            end_ns: 30,
            pid: 42,
            tid: 7,
            trans_id: "tx1".to_string(),
            truncation: CaptureTruncation::default(),
        }));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        let request = &document.spans[0];
        let rados = &document.spans[1];
        assert_eq!(request.name, "rgw.request");
        assert!(request.events.is_empty());
        assert_eq!(rados.name, "rados.op");
        assert_eq!(rados.trace_id, request.trace_id);
        assert_eq!(
            rados.parent_span_id.as_deref(),
            Some(request.span_id.as_str())
        );
        assert_eq!(string_attribute(rados, "ceph.rados.pg"), Some("16.1"));
        assert_eq!(
            string_attribute(rados, "ceph.rados.acting"),
            Some("[1,2,3]")
        );
        assert_eq!(u64_attribute(rados, "ceph.rados.target_osd"), Some(7));
        assert_eq!(document.diagnostics.events_decoded, 2);
        assert_eq!(document.diagnostics.request_markers, 1);
        assert_eq!(document.diagnostics.rados_ops, 1);
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
        assert_eq!(document.diagnostics.same_thread_correlations, 1);
        assert_eq!(document.diagnostics.missing_trans_id_background_ops, 0);
        assert_eq!(document.diagnostics.spans_produced, 2);
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("same_thread")
        );
    }

    #[test]
    fn emits_background_span_without_trans_id() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("notify.0", "")));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].name, "rgw.background.rados_op");
        assert_eq!(document.diagnostics.rados_ops, 1);
        assert_eq!(document.diagnostics.correlated_rados_ops, 0);
        assert_eq!(document.diagnostics.background_rados_ops, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 0);
        assert_eq!(document.diagnostics.missing_trans_id_background_ops, 1);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation"),
            Some("none")
        );
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation_reason"),
            Some("missing_trans_id")
        );
    }

    #[test]
    fn drains_only_expired_trace_groups() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("old", "tx-old")));

        let mut fresh = rados("fresh", "tx-fresh");
        fresh.sent_ns = 1_000;
        fresh.finish_ns = 1_010;
        collector.push(TraceEvent::RadosOp(fresh));

        let document = collector.drain_expired("rgwtrace", 200, 100).unwrap();

        assert_eq!(document.spans.len(), 2);
        assert_eq!(document.diagnostics.expired_request_groups, 1);
        assert_eq!(document.diagnostics.spans_produced, 2);

        let remaining = collector.into_trace_document("rgwtrace");
        assert_eq!(remaining.spans.len(), 2);
    }

    #[test]
    fn drains_expired_background_ops() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("notify.0", "")));

        let document = collector.drain_expired("rgwtrace", 200, 100).unwrap();

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.diagnostics.expired_background_rados_ops, 1);
        assert!(collector.drain_expired("rgwtrace", 200, 100).is_none());
    }

    #[test]
    fn reports_capture_truncation() {
        let mut collector = Collector::default();
        let mut event = rados("object", "tx1");
        event.truncation = CaptureTruncation {
            object_name: true,
            rados_ops: true,
            ..CaptureTruncation::default()
        };
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.truncated_object_names, 1);
        assert_eq!(document.diagnostics.truncated_rados_ops, 1);
        assert_eq!(
            string_attribute(&document.spans[1], "rgwtrace.truncated"),
            Some("object_name,rados_ops")
        );
    }

    fn string_attribute<'a>(span: &'a SpanDocument, key: &str) -> Option<&'a str> {
        span.attributes.iter().find_map(|attribute| {
            if attribute.key == key {
                if let AttributeValue::String(value) = &attribute.value {
                    return Some(value.as_str());
                }
            }
            None
        })
    }

    fn u64_attribute(span: &SpanDocument, key: &str) -> Option<u64> {
        span.attributes.iter().find_map(|attribute| {
            if attribute.key == key {
                if let AttributeValue::U64(value) = attribute.value {
                    return Some(value);
                }
            }
            None
        })
    }
}
