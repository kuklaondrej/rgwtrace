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
}

#[derive(Debug, Default)]
struct RequestBuilder {
    request: Option<RequestEvent>,
    rados: Vec<RadosEvent>,
}

#[derive(Debug, Serialize)]
pub struct TraceDocument {
    pub service_name: String,
    pub spans: Vec<SpanDocument>,
}

#[derive(Debug, Serialize)]
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
        match event {
            TraceEvent::RequestStart(request) => {
                self.starts_by_tid.insert(request.tid, request);
            }
            TraceEvent::RequestEnd(mut request) => {
                if let Some(start) = self.starts_by_tid.remove(&request.tid) {
                    request.start_ns = start.start_ns;
                }
                let key = request_key(&request);
                self.requests.entry(key).or_default().request = Some(request);
            }
            TraceEvent::RadosOp(rados) => {
                if rados.trans_id.is_empty() {
                    self.background.push(rados);
                } else {
                    self.requests
                        .entry(rados.trans_id.clone())
                        .or_default()
                        .rados
                        .push(rados);
                }
            }
        }
    }

    pub fn into_trace_document(self, service_name: impl Into<String>) -> TraceDocument {
        let mut spans = Vec::new();

        for (key, request) in self.requests {
            spans.push(request_span(key, request));
        }

        for rados in self.background {
            spans.push(background_span(rados));
        }

        TraceDocument {
            service_name: service_name.into(),
            spans,
        }
    }
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

fn request_span(key: String, builder: RequestBuilder) -> SpanDocument {
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

    SpanDocument {
        trace_id: trace_id(trans_id),
        span_id: span_id(&format!("request:{trans_id}")),
        parent_span_id: None,
        name: "rgw.request".to_string(),
        start_ns,
        end_ns,
        attributes: vec![
            string_attr("rgw.trans_id", trans_id),
            string_attr("rgw.request_class", request_class_name(request_class)),
        ],
        events: builder.rados.into_iter().map(rados_span_event).collect(),
    }
}

fn background_span(rados: RadosEvent) -> SpanDocument {
    let role = classify_rados(&rados);
    let object_name = rados.object_name.clone();
    let start_ns = rados.sent_ns;
    let end_ns = rados.finish_ns;
    let trace_key = format!("background:{}:{}:{}", rados.pid, rados.tid, rados.sent_ns);

    SpanDocument {
        trace_id: trace_id(&trace_key),
        span_id: span_id(&trace_key),
        parent_span_id: None,
        name: "rgw.background.rados_op".to_string(),
        start_ns,
        end_ns,
        attributes: vec![
            string_attr("ceph.rados.object", &object_name),
            string_attr("rgw.rados_role", rados_role_name(role)),
        ],
        events: vec![rados_span_event(rados)],
    }
}

fn rados_span_event(rados: RadosEvent) -> SpanEvent {
    let role = classify_rados(&rados);
    let ops = rados
        .ops
        .iter()
        .map(|op| match (&op.class, &op.method) {
            (Some(class), Some(method)) => format!("call({class}.{method})"),
            _ => op.name.clone(),
        })
        .collect::<Vec<_>>()
        .join(" ");

    SpanEvent {
        name: "rados.op".to_string(),
        time_ns: rados.finish_ns,
        attributes: vec![
            u64_attr("ceph.rados.duration_ns", rados.duration_ns),
            u64_attr("ceph.rados.pool", rados.pool),
            u64_attr("ceph.rados.pg_seed", rados.pg_seed as u64),
            string_attr("ceph.rados.object", &rados.object_name),
            string_attr("ceph.rados.ops", &ops),
            string_attr("ceph.rados.rw", format!("{:?}", rados.rw).to_lowercase()),
            u64_attr("ceph.rados.offset", rados.offset),
            u64_attr("ceph.rados.length", rados.length),
            string_attr("rgw.rados_role", rados_role_name(role)),
        ],
    }
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
    use crate::events::{RadosDirection, RadosEvent, RequestEvent};

    fn rados(object_name: &str, trans_id: &str) -> RadosEvent {
        RadosEvent {
            pid: 42,
            cid: 1,
            tid: 2,
            sent_ns: 10,
            finish_ns: 20,
            duration_ns: 10,
            pool: 16,
            pg_seed: 1,
            acting: vec![1, 2, 3],
            rw: RadosDirection::Read,
            object_name: object_name.to_string(),
            trans_id: trans_id.to_string(),
            ops: Vec::new(),
            offset: 0,
            length: 0,
        }
    }

    #[test]
    fn attaches_rados_ops_to_request_span() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("object", "tx1")));
        collector.push(TraceEvent::RequestEnd(RequestEvent {
            start_ns: 1,
            end_ns: 30,
            pid: 42,
            tid: 7,
            trans_id: "tx1".to_string(),
        }));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].name, "rgw.request");
        assert_eq!(document.spans[0].events.len(), 1);
    }

    #[test]
    fn emits_background_span_without_trans_id() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("notify.0", "")));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.spans[0].name, "rgw.background.rados_op");
    }
}
