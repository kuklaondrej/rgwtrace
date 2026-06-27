#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    classify::{classify_rados, classify_request, RadosRole, RequestClass},
    events::{RadosCorrelationSource, RadosEvent, RequestEvent, TraceEvent},
};

#[derive(Debug, Default)]
pub struct Collector {
    starts_by_tid: BTreeMap<u32, RequestEvent>,
    requests: BTreeMap<String, RequestBuilder>,
    pending_inference: Vec<RadosEvent>,
    background: Vec<BackgroundRados>,
    diagnostics: TraceDiagnostics,
    infer_correlation: bool,
    inference_window_ns: u64,
}

#[derive(Debug, Default)]
struct RequestBuilder {
    request: Option<RequestEvent>,
    rados: Vec<CorrelatedRados>,
    last_seen_ns: u64,
    saw_request_start: bool,
}

#[derive(Debug)]
struct CorrelatedRados {
    event: RadosEvent,
    correlation: RadosCorrelation,
}

#[derive(Debug)]
struct BackgroundRados {
    event: RadosEvent,
    reason: BackgroundReason,
}

#[derive(Clone, Copy, Debug)]
enum RadosCorrelation {
    OpSubmitContext,
    ActiveContext,
    SameThread,
    Inferred,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackgroundReason {
    MissingTransId,
    ClassifiedBackgroundRole,
    NoInferenceCandidate,
    AmbiguousInferenceCandidates,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InferenceMatch {
    Match(String),
    NoCandidate,
    Ambiguous,
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceDocument {
    pub service_name: String,
    pub spans: Vec<SpanDocument>,
    pub diagnostics: TraceDiagnostics,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BpfDiagnostics {
    pub ringbuf_request_drops: u64,
    pub ringbuf_rados_drops: u64,
    pub rados_map_drops: u64,
    pub rados_finish_misses: u64,
    pub request_context_drops: u64,
    pub probe_read_failures: u64,
    pub rgw_rados_operate_hits: u64,
    pub rgw_rados_operate_contexts: u64,
    pub rados_writer_process_hits: u64,
    pub rados_writer_process_contexts: u64,
    pub rados_writer_write_exclusive_hits: u64,
    pub rados_writer_write_exclusive_contexts: u64,
    pub objecter_op_submit_hits: u64,
    pub objecter_op_submit_active_contexts: u64,
    pub objecter_op_submit_same_thread_contexts: u64,
    pub objecter_op_submit_misses: u64,
    pub rados_writer_ctor_hits: u64,
    pub rados_writer_ctor_contexts: u64,
    pub put_processor_prepare_hits: u64,
    pub put_processor_prepare_contexts: u64,
    pub head_object_processor_process_hits: u64,
    pub head_object_processor_process_contexts: u64,
    pub rgw_write_meta_hits: u64,
    pub rgw_write_meta_contexts: u64,
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
    pub op_submit_context_correlations: u64,
    pub active_context_correlations: u64,
    pub inferred_correlations: u64,
    pub inference_no_candidate_rados_ops: u64,
    pub inference_ambiguous_rados_ops: u64,
    pub missing_trans_id_background_ops: u64,
    pub background_rados_by_role: BTreeMap<String, u64>,
    pub background_rados_by_reason: BTreeMap<String, u64>,
    pub spans_produced: u64,
    pub expired_request_groups: u64,
    pub expired_background_rados_ops: u64,
    pub truncated_trans_ids: u64,
    pub truncated_object_names: u64,
    pub truncated_acting_sets: u64,
    pub truncated_rados_ops: u64,
    pub truncated_cls_names: u64,
    pub truncated_method_names: u64,
    pub otlp_queue_dropped_traces: u64,
    pub otlp_queue_dropped_spans: u64,
    pub bpf_ringbuf_request_drops: u64,
    pub bpf_ringbuf_rados_drops: u64,
    pub bpf_rados_map_drops: u64,
    pub bpf_rados_finish_misses: u64,
    pub bpf_request_context_drops: u64,
    pub bpf_probe_read_failures: u64,
    pub bpf_rgw_rados_operate_hits: u64,
    pub bpf_rgw_rados_operate_contexts: u64,
    pub bpf_rados_writer_process_hits: u64,
    pub bpf_rados_writer_process_contexts: u64,
    pub bpf_rados_writer_write_exclusive_hits: u64,
    pub bpf_rados_writer_write_exclusive_contexts: u64,
    pub bpf_objecter_op_submit_hits: u64,
    pub bpf_objecter_op_submit_active_contexts: u64,
    pub bpf_objecter_op_submit_same_thread_contexts: u64,
    pub bpf_objecter_op_submit_misses: u64,
    pub bpf_rados_writer_ctor_hits: u64,
    pub bpf_rados_writer_ctor_contexts: u64,
    pub bpf_put_processor_prepare_hits: u64,
    pub bpf_put_processor_prepare_contexts: u64,
    pub bpf_head_object_processor_process_hits: u64,
    pub bpf_head_object_processor_process_contexts: u64,
    pub bpf_rgw_write_meta_hits: u64,
    pub bpf_rgw_write_meta_contexts: u64,
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
    pub fn with_inferred_correlation(inference_window_ns: u64) -> Self {
        Self {
            infer_correlation: true,
            inference_window_ns,
            ..Self::default()
        }
    }

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
                let saw_request_start = if let Some(start) = self.starts_by_tid.remove(&request.tid)
                {
                    request.start_ns = start.start_ns;
                    if request.rgw_request_id == 0 {
                        request.rgw_request_id = start.rgw_request_id;
                    }
                    if request.rgw_req_id.is_empty() {
                        request.rgw_req_id = start.rgw_req_id;
                    }
                    if request.trans_id.is_empty() {
                        request.trans_id = start.trans_id;
                    }
                    true
                } else {
                    false
                };
                let key = request_key(&request);
                let last_seen_ns = request.end_ns.max(request.start_ns);
                let builder = self.requests.entry(key).or_default();
                builder.last_seen_ns = builder.last_seen_ns.max(last_seen_ns);
                builder.saw_request_start |= saw_request_start;
                builder.request = Some(request);
                self.retry_pending_inference();
            }
            TraceEvent::RadosOp(rados) => {
                self.diagnostics.rados_ops += 1;
                record_truncation(&mut self.diagnostics, rados.truncation);
                if let Some(key) = rados_request_key(&rados) {
                    let correlation = RadosCorrelation::from_source(rados.correlation_source)
                        .unwrap_or(RadosCorrelation::SameThread);
                    self.record_correlated_rados(key, rados, correlation);
                } else {
                    let role = classify_rados(&rados);
                    if self.infer_correlation && inferable_rados_role(role) {
                        match self.inferred_request_key(&rados) {
                            InferenceMatch::Match(key) => {
                                self.record_correlated_rados(
                                    key,
                                    rados,
                                    RadosCorrelation::Inferred,
                                );
                            }
                            InferenceMatch::NoCandidate | InferenceMatch::Ambiguous => {
                                self.pending_inference.push(rados);
                            }
                        };
                    } else {
                        self.record_background_rados(rados, background_reason_for_role(role));
                    }
                }
            }
        }
    }

    fn inferred_request_key(&self, rados: &RadosEvent) -> InferenceMatch {
        if rados.send_tid != 0 {
            let same_thread_match =
                nearest_inference_match(self.requests.iter().filter_map(|(key, builder)| {
                    let request = builder.request.as_ref()?;
                    (request.tid == rados.send_tid)
                        .then(|| {
                            inference_candidate_distance(request, rados, self.inference_window_ns)
                                .map(|distance| (key.clone(), distance))
                        })
                        .flatten()
                }));
            if same_thread_match != InferenceMatch::NoCandidate {
                return same_thread_match;
            }
        }

        nearest_inference_match(self.requests.iter().filter_map(|(key, builder)| {
            let request = builder.request.as_ref()?;
            inference_candidate_distance(request, rados, self.inference_window_ns)
                .map(|distance| (key.clone(), distance))
        }))
    }

    fn retry_pending_inference(&mut self) {
        let mut remaining = Vec::new();
        for rados in std::mem::take(&mut self.pending_inference) {
            match self.inferred_request_key(&rados) {
                InferenceMatch::Match(key) => {
                    self.record_correlated_rados(key, rados, RadosCorrelation::Inferred);
                }
                InferenceMatch::NoCandidate | InferenceMatch::Ambiguous => remaining.push(rados),
            }
        }
        self.pending_inference = remaining;
    }

    fn finalize_expired_pending_inference(&mut self, cutoff_ns: u64) {
        let mut remaining = Vec::new();
        for rados in std::mem::take(&mut self.pending_inference) {
            if rados_event_time_ns(&rados) <= cutoff_ns {
                self.finalize_pending_inference(rados);
            } else {
                remaining.push(rados);
            }
        }
        self.pending_inference = remaining;
    }

    fn finalize_all_pending_inference(&mut self) {
        for rados in std::mem::take(&mut self.pending_inference) {
            self.finalize_pending_inference(rados);
        }
    }

    fn finalize_pending_inference(&mut self, rados: RadosEvent) {
        match self.inferred_request_key(&rados) {
            InferenceMatch::Match(key) => {
                self.record_correlated_rados(key, rados, RadosCorrelation::Inferred);
            }
            InferenceMatch::NoCandidate => {
                self.record_background_rados(rados, BackgroundReason::NoInferenceCandidate);
            }
            InferenceMatch::Ambiguous => {
                self.record_background_rados(rados, BackgroundReason::AmbiguousInferenceCandidates);
            }
        }
    }

    fn record_correlated_rados(
        &mut self,
        key: String,
        rados: RadosEvent,
        correlation: RadosCorrelation,
    ) {
        self.diagnostics.correlated_rados_ops += 1;
        match correlation {
            RadosCorrelation::OpSubmitContext => {
                self.diagnostics.op_submit_context_correlations += 1
            }
            RadosCorrelation::ActiveContext => self.diagnostics.active_context_correlations += 1,
            RadosCorrelation::SameThread => self.diagnostics.same_thread_correlations += 1,
            RadosCorrelation::Inferred => self.diagnostics.inferred_correlations += 1,
        }
        let last_seen_ns = rados_event_time_ns(&rados);
        let builder = self.requests.entry(key).or_default();
        builder.last_seen_ns = builder.last_seen_ns.max(last_seen_ns);
        builder.rados.push(CorrelatedRados {
            event: rados,
            correlation,
        });
    }

    fn record_background_rados(&mut self, rados: RadosEvent, reason: BackgroundReason) {
        self.diagnostics.background_rados_ops += 1;
        if rados.trans_id.is_empty() {
            self.diagnostics.missing_trans_id_background_ops += 1;
        }
        match reason {
            BackgroundReason::NoInferenceCandidate => {
                self.diagnostics.inference_no_candidate_rados_ops += 1;
            }
            BackgroundReason::AmbiguousInferenceCandidates => {
                self.diagnostics.inference_ambiguous_rados_ops += 1;
            }
            BackgroundReason::MissingTransId | BackgroundReason::ClassifiedBackgroundRole => {}
        }
        record_background_breakdown(&mut self.diagnostics, &rados, reason);
        self.background.push(BackgroundRados {
            event: rados,
            reason,
        });
    }

    pub fn record_decode_error(&mut self) {
        self.diagnostics.decode_errors += 1;
    }

    pub fn record_otlp_queue_drop(&mut self, spans: usize) {
        self.diagnostics.otlp_queue_dropped_traces += 1;
        self.diagnostics.otlp_queue_dropped_spans = self
            .diagnostics
            .otlp_queue_dropped_spans
            .saturating_add(spans as u64);
    }

    pub fn merge_bpf_diagnostics(&mut self, diagnostics: BpfDiagnostics) {
        self.diagnostics.bpf_ringbuf_request_drops = diagnostics.ringbuf_request_drops;
        self.diagnostics.bpf_ringbuf_rados_drops = diagnostics.ringbuf_rados_drops;
        self.diagnostics.bpf_rados_map_drops = diagnostics.rados_map_drops;
        self.diagnostics.bpf_rados_finish_misses = diagnostics.rados_finish_misses;
        self.diagnostics.bpf_request_context_drops = diagnostics.request_context_drops;
        self.diagnostics.bpf_probe_read_failures = diagnostics.probe_read_failures;
        self.diagnostics.bpf_rgw_rados_operate_hits = diagnostics.rgw_rados_operate_hits;
        self.diagnostics.bpf_rgw_rados_operate_contexts = diagnostics.rgw_rados_operate_contexts;
        self.diagnostics.bpf_rados_writer_process_hits = diagnostics.rados_writer_process_hits;
        self.diagnostics.bpf_rados_writer_process_contexts =
            diagnostics.rados_writer_process_contexts;
        self.diagnostics.bpf_rados_writer_write_exclusive_hits =
            diagnostics.rados_writer_write_exclusive_hits;
        self.diagnostics.bpf_rados_writer_write_exclusive_contexts =
            diagnostics.rados_writer_write_exclusive_contexts;
        self.diagnostics.bpf_objecter_op_submit_hits = diagnostics.objecter_op_submit_hits;
        self.diagnostics.bpf_objecter_op_submit_active_contexts =
            diagnostics.objecter_op_submit_active_contexts;
        self.diagnostics.bpf_objecter_op_submit_same_thread_contexts =
            diagnostics.objecter_op_submit_same_thread_contexts;
        self.diagnostics.bpf_objecter_op_submit_misses = diagnostics.objecter_op_submit_misses;
        self.diagnostics.bpf_rados_writer_ctor_hits = diagnostics.rados_writer_ctor_hits;
        self.diagnostics.bpf_rados_writer_ctor_contexts = diagnostics.rados_writer_ctor_contexts;
        self.diagnostics.bpf_put_processor_prepare_hits = diagnostics.put_processor_prepare_hits;
        self.diagnostics.bpf_put_processor_prepare_contexts =
            diagnostics.put_processor_prepare_contexts;
        self.diagnostics.bpf_head_object_processor_process_hits =
            diagnostics.head_object_processor_process_hits;
        self.diagnostics.bpf_head_object_processor_process_contexts =
            diagnostics.head_object_processor_process_contexts;
        self.diagnostics.bpf_rgw_write_meta_hits = diagnostics.rgw_write_meta_hits;
        self.diagnostics.bpf_rgw_write_meta_contexts = diagnostics.rgw_write_meta_contexts;
    }

    pub fn drain_expired(
        &mut self,
        service_name: impl Into<String>,
        now_ns: u64,
        ttl_ns: u64,
    ) -> Option<TraceDocument> {
        let cutoff_ns = now_ns.saturating_sub(ttl_ns);
        self.retry_pending_inference();
        self.finalize_expired_pending_inference(cutoff_ns);

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
        for background in std::mem::take(&mut self.background) {
            if rados_event_time_ns(&background.event) <= cutoff_ns {
                self.diagnostics.expired_background_rados_ops += 1;
                spans.push(background_span(background));
            } else {
                remaining_background.push(background);
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
        self.retry_pending_inference();
        self.finalize_all_pending_inference();

        let mut spans = Vec::new();

        for (key, request) in self.requests {
            spans.extend(request_spans(key, request));
        }

        for background in self.background {
            spans.push(background_span(background));
        }
        self.diagnostics.spans_produced = spans.len() as u64;

        TraceDocument {
            service_name: service_name.into(),
            spans,
            diagnostics: self.diagnostics,
        }
    }
}

fn nearest_inference_match(mut candidates: impl Iterator<Item = (String, u64)>) -> InferenceMatch {
    let Some((mut best_key, mut best_distance)) = candidates.next() else {
        return InferenceMatch::NoCandidate;
    };
    let mut ambiguous = false;
    for (key, distance) in candidates {
        if distance < best_distance {
            best_key = key;
            best_distance = distance;
            ambiguous = false;
        } else if distance == best_distance {
            ambiguous = true;
        }
    }
    if ambiguous {
        InferenceMatch::Ambiguous
    } else {
        InferenceMatch::Match(best_key)
    }
}

fn rados_event_time_ns(rados: &RadosEvent) -> u64 {
    rados.finish_ns.max(rados.sent_ns)
}

fn request_key(request: &RequestEvent) -> String {
    if let Some(key) = internal_request_key(&request.rgw_req_id, request.rgw_request_id) {
        key
    } else if request.trans_id.is_empty() {
        format!(
            "pid:{}:tid:{}:start:{}",
            request.pid, request.tid, request.start_ns
        )
    } else {
        request.trans_id.clone()
    }
}

fn rados_request_key(rados: &RadosEvent) -> Option<String> {
    internal_request_key(&rados.rgw_req_id, rados.rgw_request_id)
        .or_else(|| (!rados.trans_id.is_empty()).then(|| rados.trans_id.clone()))
}

fn internal_request_key(rgw_req_id: &str, rgw_request_id: u64) -> Option<String> {
    if !rgw_req_id.is_empty() {
        Some(format!("rgw_req_id:{rgw_req_id}"))
    } else if rgw_request_id != 0 {
        Some(format!("rgw_request_id:{rgw_request_id}"))
    } else {
        None
    }
}

#[derive(Debug, Default)]
struct RequestIdentity {
    rgw_req_id: String,
    rgw_request_id: u64,
    trans_id: String,
    span_key: String,
}

fn request_identity(key: &str, builder: &RequestBuilder) -> RequestIdentity {
    let mut identity = RequestIdentity {
        rgw_req_id: builder
            .request
            .as_ref()
            .map(|request| request.rgw_req_id.clone())
            .filter(|value| !value.is_empty())
            .or_else(|| {
                builder.rados.iter().find_map(|rados| {
                    (!rados.event.rgw_req_id.is_empty()).then(|| rados.event.rgw_req_id.clone())
                })
            })
            .unwrap_or_default(),
        rgw_request_id: builder
            .request
            .as_ref()
            .map(|request| request.rgw_request_id)
            .filter(|value| *value != 0)
            .or_else(|| {
                builder.rados.iter().find_map(|rados| {
                    (rados.event.rgw_request_id != 0).then_some(rados.event.rgw_request_id)
                })
            })
            .unwrap_or_default(),
        trans_id: builder
            .request
            .as_ref()
            .map(|request| request.trans_id.clone())
            .filter(|value| !value.is_empty())
            .or_else(|| {
                builder.rados.iter().find_map(|rados| {
                    (!rados.event.trans_id.is_empty()).then(|| rados.event.trans_id.clone())
                })
            })
            .unwrap_or_default(),
        span_key: String::new(),
    };

    identity.span_key = if !identity.rgw_req_id.is_empty() {
        format!("rgw_req_id:{}", identity.rgw_req_id)
    } else if identity.rgw_request_id != 0 {
        format!("rgw_request_id:{}", identity.rgw_request_id)
    } else if !identity.trans_id.is_empty() {
        identity.trans_id.clone()
    } else {
        key.to_string()
    };
    identity
}

fn request_spans(key: String, builder: RequestBuilder) -> Vec<SpanDocument> {
    let request_start_ns = builder.request.as_ref().map(|request| request.start_ns);
    let rados_start_ns = builder.rados.iter().map(|rados| rados.event.sent_ns).min();
    let start_ns = request_start_ns
        .into_iter()
        .chain(rados_start_ns)
        .min()
        .unwrap_or_default();
    let request_end_ns = builder.request.as_ref().map(|request| request.end_ns);
    let rados_end_ns = builder
        .rados
        .iter()
        .map(|rados| rados.event.finish_ns)
        .max();
    let end_ns = request_end_ns
        .into_iter()
        .chain(rados_end_ns)
        .max()
        .unwrap_or(start_ns);
    let identity = request_identity(&key, &builder);
    let request_class = classify_request(
        &identity.trans_id,
        builder
            .rados
            .first()
            .map(|rados| rados.event.object_name.as_str()),
    );
    let request_class = if !identity.trans_id.is_empty()
        || !identity.rgw_req_id.is_empty()
        || identity.rgw_request_id != 0
    {
        RequestClass::S3Request
    } else {
        request_class
    };
    let trace_id = trace_id(&identity.span_key);
    let request_span_id = span_id(&format!("request:{}", identity.span_key));
    let duration_quality = request_duration_quality(&builder);
    let mut attributes = vec![
        string_attr("rgw.trans_id", &identity.trans_id),
        string_attr("rgw.request_class", request_class_name(request_class)),
        string_attr("rgw.duration_quality", duration_quality),
    ];
    if !identity.rgw_req_id.is_empty() {
        attributes.push(string_attr("rgw.req_id", &identity.rgw_req_id));
    }
    if identity.rgw_request_id != 0 {
        attributes.push(u64_attr("rgw.request_id", identity.rgw_request_id));
    }

    let mut spans = vec![SpanDocument {
        trace_id: trace_id.clone(),
        span_id: request_span_id.clone(),
        parent_span_id: None,
        name: "rgw.request".to_string(),
        start_ns,
        end_ns,
        attributes,
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

fn background_span(background: BackgroundRados) -> SpanDocument {
    let rados = background.event;
    let start_ns = rados.sent_ns;
    let end_ns = rados.finish_ns;
    let trace_key = format!("background:{}:{}:{}", rados.pid, rados.tid, rados.sent_ns);
    let attributes = rados_attributes(&rados, "none", Some(background.reason.name()));

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

fn rados_child_span(
    rados: CorrelatedRados,
    trace_id: String,
    parent_span_id: String,
) -> SpanDocument {
    let event = rados.event;
    let span_key = format!(
        "rados:{}:{}:{}:{}",
        event.pid, event.cid, event.tid, event.sent_ns
    );
    SpanDocument {
        trace_id,
        span_id: span_id(&span_key),
        parent_span_id: Some(parent_span_id),
        name: "rados.op".to_string(),
        start_ns: event.sent_ns,
        end_ns: event.finish_ns,
        attributes: rados_attributes(&event, rados.correlation.name(), rados.correlation.reason()),
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
        string_attr("rgw.correlation_source", rados.correlation_source.name()),
    ];
    if !rados.rgw_req_id.is_empty() {
        attributes.push(string_attr("rgw.req_id", &rados.rgw_req_id));
    }
    if rados.rgw_request_id != 0 {
        attributes.push(u64_attr("rgw.request_id", rados.rgw_request_id));
    }
    if !rados.trans_id.is_empty() {
        attributes.push(string_attr("rgw.trans_id", &rados.trans_id));
    }
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

fn record_background_breakdown(
    diagnostics: &mut TraceDiagnostics,
    rados: &RadosEvent,
    reason: BackgroundReason,
) {
    let role = rados_role_name(classify_rados(rados));
    *diagnostics
        .background_rados_by_role
        .entry(role.to_string())
        .or_default() += 1;
    *diagnostics
        .background_rados_by_reason
        .entry(reason.name().to_string())
        .or_default() += 1;
}

fn background_reason_for_role(role: RadosRole) -> BackgroundReason {
    match role {
        RadosRole::Gc | RadosRole::Notify | RadosRole::Sync | RadosRole::Config => {
            BackgroundReason::ClassifiedBackgroundRole
        }
        _ => BackgroundReason::MissingTransId,
    }
}

fn inference_candidate_distance(
    request: &RequestEvent,
    rados: &RadosEvent,
    window_ns: u64,
) -> Option<u64> {
    if request.pid != rados.pid {
        return None;
    }
    let request_start = request.start_ns.min(request.end_ns);
    let request_end = request.end_ns.max(request.start_ns);
    let rados_start = rados.sent_ns.min(rados.finish_ns);
    let rados_end = rados.finish_ns.max(rados.sent_ns);
    if rados_end < request_start || rados_start > request_end.saturating_add(window_ns) {
        return None;
    }
    if rados_start <= request_end && rados_end >= request_start {
        Some(0)
    } else {
        Some(rados_start.saturating_sub(request_end))
    }
}

fn inferable_rados_role(role: RadosRole) -> bool {
    matches!(
        role,
        RadosRole::Data
            | RadosRole::BucketIndex
            | RadosRole::BucketMeta
            | RadosRole::UserMeta
            | RadosRole::AuthMeta
            | RadosRole::Unknown
    )
}

impl RadosCorrelation {
    fn from_source(source: RadosCorrelationSource) -> Option<Self> {
        match source {
            RadosCorrelationSource::OpSubmitContext => Some(Self::OpSubmitContext),
            RadosCorrelationSource::ActiveContext => Some(Self::ActiveContext),
            RadosCorrelationSource::SameThread => Some(Self::SameThread),
            RadosCorrelationSource::None | RadosCorrelationSource::Unknown(_) => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::OpSubmitContext => "op_submit_context",
            Self::ActiveContext => "active_context",
            Self::SameThread => "same_thread",
            Self::Inferred => "inferred",
        }
    }

    fn reason(self) -> Option<&'static str> {
        match self {
            Self::OpSubmitContext | Self::ActiveContext | Self::SameThread => None,
            Self::Inferred => Some("pid_time_window"),
        }
    }
}

impl BackgroundReason {
    fn name(self) -> &'static str {
        match self {
            Self::MissingTransId => "missing_trans_id",
            Self::ClassifiedBackgroundRole => "classified_background_role",
            Self::NoInferenceCandidate => "no_inference_candidate",
            Self::AmbiguousInferenceCandidates => "ambiguous_inference_candidates",
        }
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

fn request_duration_quality(builder: &RequestBuilder) -> &'static str {
    if builder.request.is_none() {
        "rados_bounds"
    } else if builder.saw_request_start {
        "request_lifecycle"
    } else {
        "marker"
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
    use crate::events::{
        CaptureTruncation, RadosCorrelationSource, RadosDirection, RadosEvent, RadosOp,
        RequestEvent,
    };

    fn rados(object_name: &str, trans_id: &str) -> RadosEvent {
        RadosEvent {
            pid: 42,
            send_tid: 7,
            cid: 1,
            tid: 2,
            sent_ns: 10,
            finish_ns: 20,
            duration_ns: 10,
            rgw_request_id: 0,
            pool: 16,
            target_osd: 7,
            pg_seed: 1,
            acting: vec![1, 2, 3],
            rw: RadosDirection::Read,
            object_name: object_name.to_string(),
            rgw_req_id: String::new(),
            trans_id: trans_id.to_string(),
            correlation_source: RadosCorrelationSource::None,
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
        collector.push(TraceEvent::RequestEnd(request("tx1", 1, 30)));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        let request = &document.spans[0];
        let rados = &document.spans[1];
        assert_eq!(request.name, "rgw.request");
        assert!(request.events.is_empty());
        assert_eq!(
            string_attribute(request, "rgw.duration_quality"),
            Some("marker")
        );
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
        assert_eq!(rados.parent_span_id, Some(request.span_id.clone()));
        assert_ne!(rados.span_id, request.span_id);
    }

    #[test]
    fn correlates_by_rgw_req_id_when_trans_id_is_missing() {
        let mut collector = Collector::default();
        let mut request = request("", 1, 30);
        request.rgw_req_id = "req-internal".to_string();
        collector.push(TraceEvent::RequestEnd(request));

        let mut child = rados("object", "");
        child.rgw_req_id = "req-internal".to_string();
        child.correlation_source = RadosCorrelationSource::OpSubmitContext;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        let request = &document.spans[0];
        let rados = &document.spans[1];
        assert_eq!(
            rados.parent_span_id.as_deref(),
            Some(request.span_id.as_str())
        );
        assert_eq!(
            string_attribute(request, "rgw.req_id"),
            Some("req-internal")
        );
        assert_eq!(string_attribute(request, "rgw.trans_id"), Some(""));
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("op_submit_context")
        );
        assert_eq!(document.diagnostics.op_submit_context_correlations, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 0);
        assert_eq!(document.diagnostics.inferred_correlations, 0);
    }

    #[test]
    fn active_context_correlates_by_numeric_request_id_when_trans_id_is_missing() {
        let mut collector = Collector::default();
        let mut request = request("", 1, 30);
        request.rgw_request_id = 4242;
        collector.push(TraceEvent::RequestEnd(request));

        let mut child = rados("object", "");
        child.rgw_request_id = 4242;
        child.correlation_source = RadosCorrelationSource::ActiveContext;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        let request = &document.spans[0];
        let rados = &document.spans[1];
        assert_eq!(
            rados.parent_span_id.as_deref(),
            Some(request.span_id.as_str())
        );
        assert_eq!(u64_attribute(request, "rgw.request_id"), Some(4242));
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("active_context")
        );
        assert_eq!(document.diagnostics.active_context_correlations, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 0);
        assert_eq!(document.diagnostics.inferred_correlations, 0);
    }

    #[test]
    fn op_submit_context_identity_precedes_conflicting_trans_id() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RequestEnd(request("tx-same-thread", 1, 30)));
        let mut target = request("", 1, 30);
        target.rgw_req_id = "req-op-submit".to_string();
        collector.push(TraceEvent::RequestEnd(target));

        let mut child = rados("object", "tx-same-thread");
        child.rgw_req_id = "req-op-submit".to_string();
        child.correlation_source = RadosCorrelationSource::OpSubmitContext;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");
        let rados = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("expected correlated rados span");
        let parent = document
            .spans
            .iter()
            .find(|span| Some(span.span_id.as_str()) == rados.parent_span_id.as_deref())
            .expect("expected parent request span");

        assert_eq!(
            string_attribute(parent, "rgw.req_id"),
            Some("req-op-submit")
        );
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("op_submit_context")
        );
    }

    #[test]
    fn op_submit_same_thread_identity_precedes_conflicting_trans_id() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RequestEnd(request("tx-stale-thread", 1, 30)));
        let mut target = request("", 1, 30);
        target.rgw_req_id = "req-op-submit-same-thread".to_string();
        collector.push(TraceEvent::RequestEnd(target));

        let mut child = rados("object", "tx-stale-thread");
        child.rgw_req_id = "req-op-submit-same-thread".to_string();
        child.correlation_source = RadosCorrelationSource::SameThread;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");
        let rados = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("expected correlated rados span");
        let parent = document
            .spans
            .iter()
            .find(|span| Some(span.span_id.as_str()) == rados.parent_span_id.as_deref())
            .expect("expected parent request span");

        assert_eq!(
            string_attribute(parent, "rgw.req_id"),
            Some("req-op-submit-same-thread")
        );
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("same_thread")
        );
        assert_eq!(
            string_attribute(rados, "rgw.correlation_source"),
            Some("same_thread")
        );
        assert_eq!(document.diagnostics.same_thread_correlations, 1);
        assert_eq!(document.diagnostics.op_submit_context_correlations, 0);
        assert_eq!(document.diagnostics.inferred_correlations, 0);
    }

    #[test]
    fn active_context_identity_precedes_conflicting_trans_id() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RequestEnd(request("tx-same-thread", 1, 30)));
        let mut target = request("", 1, 30);
        target.rgw_request_id = 9001;
        collector.push(TraceEvent::RequestEnd(target));

        let mut child = rados("object", "tx-same-thread");
        child.rgw_request_id = 9001;
        child.correlation_source = RadosCorrelationSource::ActiveContext;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");
        let rados = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("expected correlated rados span");
        let parent = document
            .spans
            .iter()
            .find(|span| Some(span.span_id.as_str()) == rados.parent_span_id.as_deref())
            .expect("expected parent request span");

        assert_eq!(u64_attribute(parent, "rgw.request_id"), Some(9001));
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("active_context")
        );
        assert_eq!(document.diagnostics.active_context_correlations, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 0);
    }

    #[test]
    fn same_thread_identity_precedes_inferred_candidate() {
        let mut collector = Collector::with_inferred_correlation(100);
        collector.push(TraceEvent::RequestEnd(request_with_tid(
            "tx-inferred",
            8,
            1,
            30,
        )));
        collector.push(TraceEvent::RequestEnd(request_with_tid(
            "tx-same-thread",
            7,
            1,
            30,
        )));

        let mut child = rados("object", "tx-same-thread");
        child.sent_ns = 40;
        child.finish_ns = 45;
        child.correlation_source = RadosCorrelationSource::SameThread;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.same_thread_correlations, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 0);
        let rados = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("expected correlated rados span");
        let parent = document
            .spans
            .iter()
            .find(|span| Some(span.span_id.as_str()) == rados.parent_span_id.as_deref())
            .expect("expected parent request span");
        assert_eq!(
            string_attribute(parent, "rgw.trans_id"),
            Some("tx-same-thread")
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
            document.diagnostics.background_rados_by_role.get("notify"),
            Some(&1)
        );
        assert_eq!(
            document
                .diagnostics
                .background_rados_by_reason
                .get("classified_background_role"),
            Some(&1)
        );
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation"),
            Some("none")
        );
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation_reason"),
            Some("classified_background_role")
        );
    }

    #[test]
    fn classifies_background_sync_objects_without_inference() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RadosOp(rados("meta.log.period.1", "")));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(
            string_attribute(&document.spans[0], "rgw.rados_role"),
            Some("sync")
        );
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation_reason"),
            Some("classified_background_role")
        );
        assert_eq!(
            document.diagnostics.background_rados_by_role.get("sync"),
            Some(&1)
        );
    }

    #[test]
    fn explicit_request_identity_correlates_background_role_objects() {
        let mut collector = Collector::default();
        let mut request = request("tx1", 1, 30);
        request.rgw_req_id = "req1".to_string();
        collector.push(TraceEvent::RequestEnd(request));

        let mut child = rados("notify.0", "");
        child.rgw_req_id = "req1".to_string();
        child.correlation_source = RadosCorrelationSource::OpSubmitContext;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
        assert_eq!(document.diagnostics.op_submit_context_correlations, 1);
        let rados = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("expected correlated rados span");
        let parent = document
            .spans
            .iter()
            .find(|span| Some(span.span_id.as_str()) == rados.parent_span_id.as_deref())
            .expect("expected parent request span");
        assert_eq!(string_attribute(parent, "rgw.req_id"), Some("req1"));
        assert_eq!(string_attribute(rados, "rgw.rados_role"), Some("notify"));
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("op_submit_context")
        );
    }

    #[test]
    fn inferred_correlation_is_disabled_by_default() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RequestEnd(request("tx1", 1, 30)));
        let mut event = rados("object", "");
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.inferred_correlations, 0);
        assert_eq!(document.diagnostics.background_rados_ops, 1);
        assert!(document
            .spans
            .iter()
            .any(|span| span.name == "rgw.background.rados_op"));
    }

    #[test]
    fn infers_correlation_for_single_pid_time_window_candidate() {
        let mut collector = Collector::with_inferred_correlation(100);
        collector.push(TraceEvent::RequestEnd(request("tx1", 1, 30)));
        let mut event = rados("object", "");
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.same_thread_correlations, 0);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
        assert_eq!(document.spans[1].trace_id, document.spans[0].trace_id);
        assert_eq!(
            document.spans[1].parent_span_id.as_deref(),
            Some(document.spans[0].span_id.as_str())
        );
        assert_eq!(
            string_attribute(&document.spans[1], "rgw.correlation"),
            Some("inferred")
        );
        assert_eq!(
            string_attribute(&document.spans[1], "rgw.correlation_reason"),
            Some("pid_time_window")
        );
    }

    #[test]
    fn defers_untagged_rados_until_request_marker_arrives() {
        let mut collector = Collector::with_inferred_correlation(100);
        let mut event = rados("object", "");
        event.sent_ns = 20;
        event.finish_ns = 25;
        collector.push(TraceEvent::RadosOp(event));

        collector.push(TraceEvent::RequestEnd(request("tx1", 1, 30)));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
        assert_eq!(document.diagnostics.inference_no_candidate_rados_ops, 0);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        assert_eq!(
            string_attribute(&document.spans[1], "rgw.correlation"),
            Some("inferred")
        );
    }

    #[test]
    fn sender_tid_preferred_over_same_pid_candidates() {
        let mut collector = Collector::with_inferred_correlation(100);
        collector.push(TraceEvent::RequestEnd(request_with_tid("tx1", 7, 1, 30)));
        collector.push(TraceEvent::RequestEnd(request_with_tid("tx2", 9, 1, 30)));
        let mut event = rados("object", "");
        event.send_tid = 9;
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        let rados = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("expected inferred rados child span");
        let parent = document
            .spans
            .iter()
            .find(|span| Some(span.span_id.as_str()) == rados.parent_span_id.as_deref())
            .expect("expected parent request span");
        assert_eq!(string_attribute(parent, "rgw.trans_id"), Some("tx2"));
    }

    #[test]
    fn nearest_inference_candidate_wins_over_older_window_match() {
        let mut collector = Collector::with_inferred_correlation(100);
        collector.push(TraceEvent::RequestEnd(request("tx-older", 1, 30)));
        collector.push(TraceEvent::RequestEnd(request("tx-nearest", 50, 60)));
        let mut event = rados("object", "");
        event.sent_ns = 64;
        event.finish_ns = 70;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        let rados = document
            .spans
            .iter()
            .find(|span| span.name == "rados.op")
            .expect("expected inferred rados child span");
        let parent = document
            .spans
            .iter()
            .find(|span| Some(span.span_id.as_str()) == rados.parent_span_id.as_deref())
            .expect("expected parent request span");
        assert_eq!(string_attribute(parent, "rgw.trans_id"), Some("tx-nearest"));
    }

    #[test]
    fn infers_when_rados_interval_overlaps_request_start() {
        let mut collector = Collector::with_inferred_correlation(0);
        collector.push(TraceEvent::RequestEnd(request("tx1", 10, 30)));
        let mut event = rados("object", "");
        event.sent_ns = 5;
        event.finish_ns = 15;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.correlated_rados_ops, 1);
        assert_eq!(document.diagnostics.inferred_correlations, 1);
        assert_eq!(document.diagnostics.background_rados_ops, 0);
    }

    #[test]
    fn marks_request_lifecycle_duration_when_start_was_seen() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RequestStart(request("", 1, 0)));
        collector.push(TraceEvent::RequestEnd(request("tx1", 10, 30)));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans[0].start_ns, 1);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("request_lifecycle")
        );
    }

    #[test]
    fn request_start_identity_is_preserved_for_later_rados_context() {
        let mut collector = Collector::default();
        let mut start = request("", 1, 0);
        start.rgw_request_id = 123;
        collector.push(TraceEvent::RequestStart(start));
        collector.push(TraceEvent::RequestEnd(request("tx1", 10, 30)));

        let mut child = rados("object", "");
        child.rgw_request_id = 123;
        child.correlation_source = RadosCorrelationSource::OpSubmitContext;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans.len(), 2);
        let request = &document.spans[0];
        let rados = &document.spans[1];
        assert_eq!(u64_attribute(request, "rgw.request_id"), Some(123));
        assert_eq!(string_attribute(request, "rgw.trans_id"), Some("tx1"));
        assert_eq!(
            rados.parent_span_id.as_deref(),
            Some(request.span_id.as_str())
        );
        assert_eq!(
            string_attribute(rados, "rgw.correlation"),
            Some("op_submit_context")
        );
    }

    #[test]
    fn request_span_envelopes_child_rados_bounds() {
        let mut collector = Collector::default();
        let mut child = rados("object", "tx1");
        child.sent_ns = 20;
        child.finish_ns = 100;
        collector.push(TraceEvent::RadosOp(child));
        collector.push(TraceEvent::RequestEnd(request("tx1", 30, 40)));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans[0].start_ns, 20);
        assert_eq!(document.spans[0].end_ns, 100);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("marker")
        );
    }

    #[test]
    fn marks_rados_bounds_duration_without_request_marker() {
        let mut collector = Collector::default();
        let mut child = rados("object", "tx1");
        child.sent_ns = 20;
        child.finish_ns = 100;
        collector.push(TraceEvent::RadosOp(child));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.spans[0].name, "rgw.request");
        assert_eq!(document.spans[0].start_ns, 20);
        assert_eq!(document.spans[0].end_ns, 100);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.duration_quality"),
            Some("rados_bounds")
        );
    }

    #[test]
    fn does_not_infer_ambiguous_candidates() {
        let mut collector = Collector::with_inferred_correlation(100);
        collector.push(TraceEvent::RequestEnd(request("tx1", 1, 30)));
        collector.push(TraceEvent::RequestEnd(request("tx2", 1, 30)));
        let mut event = rados("object", "");
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.inferred_correlations, 0);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 1);
        assert_eq!(document.diagnostics.inference_no_candidate_rados_ops, 0);
        assert_eq!(document.diagnostics.background_rados_ops, 1);
        assert_eq!(
            string_attribute(&document.spans[2], "rgw.correlation_reason"),
            Some("ambiguous_inference_candidates")
        );
        assert_eq!(
            document
                .diagnostics
                .background_rados_by_reason
                .get("ambiguous_inference_candidates"),
            Some(&1)
        );
    }

    #[test]
    fn records_no_candidate_when_inference_window_misses() {
        let mut collector = Collector::with_inferred_correlation(5);
        collector.push(TraceEvent::RequestEnd(request("tx1", 1, 30)));
        let mut event = rados("object", "");
        event.sent_ns = 40;
        event.finish_ns = 45;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.inferred_correlations, 0);
        assert_eq!(document.diagnostics.inference_no_candidate_rados_ops, 1);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        assert_eq!(
            string_attribute(&document.spans[1], "rgw.correlation_reason"),
            Some("no_inference_candidate")
        );
    }

    #[test]
    fn drain_expired_finalizes_pending_no_candidate_once() {
        let mut collector = Collector::with_inferred_correlation(5);
        let mut event = rados("object", "");
        event.sent_ns = 10;
        event.finish_ns = 20;
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.drain_expired("rgwtrace", 200, 100).unwrap();

        assert_eq!(document.spans.len(), 1);
        assert_eq!(document.diagnostics.background_rados_ops, 1);
        assert_eq!(document.diagnostics.inference_no_candidate_rados_ops, 1);
        assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 0);
        assert_eq!(document.diagnostics.expired_background_rados_ops, 1);
        assert_eq!(
            string_attribute(&document.spans[0], "rgw.correlation_reason"),
            Some("no_inference_candidate")
        );

        let remaining = collector.into_trace_document("rgwtrace");
        assert_eq!(remaining.spans.len(), 0);
        assert_eq!(remaining.diagnostics.background_rados_ops, 1);
        assert_eq!(remaining.diagnostics.inference_no_candidate_rados_ops, 1);
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
            trans_id: true,
            object_name: true,
            acting: true,
            rados_ops: true,
            cls_name: true,
            method_name: true,
        };
        collector.push(TraceEvent::RadosOp(event));

        let document = collector.into_trace_document("rgwtrace");

        assert_eq!(document.diagnostics.truncated_trans_ids, 1);
        assert_eq!(document.diagnostics.truncated_object_names, 1);
        assert_eq!(document.diagnostics.truncated_acting_sets, 1);
        assert_eq!(document.diagnostics.truncated_rados_ops, 1);
        assert_eq!(document.diagnostics.truncated_cls_names, 1);
        assert_eq!(document.diagnostics.truncated_method_names, 1);
        assert_eq!(
            string_attribute(&document.spans[1], "rgwtrace.truncated"),
            Some("trans_id,object_name,acting,rados_ops,cls_name,method_name")
        );
    }

    #[test]
    fn records_otlp_queue_drops() {
        let mut collector = Collector::default();

        collector.record_otlp_queue_drop(3);
        collector.record_otlp_queue_drop(2);

        let document = collector.into_trace_document("rgwtrace");
        assert_eq!(document.diagnostics.otlp_queue_dropped_traces, 2);
        assert_eq!(document.diagnostics.otlp_queue_dropped_spans, 5);
    }

    #[test]
    fn merges_bpf_diagnostics() {
        let mut collector = Collector::default();

        collector.merge_bpf_diagnostics(BpfDiagnostics {
            ringbuf_request_drops: 1,
            ringbuf_rados_drops: 2,
            rados_map_drops: 3,
            rados_finish_misses: 4,
            request_context_drops: 5,
            probe_read_failures: 6,
            rgw_rados_operate_hits: 7,
            rgw_rados_operate_contexts: 8,
            rados_writer_process_hits: 9,
            rados_writer_process_contexts: 10,
            rados_writer_write_exclusive_hits: 11,
            rados_writer_write_exclusive_contexts: 12,
            objecter_op_submit_hits: 13,
            objecter_op_submit_active_contexts: 14,
            objecter_op_submit_same_thread_contexts: 15,
            objecter_op_submit_misses: 16,
            rados_writer_ctor_hits: 17,
            rados_writer_ctor_contexts: 18,
            put_processor_prepare_hits: 19,
            put_processor_prepare_contexts: 20,
            head_object_processor_process_hits: 21,
            head_object_processor_process_contexts: 22,
            rgw_write_meta_hits: 23,
            rgw_write_meta_contexts: 24,
        });

        let document = collector.into_trace_document("rgwtrace");
        assert_eq!(document.diagnostics.bpf_ringbuf_request_drops, 1);
        assert_eq!(document.diagnostics.bpf_ringbuf_rados_drops, 2);
        assert_eq!(document.diagnostics.bpf_rados_map_drops, 3);
        assert_eq!(document.diagnostics.bpf_rados_finish_misses, 4);
        assert_eq!(document.diagnostics.bpf_request_context_drops, 5);
        assert_eq!(document.diagnostics.bpf_probe_read_failures, 6);
        assert_eq!(document.diagnostics.bpf_rgw_rados_operate_hits, 7);
        assert_eq!(document.diagnostics.bpf_rgw_rados_operate_contexts, 8);
        assert_eq!(document.diagnostics.bpf_rados_writer_process_hits, 9);
        assert_eq!(document.diagnostics.bpf_rados_writer_process_contexts, 10);
        assert_eq!(
            document.diagnostics.bpf_rados_writer_write_exclusive_hits,
            11
        );
        assert_eq!(
            document
                .diagnostics
                .bpf_rados_writer_write_exclusive_contexts,
            12
        );
        assert_eq!(document.diagnostics.bpf_objecter_op_submit_hits, 13);
        assert_eq!(
            document.diagnostics.bpf_objecter_op_submit_active_contexts,
            14
        );
        assert_eq!(
            document
                .diagnostics
                .bpf_objecter_op_submit_same_thread_contexts,
            15
        );
        assert_eq!(document.diagnostics.bpf_objecter_op_submit_misses, 16);
        assert_eq!(document.diagnostics.bpf_rados_writer_ctor_hits, 17);
        assert_eq!(document.diagnostics.bpf_rados_writer_ctor_contexts, 18);
        assert_eq!(document.diagnostics.bpf_put_processor_prepare_hits, 19);
        assert_eq!(document.diagnostics.bpf_put_processor_prepare_contexts, 20);
        assert_eq!(
            document.diagnostics.bpf_head_object_processor_process_hits,
            21
        );
        assert_eq!(
            document
                .diagnostics
                .bpf_head_object_processor_process_contexts,
            22
        );
        assert_eq!(document.diagnostics.bpf_rgw_write_meta_hits, 23);
        assert_eq!(document.diagnostics.bpf_rgw_write_meta_contexts, 24);
    }

    #[test]
    fn collector_trace_matches_golden_fixture() {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RequestStart(request("", 100, 0)));

        let mut child = rados("bucket-object", "tx-golden");
        child.sent_ns = 120;
        child.finish_ns = 190;
        child.duration_ns = 70;
        child.pg_seed = 0x2a;
        child.rw = RadosDirection::Write;
        child.offset = 128;
        child.length = 4096;
        child.ops = vec![
            RadosOp {
                code: 0x2202,
                name: "writefull".to_string(),
                class: None,
                method: None,
            },
            RadosOp {
                code: 0x1401,
                name: "call".to_string(),
                class: Some("cls".to_string()),
                method: Some("method".to_string()),
            },
        ];
        collector.push(TraceEvent::RadosOp(child));
        collector.push(TraceEvent::RequestEnd(request("tx-golden", 150, 250)));

        let mut background = rados("notify.0", "");
        background.sent_ns = 300;
        background.finish_ns = 320;
        background.duration_ns = 20;
        background.ops = vec![RadosOp {
            code: 0x1201,
            name: "read".to_string(),
            class: None,
            method: None,
        }];
        collector.push(TraceEvent::RadosOp(background));

        let actual = serde_json::to_string_pretty(&collector.into_trace_document("rgwtrace"))
            .expect("trace document should serialize");
        let expected = include_str!("../tests/fixtures/collector_trace_golden.json").trim();

        assert_eq!(
            actual, expected,
            "collector trace golden changed:\n{actual}"
        );
    }

    fn request(trans_id: &str, start_ns: u64, end_ns: u64) -> RequestEvent {
        request_with_tid(trans_id, 7, start_ns, end_ns)
    }

    fn request_with_tid(trans_id: &str, tid: u32, start_ns: u64, end_ns: u64) -> RequestEvent {
        RequestEvent {
            start_ns,
            end_ns,
            rgw_request_id: 0,
            pid: 42,
            tid,
            rgw_req_id: String::new(),
            trans_id: trans_id.to_string(),
            truncation: CaptureTruncation::default(),
        }
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
