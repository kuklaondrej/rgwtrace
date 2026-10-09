//! Tests for the collector's incremental expiry and inference indexes.
//!
//! The load-bearing one is `indexed_inference_matches_the_exhaustive_reference`:
//! a differential test that replays random event streams through the collector
//! AND through a line-by-line model of the old exhaustive algorithm (retry every
//! pending op against every group on every marker), and requires the same
//! decision for every op, in the same order. That is the coverage-regression
//! assertion for inference: an op the old code inferred must still be inferred,
//! onto the same request, and nothing new may be inferred.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::*;
use crate::events::{CaptureTruncation, RadosDirection, RadosEvent, RequestEvent};

const PID: u32 = 42;

fn op(object: &str, trans_id: &str, pid: u32, send_tid: u32, sent: u64, finish: u64) -> RadosEvent {
    RadosEvent {
        pid,
        send_tid,
        cid: 1,
        tid: sent,
        sent_ns: sent,
        finish_ns: finish,
        duration_ns: finish.saturating_sub(sent),
        pool: 1,
        target_osd: 0,
        pg_seed: 0,
        acting: Vec::new(),
        rw: RadosDirection::Read,
        object_name: object.to_string(),
        trans_id: trans_id.into(),
        truncation: CaptureTruncation::default(),
        ops: Vec::new(),
        offset: 0,
        length: 0,
    }
}

fn marker(trans_id: &str, pid: u32, tid: u32, start: u64, end: u64) -> RequestEvent {
    RequestEvent {
        start_ns: start,
        end_ns: end,
        pid,
        tid,
        trans_id: trans_id.into(),
        truncation: CaptureTruncation::default(),
    }
}

fn start(trans_id: &str, tid: u32, at: u64) -> TraceEvent {
    TraceEvent::RequestStart(marker(trans_id, PID, tid, at, 0))
}

fn end(trans_id: &str, tid: u32, start: u64, end: u64) -> TraceEvent {
    TraceEvent::RequestEnd(marker(trans_id, PID, tid, start, end))
}

fn untagged(object: &str, send_tid: u32, sent: u64, finish: u64) -> TraceEvent {
    TraceEvent::RadosOp(op(object, "", PID, send_tid, sent, finish))
}

fn tagged(object: &str, trans_id: &str, sent: u64, finish: u64) -> TraceEvent {
    TraceEvent::RadosOp(op(object, trans_id, PID, 7, sent, finish))
}

fn attr<'a>(span: &'a SpanDocument, key: &str) -> Option<&'a str> {
    span.attributes
        .iter()
        .find_map(|attribute| match &attribute.value {
            AttributeValue::String(value) if attribute.key == key => Some(value.as_str()),
            _ => None,
        })
}

/// Where every op ended up: per request trans_id, its children's object names in
/// span order; and per background op, its correlation reason.
#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    children: BTreeMap<String, Vec<String>>,
    background: BTreeMap<String, String>,
}

fn outcome(documents: &[TraceDocument]) -> Outcome {
    let mut outcome = Outcome::default();
    for document in documents {
        let parents: HashMap<&str, &str> = document
            .spans
            .iter()
            .filter(|span| span.name == "rgw.request")
            .map(|span| (span.span_id.as_str(), attr(span, "rgw.trans_id").unwrap()))
            .collect();
        for span in &document.spans {
            let object = attr(span, "ceph.rados.object");
            match (span.name.as_str(), object) {
                ("rados.op", Some(object)) => {
                    let parent = parents[span.parent_span_id.as_deref().unwrap()];
                    outcome
                        .children
                        .entry(parent.to_string())
                        .or_default()
                        .push(object.to_string());
                }
                ("rgw.background.rados_op", Some(object)) => {
                    outcome.background.insert(
                        object.to_string(),
                        attr(span, "rgw.correlation_reason").unwrap().to_string(),
                    );
                }
                _ => {}
            }
        }
    }
    outcome
}

// ---------------------------------------------------------------------------
// Reference model: the pre-index inference algorithm, transcribed.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RefGroup {
    request: Option<RequestEvent>,
    measured_end: Option<u64>,
    last_seen: u64,
    first_seen: u64,
    children: Vec<String>,
}

impl RefGroup {
    fn observe(&mut self, begin: u64, end: u64) {
        self.last_seen = self.last_seen.max(end);
        if begin != 0 {
            self.first_seen = if self.first_seen == 0 {
                begin
            } else {
                self.first_seen.min(begin)
            };
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefMatch {
    NoCandidate,
    Ambiguous,
}

struct Reference {
    window: u64,
    groups: BTreeMap<String, RefGroup>,
    pending: Vec<RadosEvent>,
    emitted: HashSet<String>,
    outcome: Outcome,
}

impl Reference {
    fn new(window: u64) -> Self {
        Self {
            window,
            groups: BTreeMap::new(),
            pending: Vec::new(),
            emitted: HashSet::new(),
            outcome: Outcome::default(),
        }
    }

    fn candidate(&self, request: &RequestEvent, rados: &RadosEvent) -> bool {
        if request.pid != rados.pid {
            return false;
        }
        let request_start = request.start_ns.min(request.end_ns);
        let request_end = request.end_ns.max(request.start_ns);
        let rados_start = rados.sent_ns.min(rados.finish_ns);
        let rados_end = rados.finish_ns.max(rados.sent_ns);
        rados_end >= request_start && rados_start <= request_end.saturating_add(self.window)
    }

    fn unique(mut keys: impl Iterator<Item = String>) -> Result<String, RefMatch> {
        let Some(first) = keys.next() else {
            return Err(RefMatch::NoCandidate);
        };
        if keys.next().is_some() {
            return Err(RefMatch::Ambiguous);
        }
        Ok(first)
    }

    fn infer(&self, rados: &RadosEvent) -> Result<String, RefMatch> {
        if rados.send_tid != 0 {
            let same_thread = Self::unique(self.groups.iter().filter_map(|(key, group)| {
                let request = group.request.as_ref()?;
                (request.tid == rados.send_tid && self.candidate(request, rados))
                    .then(|| key.clone())
            }));
            if same_thread != Err(RefMatch::NoCandidate) {
                return same_thread;
            }
        }
        Self::unique(self.groups.iter().filter_map(|(key, group)| {
            let request = group.request.as_ref()?;
            self.candidate(request, rados).then(|| key.clone())
        }))
    }

    fn correlate(&mut self, key: String, rados: RadosEvent) {
        let group = self.groups.entry(key).or_default();
        group.observe(
            rados.sent_ns.min(rados.finish_ns),
            rados.finish_ns.max(rados.sent_ns),
        );
        group.children.push(rados.object_name);
    }

    fn background(&mut self, rados: RadosEvent, reason: &str) {
        self.outcome
            .background
            .insert(rados.object_name, reason.to_string());
    }

    fn retry(&mut self) {
        for rados in std::mem::take(&mut self.pending) {
            match self.infer(&rados) {
                Ok(key) => self.correlate(key, rados),
                Err(_) => self.pending.push(rados),
            }
        }
    }

    fn finalize(&mut self, rados: RadosEvent) {
        match self.infer(&rados) {
            Ok(key) => self.correlate(key, rados),
            Err(RefMatch::NoCandidate) => self.background(rados, "no_inference_candidate"),
            Err(RefMatch::Ambiguous) => self.background(rados, "ambiguous_inference_candidates"),
        }
    }

    fn push(&mut self, event: TraceEvent) {
        match event {
            TraceEvent::RequestStart(request) => {
                let key = request.trans_id.to_string();
                if self.emitted.contains(&key) {
                    return;
                }
                let group = self.groups.entry(key).or_default();
                group.observe(request.start_ns, request.end_ns.max(request.start_ns));
                match group.request.as_mut() {
                    Some(existing) if group.measured_end.is_some() => {
                        existing.start_ns = request.start_ns;
                        existing.pid = request.pid;
                        existing.tid = request.tid;
                    }
                    _ => group.request = Some(request),
                }
                self.retry();
            }
            TraceEvent::RequestEnd(request) => {
                let key = request.trans_id.to_string();
                if self.emitted.contains(&key) {
                    return;
                }
                let group = self.groups.entry(key).or_default();
                group.observe(request.start_ns, request.end_ns.max(request.start_ns));
                group.measured_end = Some(request.end_ns);
                match group.request.as_mut() {
                    Some(existing) => existing.end_ns = request.end_ns,
                    None => group.request = Some(request),
                }
                self.retry();
            }
            TraceEvent::RadosOp(rados) => {
                if rados.trans_id.is_empty() {
                    match self.infer(&rados) {
                        Ok(key) => self.correlate(key, rados),
                        Err(_) => self.pending.push(rados),
                    }
                } else if self.emitted.contains(&*rados.trans_id) {
                    self.background(rados, "request_already_emitted");
                } else {
                    let key = rados.trans_id.to_string();
                    self.correlate(key, rados);
                }
            }
        }
    }

    /// The old drain, for a collector without the end probe and without a grace:
    /// every group is closed and expires on idleness.
    fn drain(&mut self, now: u64, ttl: u64) {
        let cutoff = now.saturating_sub(ttl);
        self.retry();
        let mut remaining = Vec::new();
        for rados in std::mem::take(&mut self.pending) {
            if rados.finish_ns.max(rados.sent_ns) <= cutoff {
                self.finalize(rados);
            } else {
                remaining.push(rados);
            }
        }
        self.pending = remaining;
        let expired: Vec<String> = self
            .groups
            .iter()
            .filter(|(_, group)| group.last_seen != 0 && group.last_seen <= cutoff)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            let group = self.groups.remove(&key).unwrap();
            self.emit(key, group);
        }
    }

    fn emit(&mut self, key: String, group: RefGroup) {
        if !group.children.is_empty() {
            self.outcome.children.insert(key.clone(), group.children);
        }
        self.emitted.insert(key);
    }

    fn finish(mut self) -> Outcome {
        self.retry();
        for rados in std::mem::take(&mut self.pending) {
            self.finalize(rados);
        }
        for (key, group) in std::mem::take(&mut self.groups) {
            self.emit(key, group);
        }
        self.outcome
    }
}

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

enum Step {
    Event(TraceEvent),
    Drain(u64),
}

/// A random but plausible stream: overlapping requests on a few threads (some
/// START-only, some END-before-START, some re-STARTed on another thread),
/// tagged children, untagged ops near them, and periodic drains.
fn random_stream(rng: &mut Rng, len: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut now = 1_000u64;
    let mut open: Vec<(String, u32, u64)> = Vec::new();
    let mut next_request = 0;
    let mut next_op = 0;
    for _ in 0..len {
        now += rng.below(40);
        match rng.below(10) {
            0..=1 => {
                let id = format!("tx{next_request}");
                next_request += 1;
                let tid = 1 + rng.below(4) as u32;
                if rng.below(8) == 0 {
                    // END without a START (a dropped START).
                    steps.push(Step::Event(end(&id, tid, now, now + rng.below(300))));
                } else {
                    steps.push(Step::Event(start(&id, tid, now)));
                    open.push((id, tid, now));
                }
            }
            2..=3 if !open.is_empty() => {
                let (id, tid, at) = open.swap_remove(rng.below(open.len() as u64) as usize);
                let tid = if rng.below(10) == 0 { tid + 1 } else { tid };
                steps.push(Step::Event(end(&id, tid, at, now)));
                if rng.below(10) == 0 {
                    // A duplicate/late START after the END (out-of-order delivery).
                    steps.push(Step::Event(start(&id, tid, at + rng.below(20))));
                }
            }
            4 if !open.is_empty() => {
                let (id, _, _) = &open[rng.below(open.len() as u64) as usize];
                let sent = now.saturating_sub(rng.below(50));
                steps.push(Step::Event(tagged(
                    &format!("op{next_op}"),
                    id,
                    sent,
                    sent + rng.below(60),
                )));
                next_op += 1;
            }
            5..=8 => {
                let sent = now.saturating_sub(rng.below(400));
                let mut finish = sent + rng.below(80);
                if rng.below(20) == 0 {
                    finish = sent.saturating_sub(5); // inverted stamps
                }
                steps.push(Step::Event(untagged(
                    &format!("op{next_op}"),
                    rng.below(5) as u32,
                    sent,
                    finish,
                )));
                next_op += 1;
            }
            _ => {
                if rng.below(4) == 0 {
                    steps.push(Step::Drain(now));
                }
            }
        }
    }
    steps
}

#[test]
fn indexed_inference_matches_the_exhaustive_reference() {
    const TTL: u64 = 500;
    let mut inferred_total = 0;
    for seed in 1..=300u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let window = [0, 5, 50, 200][rng.below(4) as usize];
        let steps = random_stream(&mut rng, 250);

        let mut reference = Reference::new(window);
        let mut collector = Collector::with_inferred_correlation(window);
        let mut documents = Vec::new();
        for step in steps {
            match step {
                Step::Event(event) => {
                    reference.push(event.clone());
                    collector.push(event);
                }
                Step::Drain(now) => {
                    reference.drain(now, TTL);
                    documents.extend(collector.drain_expired("rgwtrace", now, TTL));
                }
            }
        }
        let final_document = collector.into_trace_document("rgwtrace");
        inferred_total += final_document.diagnostics.inferred_correlations;
        documents.push(final_document);

        assert_eq!(
            outcome(&documents),
            reference.finish(),
            "seed {seed} (window {window}): indexed inference diverged from the exhaustive reference"
        );
    }
    // The streams must actually exercise inference, or the test proves nothing.
    assert!(inferred_total > 1_000, "only {inferred_total} inferred ops");
}

// --- targeted inference transitions (each a path the index must not miss) ---

fn parent_of(document: &TraceDocument, object: &str) -> Option<String> {
    outcome(std::slice::from_ref(document))
        .children
        .into_iter()
        .find(|(_, children)| children.iter().any(|child| child == object))
        .map(|(parent, _)| parent)
}

#[test]
fn a_pending_no_candidate_op_is_inferred_when_its_request_appears() {
    let mut collector = Collector::with_inferred_correlation(10);
    collector.push(untagged("orphan", 0, 100, 110));
    collector.push(start("tx1", 1, 90));
    collector.push(end("tx1", 1, 90, 120));
    let document = collector.into_trace_document("rgwtrace");
    assert_eq!(parent_of(&document, "orphan").as_deref(), Some("tx1"));
}

#[test]
fn an_ambiguous_op_is_inferred_once_a_recorded_candidate_drops_out() {
    // tx-a and tx-b both overlap the op; tx-b's END then shrinks it away from
    // the op, leaving tx-a unique. That decision is only reachable through the
    // witness index.
    let mut collector = Collector::with_inferred_correlation(0);
    collector.push(start("tx-a", 1, 50));
    collector.push(end("tx-a", 1, 50, 200));
    collector.push(start("tx-b", 2, 60)); // START-only: interval [0, 60]
    collector.push(untagged("op", 0, 55, 58));
    collector.push(end("tx-b", 2, 60, 300)); // now [60, 300]: no longer overlaps
    let document = collector.into_trace_document("rgwtrace");
    assert_eq!(parent_of(&document, "op").as_deref(), Some("tx-a"));
    assert_eq!(document.diagnostics.inferred_correlations, 1);
}

#[test]
fn an_ambiguous_op_is_inferred_when_a_same_thread_candidate_appears() {
    let mut collector = Collector::with_inferred_correlation(0);
    push(&mut collector, "tx-a", 1, 10, 100);
    push(&mut collector, "tx-b", 2, 10, 100);
    collector.push(untagged("op", 3, 40, 50));
    // Ambiguous on the pid, nothing on thread 3 -- until this request.
    push(&mut collector, "tx-c", 3, 30, 90);
    let document = collector.into_trace_document("rgwtrace");
    assert_eq!(parent_of(&document, "op").as_deref(), Some("tx-c"));
}

#[test]
fn an_expired_witness_is_retried_at_the_next_marker_exactly_as_before() {
    let mut collector = Collector::with_inferred_correlation(0);
    push(&mut collector, "tx-old", 1, 10, 100);
    push(&mut collector, "tx-new", 2, 50, 1_000);
    collector.push(untagged("op", 0, 90, 150)); // overlaps both
                                                // tx-old (last seen 100) expires; the op (time 150) and tx-new stay.
    let drained = collector.drain_expired("rgwtrace", 120 + 100, 120).unwrap();
    assert_eq!(drained.diagnostics.expired_request_groups, 1);
    // The next marker -- any marker, here one in another process -- re-decides
    // the op: tx-new is now its only candidate.
    collector.push(TraceEvent::RequestStart(marker(
        "tx-unrelated",
        99,
        3,
        5_000,
        0,
    )));
    let document = collector.into_trace_document("rgwtrace");
    assert_eq!(parent_of(&document, "op").as_deref(), Some("tx-new"));
}

fn push(collector: &mut Collector, trans_id: &str, tid: u32, start_ns: u64, end_ns: u64) {
    collector.push(start(trans_id, tid, start_ns));
    collector.push(end(trans_id, tid, start_ns, end_ns));
}

#[test]
fn a_marker_does_not_revisit_pending_ops_it_cannot_affect() {
    // 1000 ops ambiguous between two same-thread candidates; a new request on
    // another thread cannot change any of them, so nothing becomes dirty.
    let mut collector = Collector::with_inferred_correlation(1_000);
    push(&mut collector, "tx-a", 1, 0, 10_000);
    push(&mut collector, "tx-b", 1, 0, 10_000);
    for i in 0..1_000 {
        collector.push(untagged(&format!("op{i}"), 1, 100 + i, 200 + i));
    }
    collector.push(start("tx-c", 2, 5_000));
    let inference = collector.inference.as_ref().unwrap();
    assert_eq!(inference.pending.len(), 1_000);
    assert!(
        inference.dirty.is_empty(),
        "an addition that cannot rescue an AmbiguousTid op must not dirty it"
    );
}

#[test]
fn the_pending_queue_is_capped_and_overflow_is_counted() {
    let mut collector = Collector::with_inferred_correlation(1_000);
    collector.set_inference_max_pending(3);
    push(&mut collector, "tx-a", 1, 0, 10_000);
    push(&mut collector, "tx-b", 2, 0, 10_000);
    for i in 0..5 {
        collector.push(untagged(&format!("op{i}"), 0, 100 + i, 200 + i));
    }
    assert_eq!(collector.inference.as_ref().unwrap().pending.len(), 3);
    assert_eq!(
        collector.diagnostics.inference_pending_overflow_rados_ops,
        2
    );
    let document = collector.into_trace_document("rgwtrace");
    let outcome = outcome(std::slice::from_ref(&document));
    // The two OLDEST were decided early, as ambiguous background ops.
    assert_eq!(
        outcome.background.get("op0").map(String::as_str),
        Some("ambiguous_inference_candidates")
    );
    assert_eq!(
        outcome.background.get("op1").map(String::as_str),
        Some("ambiguous_inference_candidates")
    );
    assert_eq!(document.diagnostics.inference_pending_overflow_rados_ops, 2);
    assert_eq!(document.diagnostics.inference_ambiguous_rados_ops, 5);
}

#[test]
fn an_overflowing_op_that_has_become_unique_is_still_inferred() {
    // Overflow decides early, against the current candidates: an op whose
    // candidate set has narrowed to one is inferred, not discarded.
    let mut collector = Collector::with_inferred_correlation(0);
    collector.set_inference_max_pending(1);
    collector.push(start("tx-a", 1, 10)); // [0, 10]
    collector.push(start("tx-b", 2, 20)); // [0, 20]
    collector.push(untagged("op0", 0, 5, 8)); // ambiguous a/b
    collector.push(end("tx-b", 2, 20, 30)); // b -> [20, 30]: op0 now unique on a ...
                                            // ... and was already re-decided by that marker.
    let document = collector.into_trace_document("rgwtrace");
    assert_eq!(parent_of(&document, "op0").as_deref(), Some("tx-a"));
}

// --- expiry index ---------------------------------------------------------

#[test]
fn a_drain_visits_only_expired_groups() {
    let mut collector = Collector::default();
    for i in 0..10_000u64 {
        let id = format!("tx{i}");
        collector.push(tagged(&format!("op{i}"), &id, 1_000 + i, 1_001 + i));
    }
    let before = collector.expiry.visited;
    let drained = collector
        .drain_expired_batch(1_000 + 3 + 500, 500)
        .expect("three groups are expired");
    // tx0..tx2 have last_seen 1001..1003 <= cutoff 1003.
    assert_eq!(drained.span_count(), 6);
    let visited = collector.expiry.visited - before;
    assert_eq!(
        visited, 3,
        "a drain must visit exactly the expired entries, not the 9,997 live ones"
    );
    assert_eq!(collector.requests.len(), 9_997);
}

#[test]
fn a_detached_batch_renders_exactly_what_an_in_place_drain_does() {
    fn build() -> Collector {
        let mut collector = Collector::default();
        collector.push(start("tx-b", 7, 10));
        collector.push(tagged("b0", "tx-b", 12, 20));
        collector.push(TraceEvent::RadosOp(op("b1", "tx-b", PID, 9, 13, 25)));
        collector.push(end("tx-b", 7, 10, 30));
        collector.push(tagged("a0", "tx-a", 5, 15)); // rados_bounds group
        collector.push(untagged("notify.0", 0, 7, 8));
        collector.push(untagged("late", 0, 9_000, 9_001)); // not expired
        collector
    }
    let mut in_place = build();
    let document = in_place.drain_expired("rgwtrace", 600, 500).unwrap();
    let mut detached = build();
    let batch = detached.drain_expired_batch(600, 500).unwrap();
    assert_eq!(batch.span_count(), document.spans.len());
    let rendered = batch.into_trace_document("rgwtrace");
    assert_eq!(
        serde_json::to_string(&rendered).unwrap(),
        serde_json::to_string(&document).unwrap()
    );
    // Diagnostics were tallied at detach time, under the lock.
    assert_eq!(rendered.diagnostics.same_thread_correlations, 2);
    assert_eq!(rendered.diagnostics.cross_thread_correlations, 1);
    assert_eq!(rendered.diagnostics.measured_duration_requests, 1);
    assert_eq!(rendered.diagnostics.derived_duration_requests, 1);
    assert_eq!(rendered.diagnostics.spans_produced, 6);
    // And the remainder is unaffected.
    assert_eq!(
        serde_json::to_string(&in_place.into_trace_document("rgwtrace")).unwrap(),
        serde_json::to_string(&detached.into_trace_document("rgwtrace")).unwrap()
    );
}

#[test]
fn drained_and_whole_run_documents_contain_the_same_spans() {
    // Draining in steps must partition exactly the spans a single end-of-run
    // document would contain: nothing lost, nothing duplicated.
    fn events() -> Vec<TraceEvent> {
        let mut events = Vec::new();
        for i in 0..50u64 {
            let id = format!("tx{i}");
            let at = i * 100;
            events.push(start(&id, 1 + (i % 3) as u32, at));
            events.push(tagged(&format!("op{i}"), &id, at + 1, at + 9));
            events.push(end(&id, 1, at, at + 10));
            events.push(untagged(&format!("bg{i}"), 0, at + 50, at + 51));
        }
        events
    }
    let mut whole = Collector::default();
    let mut stepped = Collector::default();
    let mut stepped_spans = Vec::new();
    for (index, event) in events().into_iter().enumerate() {
        whole.push(event.clone());
        stepped.push(event);
        if index % 17 == 0 {
            let now = (index as u64 / 4) * 100;
            if let Some(document) = stepped.drain_expired("rgwtrace", now, 300) {
                stepped_spans.extend(document.spans);
            }
        }
    }
    stepped_spans.extend(stepped.into_trace_document("rgwtrace").spans);
    let mut whole_ids: Vec<String> = whole
        .into_trace_document("rgwtrace")
        .spans
        .into_iter()
        .map(|span| serde_json::to_string(&span).unwrap())
        .collect();
    let mut stepped_ids: Vec<String> = stepped_spans
        .into_iter()
        .map(|span| serde_json::to_string(&span).unwrap())
        .collect();
    whole_ids.sort();
    stepped_ids.sort();
    assert_eq!(whole_ids, stepped_ids);
}

// --- closed-request grace ---------------------------------------------------

fn graced_collector() -> Collector {
    let mut collector = Collector::default();
    collector.set_end_probe_attached(true);
    collector.set_closed_request_grace(50);
    collector
}

#[test]
fn an_ended_request_is_exported_after_the_grace_not_the_ttl() {
    let mut collector = graced_collector();
    push(&mut collector, "tx1", 1, 100, 200);
    assert!(collector.drain_expired("rgwtrace", 249, 10_000).is_none());
    let document = collector.drain_expired("rgwtrace", 250, 10_000).unwrap();
    assert_eq!(document.diagnostics.expired_request_groups, 1);
    assert!(collector.requests.is_empty());
}

#[test]
fn ops_landing_inside_the_grace_are_still_correlated() {
    // Coverage regression: a RADOS completion that lands after the destructor
    // but inside the grace must still join its request -- as it did when the
    // group lived for the whole TTL.
    let mut collector = graced_collector();
    collector.push(start("tx1", 1, 100));
    collector.push(tagged("before-end", "tx1", 110, 150));
    collector.push(end("tx1", 1, 100, 200));
    collector.push(tagged("after-end", "tx1", 190, 230)); // completes 30 after END
                                                          // 260 is within the grace of the op's activity (230 + 50 = 280).
    assert!(collector.drain_expired("rgwtrace", 260, 10_000).is_none());
    let document = collector.drain_expired("rgwtrace", 280, 10_000).unwrap();
    let outcome = outcome(std::slice::from_ref(&document));
    assert_eq!(
        outcome.children.get("tx1"),
        Some(&vec!["before-end".to_string(), "after-end".to_string()])
    );
    assert_eq!(document.diagnostics.correlated_rados_ops, 2);
}

#[test]
fn a_straggler_after_the_grace_becomes_background_never_a_second_span() {
    let mut collector = graced_collector();
    push(&mut collector, "tx1", 1, 100, 200);
    let first = collector.drain_expired("rgwtrace", 300, 10_000).unwrap();
    assert_eq!(first.spans.len(), 1);
    collector.push(tagged("straggler", "tx1", 290, 400));
    collector.push(end("tx1", 1, 100, 200)); // duplicate END: dropped
    let rest = collector.into_trace_document("rgwtrace");
    assert!(rest.spans.iter().all(|span| span.name != "rgw.request"));
    assert_eq!(
        outcome(std::slice::from_ref(&rest))
            .background
            .get("straggler")
            .map(String::as_str),
        Some("request_already_emitted")
    );
    assert_eq!(rest.diagnostics.late_request_markers_dropped, 1);
}

#[test]
fn the_grace_never_exceeds_the_ttl_and_open_requests_ignore_it() {
    let mut collector = graced_collector();
    collector.set_closed_request_grace(1_000_000);
    push(&mut collector, "tx-ended", 1, 100, 200);
    collector.push(start("tx-open", 2, 100));
    // TTL 100 caps the grace: tx-ended goes at 300. tx-open (END expected)
    // stays until the lifetime backstop (10 x TTL from its start).
    let document = collector.drain_expired("rgwtrace", 300, 100).unwrap();
    assert_eq!(document.diagnostics.expired_request_groups, 1);
    assert!(collector.requests.contains_key("tx-open"));
    let document = collector.drain_expired("rgwtrace", 1_100, 100).unwrap();
    assert_eq!(document.diagnostics.expired_open_requests, 1);
}

#[test]
fn without_a_grace_ended_requests_keep_the_idle_ttl() {
    let mut collector = Collector::default();
    collector.set_end_probe_attached(true);
    push(&mut collector, "tx1", 1, 100, 200);
    assert!(collector.drain_expired("rgwtrace", 1_000, 1_000).is_none());
    assert!(collector.drain_expired("rgwtrace", 1_200, 1_000).is_some());
}

#[test]
fn under_inference_the_grace_is_at_least_the_window() {
    let mut collector = Collector::with_inferred_correlation(500);
    collector.set_closed_request_grace(50);
    push(&mut collector, "tx1", 1, 100, 200);
    assert!(collector.drain_expired("rgwtrace", 600, 10_000).is_none());
    assert!(collector.drain_expired("rgwtrace", 700, 10_000).is_some());
}

#[test]
fn a_request_still_witnessing_a_pending_inference_keeps_the_full_ttl() {
    // Expiring tx-a at the grace would leave the op with tx-b as its only
    // candidate and infer it there on the strength of an expiry. It must keep
    // the old TTL behavior instead.
    let mut collector = Collector::with_inferred_correlation(10);
    collector.set_end_probe_attached(true);
    collector.set_closed_request_grace(20);
    push(&mut collector, "tx-a", 1, 100, 200);
    push(&mut collector, "tx-b", 2, 100, 5_000);
    collector.push(untagged("op", 0, 150, 160));
    assert!(collector.drain_expired("rgwtrace", 1_000, 10_000).is_none());
    assert!(collector.requests.contains_key("tx-a"));
    let document = collector.into_trace_document("rgwtrace");
    assert_eq!(
        outcome(std::slice::from_ref(&document))
            .background
            .get("op")
            .map(String::as_str),
        Some("ambiguous_inference_candidates")
    );
}
