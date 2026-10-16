//! Rendering of the `{dwarf, trace}` document for `--output json` and
//! `--output jsonl`.
//!
//! Both are written STRAIGHT to the sink. The previous code built a full
//! `serde_json::Value` copy of the trace and then a pretty `String` of it before
//! printing, so the end of a long `--output json` session held the trace three
//! times over at its peak. Here only one span is materialized as a `Value` at a
//! time.
//!
//! The output is byte-for-byte what the old `Value` path printed. That path
//! serialized through `serde_json::Value`, whose objects (without serde_json's
//! `preserve_order` feature, which this crate does not enable) are `BTreeMap`s,
//! so every object's keys came out SORTED rather than in struct declaration
//! order. To keep that, the two outer objects are written by hand in sorted key
//! order and every nested value still goes through `Value`, one span at a time.
//! `json_output_is_byte_identical_to_the_legacy_value_rendering` pins it.

use std::io::Write;

use anyhow::{Context, Result};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use crate::{
    collector::{SpanDocument, TraceDocument},
    dwarf_json::DwarfSummary,
};

/// Write the whole session as ONE pretty-printed `{dwarf, trace}` document (the
/// `--output json` format), followed by a newline, and flush.
pub fn write_json_document(
    out: impl Write,
    dwarf: &DwarfSummary,
    trace: &TraceDocument,
) -> Result<()> {
    let mut out = std::io::BufWriter::new(out);
    serde_json::to_writer_pretty(&mut out, &OutputDocument { dwarf, trace })
        .context("failed to write the JSON trace document")?;
    writeln!(out).context("failed to write the JSON trace document")?;
    out.flush()
        .context("failed to flush the JSON trace document")
}

/// Write one drained batch as a single compact `{dwarf, trace}` line (the
/// `--output jsonl` format) and flush, so a consumer sees each drain as soon as
/// it happens and a crash loses at most the batch being written.
///
/// Each line is a self-contained document: `trace.spans` holds that drain's
/// spans and `trace.diagnostics` the CUMULATIVE counters at that moment (with
/// `spans_produced` counting the line's own spans). The run's final totals are
/// therefore on the LAST line, which is always written, even when it carries no
/// spans.
pub fn write_jsonl_document(
    out: &mut impl Write,
    dwarf: &DwarfSummary,
    trace: &TraceDocument,
) -> Result<()> {
    serde_json::to_writer(&mut *out, &OutputDocument { dwarf, trace })
        .context("failed to write a JSONL trace line")?;
    out.write_all(b"\n")
        .context("failed to write a JSONL trace line")?;
    out.flush().context("failed to flush a JSONL trace line")
}

/// `{"dwarf": ..., "trace": ...}`, keys in sorted order.
struct OutputDocument<'a> {
    dwarf: &'a DwarfSummary,
    trace: &'a TraceDocument,
}

impl Serialize for OutputDocument<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("dwarf", &as_value(self.dwarf)?)?;
        map.serialize_entry("trace", &SortedTrace(self.trace))?;
        map.end()
    }
}

/// A `TraceDocument` with its keys sorted: `diagnostics`, `service_name`,
/// `spans`.
struct SortedTrace<'a>(&'a TraceDocument);

impl Serialize for SortedTrace<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("diagnostics", &as_value(&self.0.diagnostics)?)?;
        map.serialize_entry("service_name", &self.0.service_name)?;
        map.serialize_entry("spans", &SortedSpans(&self.0.spans))?;
        map.end()
    }
}

/// The span list, each span converted to a sorted-key `Value` only while it is
/// being written.
struct SortedSpans<'a>(&'a [SpanDocument]);

impl Serialize for SortedSpans<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for span in self.0 {
            seq.serialize_element(&as_value(span)?)?;
        }
        seq.end()
    }
}

fn as_value<T: Serialize, E: serde::ser::Error>(value: &T) -> Result<serde_json::Value, E> {
    serde_json::to_value(value).map_err(E::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{Collector, TraceDocument};
    use crate::dwarf_json::DwarfInfo;
    use crate::events::{
        CaptureTruncation, RadosDirection, RadosEvent, RadosOp, RequestEvent, TraceEvent,
    };

    /// The rendering every `--output json` run printed before this module: the
    /// whole document as a `Value`, then a pretty `String`, then `println!`.
    fn legacy_json_rendering(dwarf: &DwarfInfo, trace: &TraceDocument) -> String {
        let document = serde_json::json!({
            "dwarf": dwarf.summary(),
            "trace": trace,
        });
        format!("{}\n", serde_json::to_string_pretty(&document).unwrap())
    }

    fn request(trans_id: &str, start_ns: u64, end_ns: u64) -> RequestEvent {
        RequestEvent {
            start_ns,
            end_ns,
            pid: 42,
            tid: 7,
            trans_id: trans_id.into(),
            truncation: CaptureTruncation::default(),
        }
    }

    fn rados(object_name: &str, trans_id: &str, sent_ns: u64) -> RadosEvent {
        RadosEvent {
            pid: 42,
            send_tid: 7,
            cid: 1,
            tid: 2,
            sent_ns,
            finish_ns: sent_ns + 10,
            duration_ns: 10,
            pool: 16,
            target_osd: 7,
            pg_seed: 0x2a,
            acting: vec![1, 2, 3],
            rw: RadosDirection::Write,
            object_name: object_name.to_string(),
            trans_id: trans_id.into(),
            truncation: CaptureTruncation::default(),
            ops: vec![RadosOp {
                code: 0x1401,
                name: "call".into(),
                class: Some("cls".to_string()),
                method: Some("method".to_string()),
            }],
            offset: 128,
            length: 4096,
        }
    }

    /// A trace with every span shape: a request, its child, and a background op
    /// (which carries a span event), plus a populated counter map.
    fn populated_trace() -> TraceDocument {
        let mut collector = Collector::default();
        collector.push(TraceEvent::RequestStart(request("tx-a", 100, 0)));
        collector.push(TraceEvent::RadosOp(rados("obj", "tx-a", 120)));
        collector.push(TraceEvent::RequestEnd(request("tx-a", 100, 250)));
        collector.push(TraceEvent::RadosOp(rados("notify.0", "", 300)));
        collector.into_trace_document("rgwtrace")
    }

    fn dwarf() -> DwarfInfo {
        DwarfInfo {
            version: Some("19.2.3-test".to_string()),
            arch: Some("amd64".to_string()),
            ..DwarfInfo::default()
        }
    }

    #[test]
    fn json_output_is_byte_identical_to_the_legacy_value_rendering() {
        // `--output json` consumers (the e2e verifier, golden comparisons, ad-hoc
        // diffing of two runs) must see the same bytes as before, for populated
        // and for empty traces.
        for trace in [
            populated_trace(),
            Collector::default().into_trace_document("x"),
        ] {
            let mut out = Vec::new();
            write_json_document(&mut out, &dwarf().summary(), &trace).unwrap();
            assert_eq!(
                String::from_utf8(out).unwrap(),
                legacy_json_rendering(&dwarf(), &trace)
            );
        }
    }

    #[test]
    fn jsonl_writes_one_self_contained_document_per_line() {
        let summary = dwarf().summary();
        let mut out = Vec::new();
        let trace = populated_trace();
        write_jsonl_document(&mut out, &summary, &trace).unwrap();
        write_jsonl_document(
            &mut out,
            &summary,
            &Collector::default().into_trace_document("rgwtrace"),
        )
        .unwrap();

        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one line per document: {text}");
        assert!(text.ends_with('\n'));
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(
            first,
            serde_json::json!({ "dwarf": dwarf().summary(), "trace": &trace }),
            "a line is the same {{dwarf, trace}} document as --output json"
        );
        let last: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(last["trace"]["spans"].as_array().unwrap().len(), 0);
        assert_eq!(last["dwarf"]["version"], "19.2.3-test");
    }
}
