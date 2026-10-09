#!/usr/bin/env python3
import argparse
from copy import deepcopy
import json
import sys
from types import SimpleNamespace


SPAN_NAMES = {"rgw.request", "rados.op", "rgw.background.rados_op"}
# Two-marker model. A consumer must be able to tell a REAL request duration from
# a reconstructed one:
#   measured           -- the req_state::~req_state END probe fired and BOTH span
#                         bounds are the request's real ones (start == the
#                         get_handler marker, end == the destructor).
#   measured_extended  -- the END probe fired, but a span bound had to be
#                         stretched off its measured value to envelope a child:
#                         the end pushed out past a late child, or the START
#                         pulled BACK to a child that began before the marker.
#                         rgw.request.measured_{start,end}_ns keep the truth.
#   marker             -- no END marker (probe not attached on this build); the
#                         end is DERIVED from the RADOS child bounds. The start is
#                         still measured (get_handler).
#   rados_bounds       -- no request marker at all; whole span from RADOS bounds,
#                         so NEITHER bound is measured.
# There is still no request_lifecycle value: a return probe crashes RGW.
MEASURED_DURATION_QUALITIES = {"measured", "measured_extended"}
DERIVED_DURATION_QUALITIES = {"marker", "rados_bounds"}
VALID_DURATION_QUALITIES = MEASURED_DURATION_QUALITIES | DERIVED_DURATION_QUALITIES
# The cls_rgw bucket-index list call, as rendered into `ceph.rados.ops`
# ("call(rgw.bucket_list)"). RGW issues ONE per bucket-index shard.
BUCKET_LIST_OP = "rgw.bucket_list"
# How many bucket_list ops a run must observe before the list-shard gate is
# enforced. >= 2 is the observable definition of "the bucket is sharded": a
# single-shard bucket (or a listing that never reached the index) cannot show it,
# and the gate stays inert rather than failing for the wrong reason.
MIN_LIST_SHARDS = 2
VALID_RADOS_ROLES = {
    "data",
    "bucket_index",
    "bucket_meta",
    "user_meta",
    "auth_meta",
    "gc",
    "notify",
    "sync",
    "config",
    "unknown",
}
# Correlated rados.op child spans carry one of these rgw.correlation values.
# "cross_thread" is the late-derived, opt-in re-seed-bridge correlation
# (best-effort, build-dependent) added in the cross-thread stage.
VALID_CHILD_CORRELATIONS = {"same_thread", "cross_thread", "inferred"}
VALID_BACKGROUND_REASONS = {
    "missing_trans_id",
    "classified_background_role",
    "no_inference_candidate",
    "ambiguous_inference_candidates",
    # A trans_id-carrying op whose request span had already been exported. It is
    # kept as background rather than re-grouped, because re-grouping would emit a
    # SECOND request span with the same span id.
    "request_already_emitted",
    # A trans_id-carrying op for a request the collector does not hold and that
    # started before the no-duplicate tombstone's horizon (its key may have been
    # rotated out), so it cannot be proven new. Kept as background for the same
    # reason as request_already_emitted.
    "request_outside_tombstone_horizon",
}
BPF_FAILURE_DIAGNOSTICS = [
    "bpf_ringbuf_request_drops",
    "bpf_ringbuf_rados_drops",
    "bpf_rados_map_drops",
    "bpf_request_context_drops",
    "bpf_probe_read_failures",
    "bpf_reqstate_map_drops",
]
# Cross-thread re-seed bridge coverage counters (--correlate-cross-thread).
# These are informational, NOT failures: hits are the wins, and misses/base
# unresolved are the fail-closed/degraded cases the design expects. They must
# never be asserted to be zero -- only checked to be valid non-negative counts.
BPF_INFORMATIONAL_DIAGNOSTICS = [
    "bpf_reseed_hits",
    "bpf_reseed_misses",
    "bpf_reseed_base_unresolved",
    # Request-END probe (req_state::~req_state) coverage. Hits are measured
    # request ends; misses are requests whose get_handler was never seen (started
    # before the trace window) and which therefore fall back to a derived end.
    # Neither is a failure, so they are never asserted to be zero.
    "bpf_request_end_hits",
    "bpf_request_end_misses",
    "bpf_request_end_base_unresolved",
    # _send_op request-context liveness gate. `stale_ctx_drops` are ops NOT
    # stamped because the context left on the submitting thread belonged to a
    # request that already ended -- fail-closed drops (uncorrelated, never
    # mis-correlated), expected to be nonzero whenever context is re-seeded across
    # threads. `unverifiable_ctx` are ops stamped without a liveness proof, which
    # is the whole population on a build with no END probe.
    "bpf_sendop_stale_ctx_drops",
    "bpf_sendop_unverifiable_ctx",
    # PHASE B: the per-submit re-seed at rgw_rados_operate. `seed_hits` is the
    # win condition -- RADOS submits that had their request's context
    # re-established on the (possibly migrated) submitting thread. `seed_misses`
    # are operates carrying a dpp that is NOT a traced request's req_state
    # (bucket/zone/wrapper dpps, and every background GC/LC/quota thread). Misses
    # are the EXPECTED fail-closed steady state on a busy gateway, not failures
    # and not lost ops, so they are never asserted to be zero.
    "bpf_operate_seed_hits",
    "bpf_operate_seed_misses",
    "bpf_operate_base_unresolved",
    # WHICH KEY the per-submit seed hit on. This split is what decides whether the
    # `RGWOp*` alternate key -- and the S3-website-retarget mis-correlation hazard
    # it carries -- earns its place. `reqstate` healthy + `rgwop` ~0 means the key
    # buys nothing and should be disabled (--disable-rgw-op-bridge-key).
    "bpf_operate_seed_hits_reqstate",
    "bpf_operate_seed_hits_rgwop",
    # The fail-closed clears. `miss_ctx_cleared` is a resolved-but-foreign dpp;
    # `unresolved_ctx_cleared` is a dpp we could not resolve at all (null argument,
    # or a descriptor that is not register-resident). Both drop the thread's SEEDED
    # context (a copy Phase B migrated here) rather than let it stamp an op it cannot
    # be proven to own.
    "bpf_operate_miss_ctx_cleared",
    "bpf_operate_unresolved_ctx_cleared",
    # ...and the other half of that decision: the unproven submit found a HOME
    # context (`ctx.tid == this tid`: get_handler put it here for the request that
    # STARTED on this thread) and PRESERVED it. Phase B did not create it and does not
    # get to destroy it -- an unscoped clear cost a live ListObjects request all 16 of
    # its `rgw.bucket_list` shard ops, which are submitted through the cls_rgw AIO path
    # and never pass through rgw_rados_operate.
    "bpf_operate_miss_home_ctx_preserved",
    "bpf_operate_unresolved_home_ctx_preserved",
    "bpf_sendop_unbridged_ctx_drops",
    # MULTI-KEY bridge revocation accounting. The identity that must hold:
    #   inserts == revokes + revoke_skipped + revoke_absent + in-flight requests
    "bpf_rgw_op_key_inserts",
    "bpf_rgw_op_key_revokes",
    "bpf_rgw_op_key_revoke_skipped",
    "bpf_rgw_op_key_revoke_absent",
    "bpf_rgw_op_key_unresolved",
    "bpf_rgw_op_key_disabled",
]
# Counters that are informational in general but MUST be zero on a healthy run
# because a nonzero value invalidates something we rely on.
BPF_INVARIANT_DIAGNOSTICS = [
    # A seed hit must be attributable to exactly one of the request's own keys (the
    # dpp is compared against the bridged value's own req_state_ptr/rgw_op_ptr).
    # Nonzero means the reqstate-vs-rgwop split -- the number the RGWOp key's fate
    # is decided on -- cannot be trusted.
    "bpf_operate_seed_hits_unattributed",
    # The alternate key's revocation record could not be created, so the key was
    # refused. Fail-closed and never wrong, but it means rgw_op_keys is full.
    "bpf_rgw_op_key_index_drops",
]
RADOS_ATTRIBUTE_KEYS = [
    "ceph.rados.duration_ns",
    # The submitting thread. Paired with the parent's rgw.request.tid this is the
    # direct evidence of an asio coroutine migration (send_tid != request tid).
    "ceph.rados.send_tid",
    "ceph.rados.pool",
    "ceph.rados.pg",
    "ceph.rados.pg_seed",
    "ceph.rados.target_osd",
    "ceph.rados.acting",
    "ceph.rados.object",
    "ceph.rados.ops",
    "ceph.rados.rw",
    "ceph.rados.offset",
    "ceph.rados.length",
    "rgw.rados_role",
    "rgw.correlation",
]


def parse_args():
    parser = argparse.ArgumentParser(description="Verify rgwtrace JSON from a live RGW e2e run")
    parser.add_argument("--trace")
    parser.add_argument("--workload")
    parser.add_argument(
        "--trace-format",
        choices=["auto", "json", "jsonl"],
        default="auto",
        help="json: one --output json document; jsonl: --output jsonl (one document "
        "per drain, merged before verification); auto: detect",
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--min-request-spans", type=int, default=1)
    parser.add_argument("--min-rados-spans", type=int, default=1)
    parser.add_argument("--expect-role", action="append", default=[])
    parser.add_argument(
        "--expect-any-role",
        action="append",
        default=[],
        help="comma-separated role alternatives; at least one must be present",
    )
    parser.add_argument("--time-slack-ms", type=int, default=2000)
    parser.add_argument(
        "--workload-manifest",
        default=None,
        help="s3-workload.py --manifest file; enables the object->request cross-check "
        "(always-on zero-mis-correlation) and the coverage-rate gates below",
    )
    parser.add_argument(
        "--require-get-read-correlation",
        type=float,
        default=None,
        metavar="RATE",
        help="fail if the fraction of manifest GET data ops with a correctly correlated "
        "read RADOS span is below RATE (requires --workload-manifest)",
    )
    parser.add_argument(
        "--require-put-write-correlation",
        type=float,
        default=None,
        metavar="RATE",
        help="fail if the fraction of manifest PUT data ops with a correctly correlated "
        "write RADOS span is below RATE (requires --workload-manifest)",
    )
    args = parser.parse_args()
    if (args.require_get_read_correlation is not None or args.require_put_write_correlation is not None) and not (
        args.workload_manifest or args.self_test
    ):
        parser.error("--require-*-correlation requires --workload-manifest")
    if not args.self_test and (not args.trace or not args.workload):
        parser.error("--trace and --workload are required unless --self-test is used")
    return args


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_trace(path, trace_format="auto"):
    """Load an --output json document, or an --output jsonl stream merged into one.

    auto: a file holding exactly one JSON value is json; otherwise every
    non-empty line must be a document and the file is jsonl.
    """
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if trace_format == "json":
        return json.loads(text), []
    if trace_format == "auto":
        try:
            return json.loads(text), []
        except json.JSONDecodeError:
            pass
    lines = [json.loads(line) for line in text.splitlines() if line.strip()]
    return merge_jsonl_documents(lines)


def merge_jsonl_documents(lines):
    """Fold the per-drain documents of an --output jsonl run into the single
    document --output json would have printed, plus any stream-level errors.

    Each line carries that drain's spans and the CUMULATIVE diagnostics at that
    moment, with spans_produced counting the line's own spans. So: spans are
    concatenated, diagnostics are the LAST line's (the run's final totals), and
    spans_produced is the sum. A span repeated across lines then fails the
    ordinary duplicate-span_id check -- which is exactly the "never emitted twice"
    invariant streaming must keep.
    """
    errors = []
    if not lines:
        return {"trace": {"spans": [], "diagnostics": {}}}, ["jsonl stream has no documents"]
    spans = []
    previous = {}
    for index, line in enumerate(lines, start=1):
        trace = line.get("trace", line)
        line_spans = trace.get("spans", [])
        diagnostics = trace.get("diagnostics", {})
        if diagnostics.get("spans_produced") != len(line_spans):
            errors.append(
                f"jsonl line {index}: spans_produced={diagnostics.get('spans_produced')} "
                f"but the line has {len(line_spans)} spans"
            )
        for key, value in diagnostics.items():
            # Cumulative counters never go backwards (spans_produced is per line).
            if key == "spans_produced" or not isinstance(value, int):
                continue
            if value < previous.get(key, 0):
                errors.append(f"jsonl line {index}: cumulative counter {key} went backwards")
        previous = diagnostics
        spans.extend(line_spans)
    final = lines[-1]
    trace = dict(final.get("trace", final))
    diagnostics = dict(trace.get("diagnostics", {}))
    diagnostics["spans_produced"] = len(spans)
    trace["spans"] = spans
    trace["diagnostics"] = diagnostics
    merged = dict(final) if "trace" in final else {}
    merged["trace"] = trace
    return merged, errors


def load_workload(path):
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_manifest(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        return list(data)
    if isinstance(data, dict):
        return list(data.get("operations", []))
    return []


def manifest_data_ops(manifest):
    """Successful data-path (GET/PUT) operations with a key and request id."""
    ops = []
    for record in manifest or []:
        if record.get("status", "ok") != "ok":
            continue
        if not record.get("key") or not record.get("x_amz_request_id"):
            continue
        if record.get("op") not in {"GET", "PUT"}:
            continue
        ops.append(record)
    return ops


def manifest_record_matches_span(record, span, span_attrs, slack_ns, match_rw=True):
    object_name = str(span_attrs.get("ceph.rados.object", ""))
    if record["key"] not in object_name:
        return False
    if not span_overlaps(span, record["start_ns"], record["end_ns"], slack_ns):
        return False
    if match_rw and record.get("rw") and span_attrs.get("ceph.rados.rw") != record.get("rw"):
        return False
    return True


def span_parent_trans_id(span, request_by_id):
    parent = request_by_id.get(span.get("parent_span_id"))
    if parent is None:
        return None
    return attr_map(parent).get("rgw.trans_id")


def attr_map(span):
    return {attribute["key"]: attribute.get("value") for attribute in span.get("attributes", [])}


def fail(errors, message):
    errors.append(message)


def span_overlaps(span, start_ns, end_ns, slack_ns):
    return span.get("end_ns", 0) >= start_ns - slack_ns and span.get("start_ns", 0) <= end_ns + slack_ns


def duplicate_values(values):
    seen = set()
    duplicates = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def is_hex_id(value, length):
    if not isinstance(value, str) or len(value) != length:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in value)


def is_uint(value):
    return type(value) is int and value >= 0


def sum_counter_map(value):
    if not isinstance(value, dict):
        return None
    if not all(is_uint(count) for count in value.values()):
        return None
    return sum(value.values())


def count_by(values):
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def validate_rados_attributes(errors, span, attrs, label):
    span_id = span.get("span_id")
    for key in RADOS_ATTRIBUTE_KEYS:
        if attrs.get(key) is None:
            fail(errors, f"{label} span {span_id} is missing {key}")

    role = attrs.get("rgw.rados_role")
    if role not in VALID_RADOS_ROLES:
        fail(errors, f"{label} span {span_id} has invalid rgw.rados_role={role!r}")

    duration = attrs.get("ceph.rados.duration_ns")
    if not is_uint(duration):
        fail(errors, f"{label} span {span_id} has invalid ceph.rados.duration_ns={duration!r}")
    elif is_uint(span.get("start_ns")) and is_uint(span.get("end_ns")):
        expected = span["end_ns"] - span["start_ns"]
        if duration != expected:
            fail(
                errors,
                f"{label} span {span_id} duration attribute {duration} does not match bounds {expected}",
            )

    pool = attrs.get("ceph.rados.pool")
    pg_seed = attrs.get("ceph.rados.pg_seed")
    pg = attrs.get("ceph.rados.pg")
    if is_uint(pool) and is_uint(pg_seed) and pg != f"{pool}.{pg_seed:x}":
        fail(errors, f"{label} span {span_id} has ceph.rados.pg={pg!r}, expected {pool}.{pg_seed:x}")

    if not attrs.get("ceph.rados.object"):
        fail(errors, f"{label} span {span_id} has empty ceph.rados.object")
    if not attrs.get("ceph.rados.ops"):
        fail(errors, f"{label} span {span_id} has empty ceph.rados.ops")


def validate_background_event(errors, span, span_attrs):
    span_id = span.get("span_id")
    events = span.get("events", [])
    if len(events) != 1:
        fail(errors, f"background span {span_id} must have exactly one rados.op event, got {len(events)}")
        return

    event = events[0]
    if event.get("name") != "rados.op":
        fail(errors, f"background span {span_id} event has name={event.get('name')!r}")
    if event.get("time_ns") != span.get("end_ns"):
        fail(errors, f"background span {span_id} event time_ns does not match span end_ns")

    event_attrs = attr_map(event)
    for key in [*RADOS_ATTRIBUTE_KEYS, "rgw.correlation_reason"]:
        if event_attrs.get(key) != span_attrs.get(key):
            fail(errors, f"background span {span_id} event attribute {key} does not match span attribute")


def check_object_request_correlation(args, errors, manifest, workload, rados_spans, background_spans, request_by_id, slack_ns):
    """Object<->request cross-check against the workload manifest.

    Returns a coverage summary. Two independent findings:
      * MIS-CORRELATION (always fails): a correlated rados.op child span for a
        workload object is attached to the WRONG request -- but only when that
        is *provable*. The manifest records EVERY workload operation (GET, PUT,
        and OTHER ops -- HEAD/COPY/DELETE/multipart -- each with a key and a
        request id), so the request a span is attached to can be looked up. A
        mis-correlation is provable only when that request is a GET/PUT (which by
        S3 semantics touches exactly one object, its own key) whose key does NOT
        match the span's object. Attachment to a request whose recorded key DOES
        match the object (e.g. a head_object/delete_object on the same key a
        GET/PUT also touched), or to an OTHER op whose key does not match (a
        copy_object legitimately reads its SOURCE object while its recorded key
        is the DESTINATION, and multipart touches part objects), cannot be proven
        wrong from the manifest key alone and is counted informationally. Spans
        attached to a request absent from the manifest fall back to the workload
        log to distinguish a real-but-unrecorded request from a foreign trans_id.
      * COVERAGE MISS (reported as a rate; only fails when a --require-* flag
        demands it): a workload data op has no correctly correlated child span
        (its data ops landed as background/inferred, or on a wrong request).
    """
    data_ops = manifest_data_ops(manifest)

    # The manifest records every operation (incl. OTHER ops with keys), so index
    # ALL records by request id to look up whatever operation a span was actually
    # attached to and judge whether that attachment is manifest-consistent.
    record_by_request_id = {
        record.get("x_amz_request_id"): record
        for record in (manifest or [])
        if record.get("x_amz_request_id")
    }
    # Every request id the workload issued, used only to classify attachments to
    # requests the manifest does not record: real workload request vs foreign id.
    workload_request_ids = {
        record.get("x_amz_request_id")
        for record in (workload or [])
        if record.get("x_amz_request_id")
    }

    counters = {
        "attributed_to_same_key_other_op": 0,
        "attributed_to_cross_key_other_op": 0,
        "attributed_to_unrecorded_request": 0,
        "attributed_to_foreign_request": 0,
    }

    # Always-on zero-mis-correlation check. Only decide when the workload object
    # maps to exactly one data op (key substring + rw + time window); ambiguous
    # matches are skipped rather than guessed.
    for span in rados_spans:
        span_attrs = attr_map(span)
        object_name = str(span_attrs.get("ceph.rados.object", ""))
        matches = [
            record
            for record in data_ops
            if manifest_record_matches_span(record, span, span_attrs, slack_ns)
        ]
        if not matches:
            continue
        # Substring collision: one object name can contain several manifest keys
        # (e.g. a copy object "..._copy-alpha-1.txt" contains both "alpha-1.txt"
        # and "copy-alpha-1.txt"). Only the LONGEST (most specific) matching key
        # sets the expectation; a shorter, generic key must not drive the check.
        longest = max(len(record["key"]) for record in matches)
        matches = [record for record in matches if len(record["key"]) == longest]
        if len(matches) != 1:
            continue
        expected = matches[0]["x_amz_request_id"]
        actual = span_parent_trans_id(span, request_by_id)
        if actual == expected:
            continue

        actual_record = record_by_request_id.get(actual)
        if actual_record is not None:
            actual_key = actual_record.get("key")
            if actual_key and actual_key in object_name:
                # The span is attached to a DIFFERENT manifest request, but that
                # request operates on the SAME object key (e.g. head_object or
                # delete_object on a key a GET/PUT also touched). Consistent with
                # the manifest -- not a mis-correlation.
                counters["attributed_to_same_key_other_op"] += 1
            elif actual_record.get("op") in {"GET", "PUT"}:
                # A GET/PUT touches exactly one object (its own key). Attached to
                # one whose key does not match the span's object -> provable
                # mis-correlation.
                fail(
                    errors,
                    f"MIS-CORRELATION: rados.op span {span.get('span_id')} for object "
                    f"{object_name!r} (workload key {matches[0]['key']!r}) attached to "
                    f"{actual_record.get('op')} request {actual!r} for a different key "
                    f"{actual_key!r}; expected {expected!r}",
                )
            else:
                # A multi/related-object OTHER op (copy_object reads its SOURCE
                # while its recorded key is the DESTINATION; multipart touches
                # part objects) whose recorded key does not match this object.
                # Cannot be proven wrong from the manifest key alone.
                counters["attributed_to_cross_key_other_op"] += 1
        elif actual in workload_request_ids:
            # Attached to a real workload request the manifest does not record.
            counters["attributed_to_unrecorded_request"] += 1
        else:
            # trans_id belongs to no workload request at all: still not a provable
            # manifest conflict, but surfaced separately for operator attention.
            counters["attributed_to_foreign_request"] += 1

    def op_correctly_correlated(record, rw):
        for span in rados_spans:
            span_attrs = attr_map(span)
            if span_attrs.get("ceph.rados.rw") != rw:
                continue
            if not manifest_record_matches_span(record, span, span_attrs, slack_ns):
                continue
            if span_parent_trans_id(span, request_by_id) == record["x_amz_request_id"]:
                return True
        return False

    def coverage(op, rw):
        records = [record for record in data_ops if record.get("op") == op]
        hits = [record for record in records if op_correctly_correlated(record, rw)]
        return len(hits), len(records)

    get_hits, get_total = coverage("GET", "read")
    put_hits, put_total = coverage("PUT", "write")

    def enforce_rate(flag_value, hits, total, label):
        if flag_value is None:
            return
        if total == 0:
            if flag_value > 0:
                fail(errors, f"{label}: manifest has no successful data operations to evaluate")
            return
        rate = hits / total
        if rate < flag_value - 1e-9:
            fail(
                errors,
                f"{label}: correlation rate {rate:.3f} ({hits}/{total}) is below required {flag_value:.3f}",
            )

    enforce_rate(args.require_get_read_correlation, get_hits, get_total, "require-get-read-correlation")
    enforce_rate(args.require_put_write_correlation, put_hits, put_total, "require-put-write-correlation")

    return {
        "get_read": {"correlated": get_hits, "total": get_total},
        "put_write": {"correlated": put_hits, "total": put_total},
        **counters,
    }


def is_bucket_list_span(span):
    """A `cls_rgw` bucket-index list op (one per bucket-index SHARD)."""
    return BUCKET_LIST_OP in str(attr_map(span).get("ceph.rados.ops", ""))


def check_list_shard_correlation(errors, manifest, rados_spans, background_spans, request_by_id):
    """A sharded ListObjects must correlate its `rgw.bucket_list` shard ops.

    THE GAP THIS CLOSES. The gate enforced GET->read and PUT->write correlation and
    zero mis-correlation, and nothing at all about a LIST. That is exactly the shape
    that regressed: RGW issues a bucket listing as ONE `call(rgw.bucket_list)` per
    bucket-index shard, through the cls_rgw AIO path (`CLSRGWIssueBucketList` ->
    `IoCtx::aio_operate`) which NEVER passes through `rgw_rados_operate`. Those
    submits correlate only off the request context `get_handler` left on the thread.
    A fail-closed clear that also wiped that context turned all 16 shard ops of a
    live ListObjects request into standalone background ops -- a NET LOSS of context
    for the request -- while every existing assertion stayed green.

    GUARDED: enforced only when the workload actually performed a LIST *and* the run
    observed >= MIN_LIST_SHARDS bucket_list ops (i.e. the bucket really is sharded).
    A single-shard bucket, or a build/workload with no listing, skips the check
    rather than failing it.

    Correlation is judged by IDENTITY (the shard op's parent request's trans_id ==
    the LIST's x-amz-request-id), never by a time window: with a multi-second slack a
    window proves nothing about which request a shard op belongs to.
    """
    list_ops = [
        record
        for record in (manifest or [])
        if record.get("op") == "LIST"
        and record.get("status", "ok") == "ok"
        and record.get("x_amz_request_id")
    ]
    if not list_ops:
        return None

    correlated_shards = [span for span in rados_spans if is_bucket_list_span(span)]
    stranded_shards = [span for span in background_spans if is_bucket_list_span(span)]
    observed = len(correlated_shards) + len(stranded_shards)

    summary = {
        "list_requests": len(list_ops),
        "bucket_list_ops": observed,
        "bucket_list_ops_correlated": len(correlated_shards),
        "bucket_list_ops_background": len(stranded_shards),
        "enforced": False,
        "per_request": {},
    }

    if observed < MIN_LIST_SHARDS:
        # Not a sharded listing (or the listing never reached the bucket index).
        # Nothing to enforce -- reported, so a skipped gate is never invisible.
        summary["skipped_reason"] = (
            f"observed {observed} bucket_list ops, need >= {MIN_LIST_SHARDS} to prove a sharded bucket"
        )
        return summary

    summary["enforced"] = True
    for record in list_ops:
        request_id = record["x_amz_request_id"]
        own = [
            span
            for span in correlated_shards
            if span_parent_trans_id(span, request_by_id) == request_id
        ]
        summary["per_request"][request_id] = len(own)

    best = max(summary["per_request"].values(), default=0)
    if best < MIN_LIST_SHARDS:
        fail(
            errors,
            f"LIST SHARD CORRELATION: the run observed {observed} rgw.bucket_list shard ops "
            f"({len(stranded_shards)} of them emitted as standalone background ops), but no "
            f"ListObjects request correlated more than {best} of them "
            f"(per-request: {summary['per_request']!r}). A sharded bucket listing must attach "
            f"its bucket_list shard ops to its own request -- they are submitted through the "
            f"cls_rgw AIO path, which never reaches rgw_rados_operate, so they correlate only "
            f"off the request context on the listing thread.",
        )
    return summary


def verify_document(args, document, workload, manifest=None):
    errors = []

    trace = document.get("trace", document)
    spans = trace.get("spans", [])
    diagnostics = trace.get("diagnostics", {})

    request_spans = [span for span in spans if span.get("name") == "rgw.request"]
    rados_spans = [span for span in spans if span.get("name") == "rados.op"]
    background_spans = [span for span in spans if span.get("name") == "rgw.background.rados_op"]
    request_by_id = {span.get("span_id"): span for span in request_spans}
    request_ids = set(request_by_id)
    workload_request_id_count = 0
    trace_request_id_count = 0
    trace_only_request_id_count = 0

    span_ids = set()
    for span in spans:
        if span.get("name") not in SPAN_NAMES:
            fail(errors, f"span has unexpected name={span.get('name')!r}")
        span_id = span.get("span_id")
        trace_id = span.get("trace_id")
        if not is_hex_id(trace_id, 32):
            fail(errors, f"span {span.get('name')} has invalid trace_id={trace_id!r}")
        if not is_hex_id(span_id, 16):
            fail(errors, f"span {span.get('name')} has invalid span_id={span_id!r}")
        if span_id in span_ids:
            fail(errors, f"duplicate span_id={span_id!r}")
        span_ids.add(span_id)
        parent_span_id = span.get("parent_span_id")
        if parent_span_id is not None and not is_hex_id(parent_span_id, 16):
            fail(errors, f"span {span_id!r} has invalid parent_span_id={parent_span_id!r}")
        if parent_span_id == span_id:
            fail(errors, f"span {span_id!r} cannot be its own parent")
        if not is_uint(span.get("start_ns")) or not is_uint(span.get("end_ns")):
            fail(errors, f"span {span_id!r} has invalid start/end timestamps")
        elif span.get("start_ns") > span.get("end_ns"):
            fail(errors, f"span {span_id!r} has start_ns > end_ns")

    if diagnostics.get("decode_errors", 0) != 0:
        fail(errors, f"decode_errors must be 0, got {diagnostics.get('decode_errors')}")
    if diagnostics.get("events_decoded") != (
        diagnostics.get("request_markers", 0)
        + diagnostics.get("request_end_markers", 0)
        + diagnostics.get("rados_ops", 0)
    ):
        fail(errors, "events_decoded must equal request_markers + request_end_markers + rados_ops")
    if diagnostics.get("request_markers", 0) <= 0:
        fail(errors, "expected request_markers > 0")
    if diagnostics.get("rados_ops", 0) <= 0:
        fail(errors, "expected rados_ops > 0")
    if diagnostics.get("correlated_rados_ops", 0) <= 0:
        fail(errors, "expected correlated_rados_ops > 0")
    if diagnostics.get("same_thread_correlations", 0) <= 0:
        fail(errors, "expected same_thread_correlations > 0")
    if diagnostics.get("spans_produced") != len(spans):
        fail(errors, f"spans_produced={diagnostics.get('spans_produced')} but JSON has {len(spans)} spans")
    # An op dropped because the --output json buffer cap was reached is counted in
    # rados_ops but rendered as no span.
    buffer_dropped_ops = diagnostics.get("buffer_full_dropped_rados_ops", 0)
    if diagnostics.get("rados_ops") != len(rados_spans) + len(background_spans) + buffer_dropped_ops:
        fail(errors, f"rados_ops={diagnostics.get('rados_ops')} but JSON has {len(rados_spans)} child and {len(background_spans)} background RADOS spans (+{buffer_dropped_ops} dropped at the buffer cap)")
    if diagnostics.get("correlated_rados_ops") != len(rados_spans):
        fail(errors, f"correlated_rados_ops={diagnostics.get('correlated_rados_ops')} but JSON has {len(rados_spans)} rados.op spans")
    if diagnostics.get("background_rados_ops") != len(background_spans):
        fail(errors, f"background_rados_ops={diagnostics.get('background_rados_ops')} but JSON has {len(background_spans)} background spans")
    # Counter equation (cross-thread stage): every correlated op is exactly one
    # of same_thread, cross_thread, or inferred. same_thread/cross_thread are
    # derived late when spans are built, so the equation ties the render-time
    # tallies back to the ingest-time correlated total.
    if (
        diagnostics.get("same_thread_correlations", 0)
        + diagnostics.get("cross_thread_correlations", 0)
        + diagnostics.get("inferred_correlations", 0)
        != diagnostics.get("correlated_rados_ops")
    ):
        fail(errors, "same_thread_correlations + cross_thread_correlations + inferred_correlations must equal correlated_rados_ops")
    # Tie each counter to the rendered child spans it derives from.
    child_correlations = count_by([attr_map(span).get("rgw.correlation") for span in rados_spans])
    for counter, correlation in (
        ("same_thread_correlations", "same_thread"),
        ("cross_thread_correlations", "cross_thread"),
        ("inferred_correlations", "inferred"),
    ):
        if diagnostics.get(counter, 0) != child_correlations.get(correlation, 0):
            fail(errors, f"{counter}={diagnostics.get(counter, 0)} but JSON has {child_correlations.get(correlation, 0)} {correlation} rados.op spans")
    if diagnostics.get("missing_trans_id_background_ops") != diagnostics.get("background_rados_ops"):
        fail(errors, "missing_trans_id_background_ops must equal background_rados_ops")
    for key in BPF_FAILURE_DIAGNOSTICS:
        if diagnostics.get(key, 0) != 0:
            fail(errors, f"{key} must be 0, got {diagnostics.get(key)}")
    for key in BPF_INFORMATIONAL_DIAGNOSTICS:
        value = diagnostics.get(key, 0)
        if not isinstance(value, int) or value < 0:
            fail(errors, f"{key} must be a non-negative integer, got {value!r}")
    for key in BPF_INVARIANT_DIAGNOSTICS:
        if diagnostics.get(key, 0) != 0:
            fail(errors, f"{key} must be 0, got {diagnostics.get(key)}")
    # The multi-key bridge's revocation identity. Every alternate key that was
    # inserted must have been revoked, skipped (already re-keyed by a newer request),
    # found already absent (LRU-evicted), or still belong to a request in flight. A
    # shortfall means keys are LEAKING, and a leaked key on a recycled RGWOp address
    # is a mis-correlation source.
    inserts = diagnostics.get("bpf_rgw_op_key_inserts", 0)
    accounted = (
        diagnostics.get("bpf_rgw_op_key_revokes", 0)
        + diagnostics.get("bpf_rgw_op_key_revoke_skipped", 0)
        + diagnostics.get("bpf_rgw_op_key_revoke_absent", 0)
    )
    if accounted > inserts:
        fail(errors, f"bpf_rgw_op_key revocations ({accounted}) exceed inserts ({inserts})")
    # In-flight requests at end of run bound the shortfall. Requests that were still
    # open when tracing stopped keep their keys, which is expected -- but a shortfall
    # larger than the requests we saw start-without-end cannot be explained that way.
    open_requests = max(
        0, diagnostics.get("request_markers", 0) - diagnostics.get("request_end_markers", 0)
    )
    if inserts - accounted > open_requests:
        fail(
            errors,
            f"bpf_rgw_op_key_inserts={inserts} but only {accounted} were revoked/skipped/absent "
            f"and at most {open_requests} requests were still in flight -- alternate keys leaked",
        )

    if len(request_spans) < args.min_request_spans:
        fail(errors, f"expected at least {args.min_request_spans} rgw.request spans, got {len(request_spans)}")
    if len(rados_spans) < args.min_rados_spans:
        fail(errors, f"expected at least {args.min_rados_spans} rados.op spans, got {len(rados_spans)}")

    measured_request_spans = 0
    derived_request_spans = 0
    for span in request_spans:
        attrs = attr_map(span)
        if span.get("parent_span_id") is not None:
            fail(errors, f"request span {span.get('span_id')} unexpectedly has a parent")
        if span.get("events"):
            fail(errors, f"request span {span.get('span_id')} unexpectedly has events")
        if attrs.get("rgw.request_class") != "s3_request":
            fail(errors, f"request span {span.get('span_id')} has rgw.request_class={attrs.get('rgw.request_class')!r}")
        if not attrs.get("rgw.trans_id"):
            fail(errors, f"request span {span.get('span_id')} has empty rgw.trans_id")
        quality = attrs.get("rgw.duration_quality")
        if quality not in VALID_DURATION_QUALITIES:
            fail(errors, f"request span {span.get('span_id')} has invalid rgw.duration_quality={quality!r}")
        # Both boundaries have provenance. The START is measured whenever a
        # request marker exists (get_handler's own clock read); the END only when
        # the destructor probe fired. `rados_bounds` has neither.
        measured_start = attrs.get("rgw.request.measured_start_ns")
        if quality == "rados_bounds":
            if measured_start is not None:
                fail(errors, f"request span {span.get('span_id')} has no marker but carries rgw.request.measured_start_ns={measured_start!r}")
        elif not is_uint(measured_start):
            fail(errors, f"request span {span.get('span_id')} is {quality} but has no rgw.request.measured_start_ns")
        # A measured duration MUST be backed by the raw end from the END probe,
        # and a derived one must NOT claim to have one. `measured` additionally
        # means BOTH span bounds ARE the raw measured values (unextended,
        # unclamped) -- a span whose start was pulled back to an early child is
        # just as partly-fictional as one whose end was pushed out.
        measured_end = attrs.get("rgw.request.measured_end_ns")
        if quality in MEASURED_DURATION_QUALITIES:
            measured_request_spans += 1
            if not is_uint(measured_end):
                fail(errors, f"request span {span.get('span_id')} is {quality} but has no rgw.request.measured_end_ns")
            elif quality == "measured" and measured_end != span.get("end_ns"):
                fail(errors, f"request span {span.get('span_id')} claims measured but end_ns {span.get('end_ns')} != measured_end_ns {measured_end}")
            elif quality == "measured" and measured_start != span.get("start_ns"):
                fail(errors, f"request span {span.get('span_id')} claims measured but start_ns {span.get('start_ns')} != measured_start_ns {measured_start}")
            elif quality == "measured_extended" and measured_end == span.get("end_ns") and measured_start == span.get("start_ns"):
                fail(errors, f"request span {span.get('span_id')} claims measured_extended but both bounds equal the measured interval")
        else:
            derived_request_spans += 1
            if measured_end is not None:
                fail(errors, f"request span {span.get('span_id')} is {quality} but carries rgw.request.measured_end_ns={measured_end!r}")

    if diagnostics.get("measured_duration_requests", 0) != measured_request_spans:
        fail(errors, f"measured_duration_requests={diagnostics.get('measured_duration_requests', 0)} but JSON has {measured_request_spans} measured request spans")
    if diagnostics.get("derived_duration_requests", 0) != derived_request_spans:
        fail(errors, f"derived_duration_requests={diagnostics.get('derived_duration_requests', 0)} but JSON has {derived_request_spans} derived request spans")
    # Every request end marker must land on a request span, so measured spans can
    # never exceed the END markers decoded.
    if measured_request_spans > diagnostics.get("request_end_markers", 0):
        fail(errors, f"{measured_request_spans} measured request spans but only {diagnostics.get('request_end_markers', 0)} request_end_markers")

    roles = set()
    rados_objects = []
    background_roles = []
    background_reasons = []
    for span in rados_spans:
        attrs = attr_map(span)
        roles.add(attrs.get("rgw.rados_role"))
        rados_objects.append(str(attrs.get("ceph.rados.object", "")))
        validate_rados_attributes(errors, span, attrs, "rados.op")
        if span.get("events"):
            fail(errors, f"rados.op span {span.get('span_id')} unexpectedly has events")
        parent = span.get("parent_span_id")
        if parent not in request_ids:
            fail(errors, f"rados.op span {span.get('span_id')} parent {parent!r} is not an rgw.request span")
        else:
            parent_span = request_by_id[parent]
            if span.get("trace_id") != parent_span.get("trace_id"):
                fail(errors, f"rados.op span {span.get('span_id')} trace_id does not match parent request")
            if span.get("start_ns", 0) < parent_span.get("start_ns", 0) or span.get("end_ns", 0) > parent_span.get("end_ns", 0):
                fail(errors, f"rados.op span {span.get('span_id')} is outside parent request bounds")
        if attrs.get("rgw.correlation") not in VALID_CHILD_CORRELATIONS:
            fail(errors, f"rados.op span {span.get('span_id')} has invalid rgw.correlation={attrs.get('rgw.correlation')!r}")
        if attrs.get("rgw.correlation") == "same_thread" and attrs.get("rgw.correlation_reason") is not None:
            fail(errors, f"rados.op span {span.get('span_id')} has unexpected rgw.correlation_reason")
        # cross_thread is the late-derived, bridge-inherited correlation
        # (--correlate-cross-thread): best-effort, opt-in, build-dependent. It
        # carries a fixed reason so consumers can distinguish it from a native
        # same-thread correlation.
        if attrs.get("rgw.correlation") == "cross_thread" and attrs.get("rgw.correlation_reason") != "reseed_bridge":
            fail(errors, f"rados.op span {span.get('span_id')} has invalid cross_thread correlation reason")
        if attrs.get("rgw.correlation") == "inferred" and attrs.get("rgw.correlation_reason") != "pid_time_window":
            fail(errors, f"rados.op span {span.get('span_id')} has invalid inferred correlation reason")

    for span in background_spans:
        attrs = attr_map(span)
        roles.add(attrs.get("rgw.rados_role"))
        rados_objects.append(str(attrs.get("ceph.rados.object", "")))
        background_roles.append(attrs.get("rgw.rados_role"))
        background_reasons.append(attrs.get("rgw.correlation_reason"))
        validate_rados_attributes(errors, span, attrs, "background")
        if span.get("parent_span_id") is not None:
            fail(errors, f"background span {span.get('span_id')} unexpectedly has a parent")
        if attrs.get("rgw.correlation") != "none":
            fail(errors, f"background span {span.get('span_id')} has rgw.correlation={attrs.get('rgw.correlation')!r}")
        if attrs.get("rgw.correlation_reason") not in VALID_BACKGROUND_REASONS:
            fail(errors, f"background span {span.get('span_id')} is missing rgw.correlation_reason")
        validate_background_event(errors, span, attrs)

    if sum_counter_map(diagnostics.get("background_rados_by_role")) != len(background_spans):
        fail(errors, "background_rados_by_role counts must sum to background_rados_ops")
    if sum_counter_map(diagnostics.get("background_rados_by_reason")) != len(background_spans):
        fail(errors, "background_rados_by_reason counts must sum to background_rados_ops")
    if diagnostics.get("background_rados_by_role", {}) != count_by(background_roles):
        fail(errors, "background_rados_by_role does not match background span roles")
    if diagnostics.get("background_rados_by_reason", {}) != count_by(background_reasons):
        fail(errors, "background_rados_by_reason does not match background span reasons")

    for role in args.expect_role:
        if role not in roles:
            fail(errors, f"expected rgw.rados_role={role!r}; observed roles: {sorted(role for role in roles if role)}")

    for group in args.expect_any_role:
        alternatives = {role.strip() for role in group.split(",") if role.strip()}
        if alternatives.isdisjoint(roles):
            fail(errors, f"expected one of roles {sorted(alternatives)}; observed roles: {sorted(role for role in roles if role)}")

    successful_workload = [record for record in workload if record.get("status") == "ok"]
    failed_workload = [record for record in workload if record.get("status") != "ok"]
    if failed_workload:
        fail(errors, f"workload had failed operations: {[record.get('name') for record in failed_workload]}")
    if not successful_workload:
        fail(errors, "workload file contains no successful operations")
    else:
        start_ns = min(record["start_ns"] for record in successful_workload)
        end_ns = max(record["end_ns"] for record in successful_workload)
        slack_ns = args.time_slack_ms * 1_000_000
        request_in_window = [span for span in request_spans if span_overlaps(span, start_ns, end_ns, slack_ns)]
        rados_in_window = [span for span in rados_spans if span_overlaps(span, start_ns, end_ns, slack_ns)]
        if not request_in_window:
            fail(errors, "no rgw.request span overlaps the workload time window")
        if not rados_in_window:
            fail(errors, "no rados.op span overlaps the workload time window")
        rados_bounds_requests = [
            attr_map(span).get("rgw.trans_id")
            for span in request_in_window
            if attr_map(span).get("rgw.duration_quality") == "rados_bounds"
        ]
        if rados_bounds_requests:
            fail(errors, f"workload request spans missing RGW request markers: {rados_bounds_requests}")

        keys = {record.get("key") for record in successful_workload if record.get("key")}
        if keys and not any(any(key in obj for key in keys) for obj in rados_objects):
            fail(errors, f"no captured ceph.rados.object contains workload keys {sorted(keys)}")

        missing_request_id_records = [record for record in successful_workload if not record.get("x_amz_request_id")]
        if missing_request_id_records:
            fail(
                errors,
                "successful workload records missing x-amz-request-id: "
                f"{[record.get('name') for record in missing_request_id_records]}",
            )

        workload_request_ids = [record["x_amz_request_id"] for record in successful_workload if record.get("x_amz_request_id")]
        trace_request_ids = []
        for span in request_in_window:
            trans_id = attr_map(span).get("rgw.trans_id")
            if trans_id:
                trace_request_ids.append(trans_id)

        workload_request_id_count = len(workload_request_ids)
        trace_request_id_count = len(trace_request_ids)

        duplicate_workload_ids = duplicate_values(workload_request_ids)
        if duplicate_workload_ids:
            fail(errors, f"duplicate workload x-amz-request-id values: {duplicate_workload_ids}")

        duplicate_trace_ids = duplicate_values(trace_request_ids)
        if duplicate_trace_ids:
            fail(errors, f"duplicate trace rgw.trans_id values in workload window: {duplicate_trace_ids}")

        workload_request_id_set = set(workload_request_ids)
        trace_request_id_set = set(trace_request_ids)
        missing_trace_ids = sorted(workload_request_id_set - trace_request_id_set)
        unexpected_trace_ids = sorted(trace_request_id_set - workload_request_id_set)
        # Coverage guarantee (still a failure): every workload request the tool
        # issued must show up in the trace window.
        if missing_trace_ids:
            fail(errors, f"workload x-amz-request-id values missing from trace rgw.trans_id: {missing_trace_ids}")
        # The reverse direction is NOT a failure: a live trace window legitimately
        # captures every request RGW served, which can exceed a single --workload
        # file (concurrent clients, retries, background/health requests). Flagging
        # those extra trace requests was a false positive -- e.g. a concurrent
        # workload phase running alongside the sequential one. Surface the count
        # informationally instead.
        trace_only_request_id_count = len(unexpected_trace_ids)

    manifest_coverage = None
    list_shard_coverage = None
    if manifest is not None:
        slack_ns = args.time_slack_ms * 1_000_000
        manifest_coverage = check_object_request_correlation(
            args, errors, manifest, workload, rados_spans, background_spans, request_by_id, slack_ns
        )
        list_shard_coverage = check_list_shard_correlation(
            errors, manifest, rados_spans, background_spans, request_by_id
        )

    summary = {
        "spans": len(spans),
        "request_spans": len(request_spans),
        "rados_spans": len(rados_spans),
        "background_spans": len(background_spans),
        "workload_request_ids": workload_request_id_count,
        "trace_request_ids_in_window": trace_request_id_count,
        "trace_only_request_ids": trace_only_request_id_count,
        "roles": sorted(role for role in roles if role),
        "diagnostics": diagnostics,
    }
    if manifest_coverage is not None:
        summary["manifest_coverage"] = manifest_coverage
    if list_shard_coverage is not None:
        summary["list_shard_coverage"] = list_shard_coverage
    return summary, errors


def self_test_args(
    require_get_read_correlation=None,
    require_put_write_correlation=None,
    expect_role=("data",),
):
    return SimpleNamespace(
        min_request_spans=1,
        min_rados_spans=1,
        expect_role=list(expect_role),
        expect_any_role=[],
        time_slack_ms=2000,
        workload_manifest=None,
        require_get_read_correlation=require_get_read_correlation,
        require_put_write_correlation=require_put_write_correlation,
    )


def attr(key, value):
    return {"key": key, "value": value}


def valid_self_test_document():
    # The default shape is now the two-marker one: the END probe fired, so the
    # request span carries a MEASURED end (span end_ns == measured_end_ns).
    request_attrs = [
        attr("rgw.trans_id", "tx-selftest"),
        attr("rgw.request_class", "s3_request"),
        attr("rgw.duration_quality", "measured"),
        attr("rgw.request.tid", 7),
        attr("rgw.request.measured_start_ns", 100),
        attr("rgw.request.measured_end_ns", 300),
    ]
    rados_attrs = [
        attr("ceph.rados.duration_ns", 60),
        attr("ceph.rados.send_tid", 7),
        attr("ceph.rados.pool", 1),
        attr("ceph.rados.pg", "1.2a"),
        attr("ceph.rados.pg_seed", 42),
        attr("ceph.rados.target_osd", 0),
        attr("ceph.rados.acting", "[0,1,2]"),
        attr("ceph.rados.object", "bucket/selftest-object"),
        attr("ceph.rados.ops", "read"),
        attr("ceph.rados.rw", "read"),
        attr("ceph.rados.offset", 0),
        attr("ceph.rados.length", 0),
        attr("rgw.rados_role", "data"),
        attr("rgw.correlation", "same_thread"),
    ]
    background_attrs = [
        attr("ceph.rados.duration_ns", 20),
        attr("ceph.rados.send_tid", 11),
        attr("ceph.rados.pool", 2),
        attr("ceph.rados.pg", "2.7"),
        attr("ceph.rados.pg_seed", 7),
        attr("ceph.rados.target_osd", 1),
        attr("ceph.rados.acting", "[1,2,3]"),
        attr("ceph.rados.object", "notify.0"),
        attr("ceph.rados.ops", "read"),
        attr("ceph.rados.rw", "read"),
        attr("ceph.rados.offset", 0),
        attr("ceph.rados.length", 0),
        attr("rgw.rados_role", "notify"),
        attr("rgw.correlation", "none"),
        attr("rgw.correlation_reason", "classified_background_role"),
    ]
    return {
        "service_name": "rgwtrace-e2e",
        "spans": [
            {
                "trace_id": "1" * 32,
                "span_id": "1" * 16,
                "parent_span_id": None,
                "name": "rgw.request",
                "start_ns": 100,
                "end_ns": 300,
                "attributes": request_attrs,
                "events": [],
            },
            {
                "trace_id": "1" * 32,
                "span_id": "2" * 16,
                "parent_span_id": "1" * 16,
                "name": "rados.op",
                "start_ns": 120,
                "end_ns": 180,
                "attributes": rados_attrs,
                "events": [],
            },
            {
                "trace_id": "3" * 32,
                "span_id": "3" * 16,
                "parent_span_id": None,
                "name": "rgw.background.rados_op",
                "start_ns": 400,
                "end_ns": 420,
                "attributes": background_attrs,
                "events": [
                    {
                        "name": "rados.op",
                        "time_ns": 420,
                        "attributes": deepcopy(background_attrs),
                    }
                ],
            },
        ],
        "diagnostics": {
            "events_decoded": 4,
            "decode_errors": 0,
            "request_markers": 1,
            "request_end_markers": 1,
            "measured_duration_requests": 1,
            "derived_duration_requests": 0,
            "rados_ops": 2,
            "correlated_rados_ops": 1,
            "background_rados_ops": 1,
            "same_thread_correlations": 1,
            "inferred_correlations": 0,
            "missing_trans_id_background_ops": 1,
            "background_rados_by_role": {"notify": 1},
            "background_rados_by_reason": {"classified_background_role": 1},
            "spans_produced": 3,
        },
    }


def derived_duration_self_test_document():
    """valid_self_test_document as produced on a build WITHOUT the end probe.

    Only the get_handler START marker arrives, so the request's end is derived
    from its RADOS child bounds: quality `marker`, no rgw.request.measured_end_ns,
    and no request_end_markers. This is the backward-compatibility shape and it
    must keep validating.
    """
    document = valid_self_test_document()
    request = document["spans"][0]
    request["attributes"] = [
        attr("rgw.trans_id", "tx-selftest"),
        attr("rgw.request_class", "s3_request"),
        attr("rgw.duration_quality", "marker"),
        attr("rgw.request.tid", 7),
        # The START is still measured (get_handler); only the END is derived.
        attr("rgw.request.measured_start_ns", 100),
    ]
    diagnostics = document["diagnostics"]
    diagnostics["events_decoded"] = 3
    diagnostics["request_end_markers"] = 0
    diagnostics["measured_duration_requests"] = 0
    diagnostics["derived_duration_requests"] = 1
    return document


def cross_thread_self_test_document():
    """valid_self_test_document plus a second child correlated cross_thread.

    Exercises the late-derived cross_thread label (opt-in re-seed bridge): a
    same_thread child and a cross_thread child under the same request, with the
    counter equation correlated == same_thread + cross_thread + inferred holding.
    """
    document = valid_self_test_document()
    cross_attrs = [
        attr("ceph.rados.duration_ns", 40),
        # A bridged op: submitted on a different thread than the request marker.
        attr("ceph.rados.send_tid", 4242),
        attr("ceph.rados.pool", 1),
        attr("ceph.rados.pg", "1.2b"),
        attr("ceph.rados.pg_seed", 43),
        attr("ceph.rados.target_osd", 0),
        attr("ceph.rados.acting", "[0,1,2]"),
        attr("ceph.rados.object", "bucket/selftest-object-shadow"),
        attr("ceph.rados.ops", "writefull"),
        attr("ceph.rados.rw", "write"),
        attr("ceph.rados.offset", 0),
        attr("ceph.rados.length", 4096),
        attr("rgw.rados_role", "data"),
        attr("rgw.correlation", "cross_thread"),
        attr("rgw.correlation_reason", "reseed_bridge"),
    ]
    document["spans"].insert(
        2,
        {
            "trace_id": "1" * 32,
            "span_id": "6" * 16,
            "parent_span_id": "1" * 16,
            "name": "rados.op",
            "start_ns": 200,
            "end_ns": 240,
            "attributes": cross_attrs,
            "events": [],
        },
    )
    diagnostics = document["diagnostics"]
    diagnostics["events_decoded"] = 5
    diagnostics["rados_ops"] = 3
    diagnostics["correlated_rados_ops"] = 2
    diagnostics["cross_thread_correlations"] = 1
    diagnostics["spans_produced"] = 4
    return document


def valid_self_test_workload():
    return [
        {
            "name": "put-object",
            "status": "ok",
            "start_ns": 110,
            "end_ns": 190,
            "key": "selftest-object",
            "x_amz_request_id": "tx-selftest",
        }
    ]


def manifest_self_test_document():
    """A two-request document (GET->read, PUT->write) plus one background op.

    Both data ops carry a distinct object key so the manifest object->request
    mapping is unambiguous, mirroring s3-workload.py --unique-keys output.
    """
    get_request_attrs = [
        attr("rgw.trans_id", "tx-get"),
        attr("rgw.request_class", "s3_request"),
        attr("rgw.duration_quality", "measured"),
        attr("rgw.request.tid", 7),
        attr("rgw.request.measured_start_ns", 100),
        attr("rgw.request.measured_end_ns", 300),
    ]
    read_rados_attrs = [
        attr("ceph.rados.duration_ns", 60),
        attr("ceph.rados.send_tid", 7),
        attr("ceph.rados.pool", 1),
        attr("ceph.rados.pg", "1.2a"),
        attr("ceph.rados.pg_seed", 42),
        attr("ceph.rados.target_osd", 0),
        attr("ceph.rados.acting", "[0,1,2]"),
        attr("ceph.rados.object", "bucket/get-key-aaa"),
        attr("ceph.rados.ops", "read"),
        attr("ceph.rados.rw", "read"),
        attr("ceph.rados.offset", 0),
        attr("ceph.rados.length", 0),
        attr("rgw.rados_role", "data"),
        attr("rgw.correlation", "same_thread"),
    ]
    put_request_attrs = [
        attr("rgw.trans_id", "tx-put"),
        attr("rgw.request_class", "s3_request"),
        attr("rgw.duration_quality", "measured"),
        attr("rgw.request.tid", 9),
        attr("rgw.request.measured_start_ns", 400),
        attr("rgw.request.measured_end_ns", 600),
    ]
    write_rados_attrs = [
        attr("ceph.rados.duration_ns", 80),
        attr("ceph.rados.send_tid", 9),
        attr("ceph.rados.pool", 1),
        attr("ceph.rados.pg", "1.2b"),
        attr("ceph.rados.pg_seed", 43),
        attr("ceph.rados.target_osd", 0),
        attr("ceph.rados.acting", "[0,1,2]"),
        attr("ceph.rados.object", "bucket/put-key-bbb__shadow_0"),
        attr("ceph.rados.ops", "writefull"),
        attr("ceph.rados.rw", "write"),
        attr("ceph.rados.offset", 0),
        attr("ceph.rados.length", 4096),
        attr("rgw.rados_role", "data"),
        attr("rgw.correlation", "same_thread"),
    ]
    background_attrs = [
        attr("ceph.rados.duration_ns", 20),
        attr("ceph.rados.send_tid", 11),
        attr("ceph.rados.pool", 2),
        attr("ceph.rados.pg", "2.7"),
        attr("ceph.rados.pg_seed", 7),
        attr("ceph.rados.target_osd", 1),
        attr("ceph.rados.acting", "[1,2,3]"),
        attr("ceph.rados.object", "notify.0"),
        attr("ceph.rados.ops", "read"),
        attr("ceph.rados.rw", "read"),
        attr("ceph.rados.offset", 0),
        attr("ceph.rados.length", 0),
        attr("rgw.rados_role", "notify"),
        attr("rgw.correlation", "none"),
        attr("rgw.correlation_reason", "classified_background_role"),
    ]
    return {
        "service_name": "rgwtrace-e2e",
        "spans": [
            {
                "trace_id": "1" * 32,
                "span_id": "1" * 16,
                "parent_span_id": None,
                "name": "rgw.request",
                "start_ns": 100,
                "end_ns": 300,
                "attributes": get_request_attrs,
                "events": [],
            },
            {
                "trace_id": "1" * 32,
                "span_id": "2" * 16,
                "parent_span_id": "1" * 16,
                "name": "rados.op",
                "start_ns": 120,
                "end_ns": 180,
                "attributes": read_rados_attrs,
                "events": [],
            },
            {
                "trace_id": "4" * 32,
                "span_id": "4" * 16,
                "parent_span_id": None,
                "name": "rgw.request",
                "start_ns": 400,
                "end_ns": 600,
                "attributes": put_request_attrs,
                "events": [],
            },
            {
                "trace_id": "4" * 32,
                "span_id": "5" * 16,
                "parent_span_id": "4" * 16,
                "name": "rados.op",
                "start_ns": 420,
                "end_ns": 500,
                "attributes": write_rados_attrs,
                "events": [],
            },
            {
                "trace_id": "3" * 32,
                "span_id": "3" * 16,
                "parent_span_id": None,
                "name": "rgw.background.rados_op",
                "start_ns": 700,
                "end_ns": 720,
                "attributes": background_attrs,
                "events": [
                    {
                        "name": "rados.op",
                        "time_ns": 720,
                        "attributes": deepcopy(background_attrs),
                    }
                ],
            },
        ],
        "diagnostics": {
            "events_decoded": 7,
            "decode_errors": 0,
            "request_markers": 2,
            "request_end_markers": 2,
            "measured_duration_requests": 2,
            "derived_duration_requests": 0,
            "rados_ops": 3,
            "correlated_rados_ops": 2,
            "background_rados_ops": 1,
            "same_thread_correlations": 2,
            "inferred_correlations": 0,
            "missing_trans_id_background_ops": 1,
            "background_rados_by_role": {"notify": 1},
            "background_rados_by_reason": {"classified_background_role": 1},
            "spans_produced": 5,
        },
    }


def manifest_self_test_workload():
    return [
        {
            "name": "get_object",
            "status": "ok",
            "start_ns": 110,
            "end_ns": 290,
            "key": "get-key-aaa",
            "x_amz_request_id": "tx-get",
        },
        {
            "name": "put_object",
            "status": "ok",
            "start_ns": 410,
            "end_ns": 590,
            "key": "put-key-bbb",
            "x_amz_request_id": "tx-put",
        },
    ]


def manifest_self_test_manifest():
    return [
        {
            "name": "get_object",
            "op": "GET",
            "rw": "read",
            "status": "ok",
            "start_ns": 110,
            "end_ns": 290,
            "key": "get-key-aaa",
            "x_amz_request_id": "tx-get",
        },
        {
            "name": "put_object",
            "op": "PUT",
            "rw": "write",
            "status": "ok",
            "start_ns": 410,
            "end_ns": 590,
            "key": "put-key-bbb",
            "x_amz_request_id": "tx-put",
        },
    ]


def list_shard_self_test_document(shards_correlated, shards=3):
    """A GET request plus a LIST request whose bucket-index listing is sharded.

    `shards_correlated` picks the two live-observed shapes:
      True  -- the healthy one: every `call(rgw.bucket_list)` shard op is a child of
               the ListObjects request that issued it (same_thread -- the shards are
               submitted through the cls_rgw AIO path on the request's own thread).
      False -- THE REGRESSION: the same shard ops emitted as standalone
               `rgw.background.rados_op`s with reason `missing_trans_id`, because the
               request context was cleared off the listing thread. Every other
               assertion in this verifier stays green in this shape, which is exactly
               how it reached a live cluster.

    The GET request keeps a correlated data op in BOTH shapes, so the regressed
    document still satisfies `correlated_rados_ops > 0` and the counter equations --
    i.e. the list-shard gate is the ONLY thing that can catch it.
    """

    def rados_attrs(*, pg_seed, obj, ops, role, rw, correlation, reason=None, duration=60, tid=7):
        attrs = [
            attr("ceph.rados.duration_ns", duration),
            attr("ceph.rados.send_tid", tid),
            attr("ceph.rados.pool", 1),
            attr("ceph.rados.pg", f"1.{pg_seed:x}"),
            attr("ceph.rados.pg_seed", pg_seed),
            attr("ceph.rados.target_osd", 0),
            attr("ceph.rados.acting", "[0,1,2]"),
            attr("ceph.rados.object", obj),
            attr("ceph.rados.ops", ops),
            attr("ceph.rados.rw", rw),
            attr("ceph.rados.offset", 0),
            attr("ceph.rados.length", 0),
            attr("rgw.rados_role", role),
            attr("rgw.correlation", correlation),
        ]
        if reason is not None:
            attrs.append(attr("rgw.correlation_reason", reason))
        return attrs

    spans = [
        {
            "trace_id": "1" * 32,
            "span_id": "1" * 16,
            "parent_span_id": None,
            "name": "rgw.request",
            "start_ns": 100,
            "end_ns": 300,
            "attributes": [
                attr("rgw.trans_id", "tx-get"),
                attr("rgw.request_class", "s3_request"),
                attr("rgw.duration_quality", "measured"),
                attr("rgw.request.tid", 7),
                attr("rgw.request.measured_start_ns", 100),
                attr("rgw.request.measured_end_ns", 300),
            ],
            "events": [],
        },
        {
            "trace_id": "1" * 32,
            "span_id": "2" * 16,
            "parent_span_id": "1" * 16,
            "name": "rados.op",
            "start_ns": 120,
            "end_ns": 180,
            "attributes": rados_attrs(
                pg_seed=42,
                obj="bucket/get-key-aaa",
                ops="read",
                role="data",
                rw="read",
                correlation="same_thread",
            ),
            "events": [],
        },
        {
            "trace_id": "4" * 32,
            "span_id": "4" * 16,
            "parent_span_id": None,
            "name": "rgw.request",
            "start_ns": 400,
            "end_ns": 600,
            "attributes": [
                attr("rgw.trans_id", "tx-list"),
                attr("rgw.request_class", "s3_request"),
                attr("rgw.duration_quality", "measured"),
                attr("rgw.request.tid", 9),
                attr("rgw.request.measured_start_ns", 400),
                attr("rgw.request.measured_end_ns", 600),
            ],
            "events": [],
        },
    ]

    # One `call(rgw.bucket_list)` per bucket-index shard, all submitted on the
    # listing request's own thread (tid 9) through the AIO path.
    for shard in range(shards):
        shard_attrs = rados_attrs(
            pg_seed=0x50 + shard,
            obj=f".dir.bucket-marker.{shard}",
            ops="call(rgw.bucket_list)",
            role="bucket_index",
            rw="read",
            correlation="same_thread" if shards_correlated else "none",
            reason=None if shards_correlated else "missing_trans_id",
            duration=20,
            tid=9,
        )
        if shards_correlated:
            spans.append(
                {
                    "trace_id": "4" * 32,
                    "span_id": f"{shard + 5}" * 16,
                    "parent_span_id": "4" * 16,
                    "name": "rados.op",
                    "start_ns": 420,
                    "end_ns": 440,
                    "attributes": shard_attrs,
                    "events": [],
                }
            )
        else:
            spans.append(
                {
                    "trace_id": f"{shard + 5}" * 32,
                    "span_id": f"{shard + 5}" * 16,
                    "parent_span_id": None,
                    "name": "rgw.background.rados_op",
                    "start_ns": 420,
                    "end_ns": 440,
                    "attributes": shard_attrs,
                    "events": [
                        {
                            "name": "rados.op",
                            "time_ns": 440,
                            "attributes": deepcopy(shard_attrs),
                        }
                    ],
                }
            )

    correlated = 1 + (shards if shards_correlated else 0)
    background = 0 if shards_correlated else shards
    return {
        "service_name": "rgwtrace-e2e",
        "spans": spans,
        "diagnostics": {
            "events_decoded": 4 + 1 + shards,
            "decode_errors": 0,
            "request_markers": 2,
            "request_end_markers": 2,
            "measured_duration_requests": 2,
            "derived_duration_requests": 0,
            "rados_ops": 1 + shards,
            "correlated_rados_ops": correlated,
            "background_rados_ops": background,
            "same_thread_correlations": correlated,
            "inferred_correlations": 0,
            "missing_trans_id_background_ops": background,
            "background_rados_by_role": {"bucket_index": shards} if background else {},
            "background_rados_by_reason": {"missing_trans_id": shards} if background else {},
            "spans_produced": len(spans),
        },
    }


def list_shard_self_test_workload():
    return [
        {
            "name": "get_object",
            "status": "ok",
            "start_ns": 110,
            "end_ns": 290,
            "key": "get-key-aaa",
            "x_amz_request_id": "tx-get",
        },
        {
            "name": "list_objects",
            "status": "ok",
            "start_ns": 410,
            "end_ns": 590,
            "key": None,
            "x_amz_request_id": "tx-list",
        },
    ]


def list_shard_self_test_manifest():
    return [
        {
            "name": "get_object",
            "op": "GET",
            "rw": "read",
            "status": "ok",
            "start_ns": 110,
            "end_ns": 290,
            "key": "get-key-aaa",
            "x_amz_request_id": "tx-get",
        },
        {
            "name": "list_objects",
            "op": "LIST",
            "rw": "read",
            "status": "ok",
            "start_ns": 410,
            "end_ns": 590,
            "key": None,
            "x_amz_request_id": "tx-list",
        },
    ]


def run_list_shard_self_test():
    """The gate that would have caught the ListObjects shard regression."""
    workload = list_shard_self_test_workload()
    manifest = list_shard_self_test_manifest()

    # 1. The healthy shape passes, and reports the gate as ENFORCED (a gate that
    #    silently skipped itself would be worthless).
    summary, errors = verify_document(
        self_test_args(), list_shard_self_test_document(True), workload, manifest
    )
    if errors:
        for error in errors:
            print(f"SELF-TEST ERROR: correlated list shards failed: {error}", file=sys.stderr)
        return 1
    coverage = summary.get("list_shard_coverage") or {}
    if not coverage.get("enforced"):
        print(f"SELF-TEST ERROR: list-shard gate did not enforce: {coverage!r}", file=sys.stderr)
        return 1
    if coverage.get("bucket_list_ops_correlated") != 3:
        print(f"SELF-TEST ERROR: list-shard coverage miscounted: {coverage!r}", file=sys.stderr)
        return 1

    # 2. THE REGRESSION: the same shard ops emitted as background ops MUST fail.
    #    Every other check in this file passes on that document -- which is the whole
    #    reason this gate exists.
    _, errors = verify_document(
        self_test_args(), list_shard_self_test_document(False), workload, manifest
    )
    if not any("LIST SHARD CORRELATION" in error for error in errors):
        print(
            "SELF-TEST ERROR: stranded rgw.bucket_list shard ops did not fail the list-shard gate",
            file=sys.stderr,
        )
        print(json.dumps(errors, indent=2, sort_keys=True), file=sys.stderr)
        return 1

    # 3. GUARD: an unsharded listing (a single bucket_list op) must SKIP the gate,
    #    not fail it. A single-shard bucket cannot prove anything about sharding.
    document = list_shard_self_test_document(False, shards=1)
    summary, errors = verify_document(self_test_args(), document, workload, manifest)
    if any("LIST SHARD CORRELATION" in error for error in errors):
        print(
            "SELF-TEST ERROR: the list-shard gate fired on an UNSHARDED listing",
            file=sys.stderr,
        )
        return 1
    coverage = summary.get("list_shard_coverage") or {}
    if coverage.get("enforced") or not coverage.get("skipped_reason"):
        print(f"SELF-TEST ERROR: unsharded listing must report a skip reason: {coverage!r}", file=sys.stderr)
        return 1

    # 4. GUARD: a workload with no LIST at all leaves the gate inert.
    no_list_manifest = [record for record in list_shard_self_test_manifest() if record["op"] != "LIST"]
    no_list_workload = [record for record in workload if record["name"] != "list_objects"]
    summary, errors = verify_document(
        self_test_args(),
        list_shard_self_test_document(False),
        no_list_workload,
        no_list_manifest,
    )
    if any("LIST SHARD CORRELATION" in error for error in errors):
        print("SELF-TEST ERROR: the list-shard gate fired without a LIST workload", file=sys.stderr)
        return 1
    if summary.get("list_shard_coverage") is not None:
        print("SELF-TEST ERROR: the list-shard gate must be inert without a LIST", file=sys.stderr)
        return 1

    return 0


def set_span_object(document, span_id, value):
    for span in document["spans"]:
        if span.get("span_id") == span_id:
            for attribute in span["attributes"]:
                if attribute["key"] == "ceph.rados.object":
                    attribute["value"] = value
    return document


def set_manifest_request_id(manifest, op, request_id):
    for record in manifest:
        if record.get("op") == op:
            record["x_amz_request_id"] = request_id
    return manifest


def add_manifest_record(manifest, op, rw, key, request_id, start_ns=110, end_ns=290):
    manifest.append(
        {
            "name": f"{op.lower()}_object",
            "op": op,
            "rw": rw,
            "status": "ok",
            "start_ns": start_ns,
            "end_ns": end_ns,
            "key": key,
            "x_amz_request_id": request_id,
        }
    )
    return manifest


def run_manifest_self_test():
    workload = manifest_self_test_workload()

    # 1. Correct correlation passes even under strict (100%) rate gates.
    strict_args = self_test_args(require_get_read_correlation=1.0, require_put_write_correlation=1.0)
    _, errors = verify_document(strict_args, manifest_self_test_document(), workload, manifest_self_test_manifest())
    if errors:
        for error in errors:
            print(f"SELF-TEST ERROR: valid manifest document failed: {error}", file=sys.stderr)
        return 1

    # 2. Manifest absent => behavior unchanged (gate inert, strict flags ignored).
    _, errors = verify_document(strict_args, manifest_self_test_document(), workload, None)
    if errors:
        for error in errors:
            print(f"SELF-TEST ERROR: manifest-absent path regressed: {error}", file=sys.stderr)
        return 1

    # 3. A coverage miss (data op with no correctly correlated span) must NOT
    #    fail when no --require-* flag is set.
    doc = set_span_object(manifest_self_test_document(), "2" * 16, "bucket/unrelated-read-object")
    _, errors = verify_document(self_test_args(), doc, workload, manifest_self_test_manifest())
    if errors:
        for error in errors:
            print(f"SELF-TEST ERROR: coverage miss failed without a --require flag: {error}", file=sys.stderr)
        return 1

    # Positive regressions: these must produce NO errors (F2 false-positive
    # fixes). The manifest records EVERY workload operation, including OTHER ops
    # (HEAD/COPY/DELETE) that carry a key and a request id, so these cases encode
    # that true shape rather than an absent record.
    positive_cases = [
        (
            # (i) Same-key OTHER op: the read span for get-key-aaa is attached to
            # tx-get, which the manifest records as a delete_object (op OTHER) on
            # the SAME key get-key-aaa, while get-key-aaa's GET is tx-get-read.
            # The attachment is consistent with the manifest (a delete on the key
            # a GET also touched), so it is informational, not a mis-correlation.
            "same-key OTHER-op attachment is consistent",
            lambda doc, man: (
                doc,
                add_manifest_record(
                    set_manifest_request_id(man, "GET", "tx-get-read"),
                    "OTHER",
                    None,
                    "get-key-aaa",
                    "tx-get",
                ),
            ),
        ),
        (
            # (ii) Cross-key OTHER op (copy source): the read span for get-key-aaa
            # is attached to tx-get, recorded as a copy_object (op OTHER) whose key
            # is the DESTINATION copy-get-key-aaa -- which does NOT match the
            # SOURCE object the span read. A copy legitimately reads its source, so
            # the key mismatch on an OTHER op is not provable and does not fail.
            "cross-key OTHER-op (copy source) attachment does not fail",
            lambda doc, man: (
                doc,
                add_manifest_record(
                    set_manifest_request_id(man, "GET", "tx-get-read"),
                    "OTHER",
                    None,
                    "copy-get-key-aaa",
                    "tx-get",
                ),
            ),
        ),
        (
            # (iii) Absent from the manifest entirely: tx-get is not a manifest
            # request at all but is a real workload request. Falls back to the
            # workload log -> informational, not a mis-correlation.
            "attachment to a request absent from the manifest does not fail",
            lambda doc, man: (doc, set_manifest_request_id(man, "GET", "tx-head-external")),
        ),
        (
            # (iv) The object contains two manifest keys, one a substring of the
            # other ("key-aaa" inside "get-key-aaa"). Only the longest, most
            # specific key sets the expectation; its request equals the span's
            # actual parent, so there is no false flag. Using the shorter generic
            # key would (wrongly) expect tx-other and flag a mis-correlation.
            "substring key collision resolves to the longest key",
            lambda doc, man: (
                doc,
                add_manifest_record(man, "GET", "read", "key-aaa", "tx-other"),
            ),
        ),
    ]
    for name, mutate in positive_cases:
        document = manifest_self_test_document()
        manifest = manifest_self_test_manifest()
        document, manifest = mutate(document, manifest)
        _, errors = verify_document(self_test_args(), document, workload, manifest)
        if errors:
            for error in errors:
                print(f"SELF-TEST ERROR: manifest {name!r} case unexpectedly failed: {error}", file=sys.stderr)
            return 1

    cases = [
        (
            # (v) Genuine, provable conflict: the read span for get-key-aaa is
            # attached to tx-get, but the manifest records tx-get as the PUT of
            # put-key-bbb (a single-object op) and get-key-aaa's GET as tx-other.
            # A GET/PUT touches exactly one object, so an attachment to a PUT
            # whose key does not match the span's object still FAILS.
            "genuine conflict with a GET/PUT for a different key",
            self_test_args(),
            lambda doc, man: (
                doc,
                set_manifest_request_id(set_manifest_request_id(man, "GET", "tx-other"), "PUT", "tx-get"),
            ),
            "MIS-CORRELATION",
        ),
        (
            "get coverage gate",
            self_test_args(require_get_read_correlation=1.0),
            lambda doc, man: (set_span_object(doc, "2" * 16, "bucket/unrelated-read-object"), man),
            "require-get-read-correlation",
        ),
        (
            "put coverage gate",
            self_test_args(require_put_write_correlation=1.0),
            lambda doc, man: (set_span_object(doc, "5" * 16, "bucket/unrelated-write-object"), man),
            "require-put-write-correlation",
        ),
        (
            "get coverage gate needs data ops",
            self_test_args(require_get_read_correlation=0.5),
            lambda doc, man: (doc, [record for record in man if record.get("op") != "GET"]),
            "no successful data operations",
        ),
    ]

    for name, case_args, mutate, expected_error in cases:
        document = manifest_self_test_document()
        manifest = manifest_self_test_manifest()
        document, manifest = mutate(document, manifest)
        _, errors = verify_document(case_args, document, workload, manifest)
        if not any(expected_error in error for error in errors):
            print(f"SELF-TEST ERROR: manifest {name!r} case did not fail with {expected_error!r}", file=sys.stderr)
            print(json.dumps(errors, indent=2, sort_keys=True), file=sys.stderr)
            return 1

    return 0


def split_into_jsonl(document):
    """valid_self_test_document as an --output jsonl run would stream it: the
    request with its child in one drain, the background span in the final line,
    each line carrying cumulative diagnostics and its own spans_produced."""
    spans = document["spans"]
    request_and_child = [span for span in spans if span["name"] != "rgw.background.rados_op"]
    background = [span for span in spans if span["name"] == "rgw.background.rados_op"]
    first = deepcopy(document)
    first["spans"] = request_and_child
    first["diagnostics"]["spans_produced"] = len(request_and_child)
    last = deepcopy(document)
    last["spans"] = background
    last["diagnostics"]["spans_produced"] = len(background)
    return [{"dwarf": {"version": "19.2.3"}, "trace": first}, {"dwarf": {"version": "19.2.3"}, "trace": last}]


def run_jsonl_self_test():
    import os
    import tempfile

    args = self_test_args()
    workload = valid_self_test_workload()

    def verify_lines(lines):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            for line in lines:
                handle.write(json.dumps(line) + "\n")
            path = handle.name
        try:
            document, stream_errors = load_trace(path, "auto")
        finally:
            os.unlink(path)
        _, errors = verify_document(args, document, workload)
        return stream_errors + errors

    errors = verify_lines(split_into_jsonl(valid_self_test_document()))
    if errors:
        for error in errors:
            print(f"SELF-TEST ERROR: valid jsonl stream failed: {error}", file=sys.stderr)
        return 1

    cases = [
        (
            # The core streaming invariant: a request must never be emitted twice
            # under one span id, even across drains.
            "span repeated across lines",
            lambda lines: lines[1]["trace"]["spans"].append(deepcopy(lines[0]["trace"]["spans"][0])),
            "duplicate span_id",
        ),
        (
            "per-line spans_produced",
            lambda lines: lines[0]["trace"]["diagnostics"].update({"spans_produced": 7}),
            "jsonl line 1: spans_produced=7",
        ),
        (
            "cumulative counter regression",
            lambda lines: lines[0]["trace"]["diagnostics"].update({"rados_ops": 99}),
            "cumulative counter rados_ops went backwards",
        ),
    ]
    for name, mutate, expected_error in cases:
        lines = split_into_jsonl(valid_self_test_document())
        mutate(lines)
        errors = verify_lines(lines)
        if not any(expected_error in error for error in errors):
            print(f"SELF-TEST ERROR: jsonl {name} case did not fail with {expected_error!r}", file=sys.stderr)
            print(json.dumps(errors, indent=2, sort_keys=True), file=sys.stderr)
            return 1
    return 0


def run_self_test():
    args = self_test_args()
    workload = valid_self_test_workload()
    summary, errors = verify_document(args, valid_self_test_document(), workload)
    if errors:
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"SELF-TEST ERROR: valid document failed: {error}", file=sys.stderr)
        return 1

    # A document carrying a late-derived cross_thread child must validate, and
    # its cross_thread_correlations counter must satisfy the counter equation.
    _, errors = verify_document(args, cross_thread_self_test_document(), workload)
    if errors:
        for error in errors:
            print(f"SELF-TEST ERROR: valid cross_thread document failed: {error}", file=sys.stderr)
        return 1

    # BACKWARD COMPATIBILITY: a run on a build without the request-END probe
    # produces derived (`marker`) request durations and no measured_end_ns. That
    # document must keep validating -- the end probe is optional by contract.
    _, errors = verify_document(args, derived_duration_self_test_document(), workload)
    if errors:
        for error in errors:
            print(f"SELF-TEST ERROR: valid derived-duration document failed: {error}", file=sys.stderr)
        return 1

    cases = [
        (
            "cross_thread reason",
            # Relabel the same_thread child as cross_thread with no valid reason.
            lambda document: document["spans"][1]["attributes"][-1].update({"value": "cross_thread"}),
            "invalid cross_thread correlation reason",
        ),
        (
            "counter equation",
            lambda document: document["diagnostics"].update({"inferred_correlations": 1}),
            "must equal correlated_rados_ops",
        ),
        (
            "bpf diagnostics",
            lambda document: document["diagnostics"].update({"bpf_probe_read_failures": 1}),
            "bpf_probe_read_failures must be 0",
        ),
        (
            "request parent",
            lambda document: document["spans"][0].update({"parent_span_id": "2" * 16}),
            "request span",
        ),
        (
            "rados reason",
            lambda document: document["spans"][1]["attributes"].append(
                attr("rgw.correlation_reason", "missing_trans_id")
            ),
            "unexpected rgw.correlation_reason",
        ),
        (
            "background event",
            lambda document: document["spans"][2]["events"][0].update({"time_ns": 421}),
            "event time_ns does not match",
        ),
        (
            "diagnostics breakdown",
            lambda document: document["diagnostics"]["background_rados_by_role"].update({"notify": 2}),
            "background_rados_by_role counts",
        ),
        (
            "workload request marker",
            lambda document: document["spans"][0]["attributes"][2].update({"value": "rados_bounds"}),
            "missing RGW request markers",
        ),
        (
            # A span claiming a measured duration whose end_ns does not equal the
            # measured end is a LIE about provenance: it must fail.
            "measured end must match the span end",
            lambda document: document["spans"][0]["attributes"][5].update({"value": 999}),
            "claims measured but end_ns",
        ),
        (
            # ...and so is one whose START was stretched off the measured start
            # (the backward extension to an early child). Both boundaries carry
            # provenance, so both must match for a span to claim `measured`.
            "measured start must match the span start",
            lambda document: document["spans"][0]["attributes"][4].update({"value": 999}),
            "claims measured but start_ns",
        ),
        (
            # Any span with a request marker must expose its measured start.
            "marker-bearing span must carry a measured start",
            lambda document: document["spans"][0]["attributes"].pop(4),
            "has no rgw.request.measured_start_ns",
        ),
        (
            # A derived (`marker`) span must not carry a measured end.
            "derived span must not carry a measured end",
            lambda document: document["spans"][0]["attributes"][2].update({"value": "marker"}),
            "carries rgw.request.measured_end_ns",
        ),
        (
            # The duration-provenance counters must match the rendered spans.
            "measured duration counter",
            lambda document: document["diagnostics"].update({"measured_duration_requests": 0}),
            "measured_duration_requests=0",
        ),
        (
            # A measured span with no END marker decoded is impossible.
            "measured spans require end markers",
            lambda document: document["diagnostics"].update(
                {"request_end_markers": 0, "events_decoded": 3}
            ),
            "request_end_markers",
        ),
    ]

    for name, mutate, expected_error in cases:
        document = valid_self_test_document()
        mutate(document)
        _, errors = verify_document(args, document, workload)
        if not any(expected_error in error for error in errors):
            print(f"SELF-TEST ERROR: {name} case did not fail with {expected_error!r}", file=sys.stderr)
            print(json.dumps(errors, indent=2, sort_keys=True), file=sys.stderr)
            return 1

    if run_manifest_self_test() != 0:
        return 1

    if run_list_shard_self_test() != 0:
        return 1

    if run_jsonl_self_test() != 0:
        return 1

    print("verify-rgwtrace-json self-test passed")
    return 0


def main():
    args = parse_args()
    if args.self_test:
        return run_self_test()

    document, stream_errors = load_trace(args.trace, args.trace_format)
    workload = load_workload(args.workload)
    manifest = load_manifest(args.workload_manifest) if args.workload_manifest else None
    summary, errors = verify_document(args, document, workload, manifest)
    errors = stream_errors + errors
    print(json.dumps(summary, indent=2, sort_keys=True))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
