#!/usr/bin/env python3
import argparse
from copy import deepcopy
import json
import sys
from types import SimpleNamespace


SPAN_NAMES = {"rgw.request", "rados.op", "rgw.background.rados_op"}
# Single-marker model: request_lifecycle is unattainable by contract (RGW has
# no safe request-completion probe), so only "marker" and "rados_bounds" occur.
VALID_DURATION_QUALITIES = {"marker", "rados_bounds"}
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
VALID_BACKGROUND_REASONS = {
    "missing_trans_id",
    "classified_background_role",
    "no_inference_candidate",
    "ambiguous_inference_candidates",
}
BPF_FAILURE_DIAGNOSTICS = [
    "bpf_ringbuf_request_drops",
    "bpf_ringbuf_rados_drops",
    "bpf_rados_map_drops",
    "bpf_request_context_drops",
    "bpf_probe_read_failures",
    "bpf_reqstate_map_drops",
]
RADOS_ATTRIBUTE_KEYS = [
    "ceph.rados.duration_ns",
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
    args = parser.parse_args()
    if not args.self_test and (not args.trace or not args.workload):
        parser.error("--trace and --workload are required unless --self-test is used")
    return args


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_workload(path):
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


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


def verify_document(args, document, workload):
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
    if diagnostics.get("events_decoded") != diagnostics.get("request_markers", 0) + diagnostics.get("rados_ops", 0):
        fail(errors, "events_decoded must equal request_markers + rados_ops")
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
    if diagnostics.get("rados_ops") != len(rados_spans) + len(background_spans):
        fail(errors, f"rados_ops={diagnostics.get('rados_ops')} but JSON has {len(rados_spans)} child and {len(background_spans)} background RADOS spans")
    if diagnostics.get("correlated_rados_ops") != len(rados_spans):
        fail(errors, f"correlated_rados_ops={diagnostics.get('correlated_rados_ops')} but JSON has {len(rados_spans)} rados.op spans")
    if diagnostics.get("background_rados_ops") != len(background_spans):
        fail(errors, f"background_rados_ops={diagnostics.get('background_rados_ops')} but JSON has {len(background_spans)} background spans")
    if diagnostics.get("same_thread_correlations", 0) + diagnostics.get("inferred_correlations", 0) != diagnostics.get("correlated_rados_ops"):
        fail(errors, "same_thread_correlations + inferred_correlations must equal correlated_rados_ops")
    if diagnostics.get("missing_trans_id_background_ops") != diagnostics.get("background_rados_ops"):
        fail(errors, "missing_trans_id_background_ops must equal background_rados_ops")
    for key in BPF_FAILURE_DIAGNOSTICS:
        if diagnostics.get(key, 0) != 0:
            fail(errors, f"{key} must be 0, got {diagnostics.get(key)}")

    if len(request_spans) < args.min_request_spans:
        fail(errors, f"expected at least {args.min_request_spans} rgw.request spans, got {len(request_spans)}")
    if len(rados_spans) < args.min_rados_spans:
        fail(errors, f"expected at least {args.min_rados_spans} rados.op spans, got {len(rados_spans)}")

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
        if attrs.get("rgw.duration_quality") not in VALID_DURATION_QUALITIES:
            fail(errors, f"request span {span.get('span_id')} has invalid rgw.duration_quality={attrs.get('rgw.duration_quality')!r}")

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
        if attrs.get("rgw.correlation") not in {"same_thread", "inferred"}:
            fail(errors, f"rados.op span {span.get('span_id')} has invalid rgw.correlation={attrs.get('rgw.correlation')!r}")
        if attrs.get("rgw.correlation") == "same_thread" and attrs.get("rgw.correlation_reason") is not None:
            fail(errors, f"rados.op span {span.get('span_id')} has unexpected rgw.correlation_reason")
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
        if missing_trace_ids:
            fail(errors, f"workload x-amz-request-id values missing from trace rgw.trans_id: {missing_trace_ids}")
        if unexpected_trace_ids:
            fail(errors, f"trace rgw.trans_id values without matching workload x-amz-request-id: {unexpected_trace_ids}")

    summary = {
        "spans": len(spans),
        "request_spans": len(request_spans),
        "rados_spans": len(rados_spans),
        "background_spans": len(background_spans),
        "workload_request_ids": workload_request_id_count,
        "trace_request_ids_in_window": trace_request_id_count,
        "roles": sorted(role for role in roles if role),
        "diagnostics": diagnostics,
    }
    return summary, errors


def self_test_args():
    return SimpleNamespace(
        min_request_spans=1,
        min_rados_spans=1,
        expect_role=["data"],
        expect_any_role=[],
        time_slack_ms=2000,
    )


def attr(key, value):
    return {"key": key, "value": value}


def valid_self_test_document():
    request_attrs = [
        attr("rgw.trans_id", "tx-selftest"),
        attr("rgw.request_class", "s3_request"),
        attr("rgw.duration_quality", "marker"),
    ]
    rados_attrs = [
        attr("ceph.rados.duration_ns", 60),
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
            "events_decoded": 3,
            "decode_errors": 0,
            "request_markers": 1,
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


def run_self_test():
    args = self_test_args()
    workload = valid_self_test_workload()
    summary, errors = verify_document(args, valid_self_test_document(), workload)
    if errors:
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"SELF-TEST ERROR: valid document failed: {error}", file=sys.stderr)
        return 1

    cases = [
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
    ]

    for name, mutate, expected_error in cases:
        document = valid_self_test_document()
        mutate(document)
        _, errors = verify_document(args, document, workload)
        if not any(expected_error in error for error in errors):
            print(f"SELF-TEST ERROR: {name} case did not fail with {expected_error!r}", file=sys.stderr)
            print(json.dumps(errors, indent=2, sort_keys=True), file=sys.stderr)
            return 1

    print("verify-rgwtrace-json self-test passed")
    return 0


def main():
    args = parse_args()
    if args.self_test:
        return run_self_test()

    document = load_json(args.trace)
    workload = load_workload(args.workload)
    summary, errors = verify_document(args, document, workload)
    print(json.dumps(summary, indent=2, sort_keys=True))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
