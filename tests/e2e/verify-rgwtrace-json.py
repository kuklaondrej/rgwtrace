#!/usr/bin/env python3
import argparse
import json
import sys


def parse_args():
    parser = argparse.ArgumentParser(description="Verify rgwtrace JSON from a live RGW e2e run")
    parser.add_argument("--trace", required=True)
    parser.add_argument("--workload", required=True)
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
    return parser.parse_args()


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


def main():
    args = parse_args()
    errors = []
    document = load_json(args.trace)
    workload = load_workload(args.workload)

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

    if diagnostics.get("decode_errors", 0) != 0:
        fail(errors, f"decode_errors must be 0, got {diagnostics.get('decode_errors')}")
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

    if len(request_spans) < args.min_request_spans:
        fail(errors, f"expected at least {args.min_request_spans} rgw.request spans, got {len(request_spans)}")
    if len(rados_spans) < args.min_rados_spans:
        fail(errors, f"expected at least {args.min_rados_spans} rados.op spans, got {len(rados_spans)}")

    for span in request_spans:
        attrs = attr_map(span)
        if attrs.get("rgw.request_class") != "s3_request":
            fail(errors, f"request span {span.get('span_id')} has rgw.request_class={attrs.get('rgw.request_class')!r}")
        if not attrs.get("rgw.trans_id"):
            fail(errors, f"request span {span.get('span_id')} has empty rgw.trans_id")
        if attrs.get("rgw.duration_quality") not in {"marker", "request_lifecycle", "rados_bounds"}:
            fail(errors, f"request span {span.get('span_id')} has invalid rgw.duration_quality={attrs.get('rgw.duration_quality')!r}")
        if span.get("start_ns", 0) > span.get("end_ns", 0):
            fail(errors, f"request span {span.get('span_id')} has start_ns > end_ns")

    roles = set()
    rados_objects = []
    for span in rados_spans:
        attrs = attr_map(span)
        roles.add(attrs.get("rgw.rados_role"))
        rados_objects.append(str(attrs.get("ceph.rados.object", "")))
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
        if not attrs.get("ceph.rados.object"):
            fail(errors, f"rados.op span {span.get('span_id')} has empty ceph.rados.object")
        if not attrs.get("ceph.rados.ops"):
            fail(errors, f"rados.op span {span.get('span_id')} has empty ceph.rados.ops")

    for span in background_spans:
        attrs = attr_map(span)
        roles.add(attrs.get("rgw.rados_role"))
        rados_objects.append(str(attrs.get("ceph.rados.object", "")))
        if span.get("parent_span_id") is not None:
            fail(errors, f"background span {span.get('span_id')} unexpectedly has a parent")
        if attrs.get("rgw.correlation") != "none":
            fail(errors, f"background span {span.get('span_id')} has rgw.correlation={attrs.get('rgw.correlation')!r}")
        if attrs.get("rgw.correlation_reason") not in {
            "missing_trans_id",
            "classified_background_role",
            "no_inference_candidate",
            "ambiguous_inference_candidates",
        }:
            fail(errors, f"background span {span.get('span_id')} is missing rgw.correlation_reason")
        if not span.get("events"):
            fail(errors, f"background span {span.get('span_id')} is missing its rados.op event")

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
    print(json.dumps(summary, indent=2, sort_keys=True))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
