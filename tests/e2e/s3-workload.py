#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
import io
import json
import math
import subprocess
import threading
import time
import uuid

import boto3
from botocore.config import Config


def parse_args():
    parser = argparse.ArgumentParser(description="Drive deterministic S3 traffic for rgwtrace e2e")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--access-key", required=True)
    parser.add_argument("--secret-key", required=True)
    parser.add_argument("--bucket", default=None)
    parser.add_argument("--bucket-shards", type=int, default=0,
                        help="reshard the functional-test bucket before traffic (requires local RGW admin)")
    parser.add_argument("--rgw-admin", default="radosgw-admin")
    parser.add_argument("--output", required=True, help="per-operation workload JSONL log")
    parser.add_argument(
        "--manifest",
        default=None,
        help="write a machine-readable manifest (JSON) consumed by "
        "verify-rgwtrace-json.py --workload-manifest for the object->request cross-check",
    )
    parser.add_argument(
        "--concurrent-requests",
        type=int,
        default=4,
        help="number of concurrent PUT+GET object round-trips to drive (0 disables)",
    )
    parser.add_argument(
        "--unique-keys",
        action="store_true",
        help="give every object a run-unique key so the object->request mapping is "
        "unambiguous (recommended when arming the correlation gate)",
    )
    # --- benchmark mode (additive; --requests 0 keeps the historical functional
    # workload untouched so the e2e test's behaviour is unchanged) ---------------
    parser.add_argument(
        "--requests",
        type=int,
        default=0,
        help="benchmark mode: total number of measured PUT/GET requests to drive "
        "with a fixed op mix and object size (0 = run the functional workload instead)",
    )
    parser.add_argument(
        "--object-size",
        type=int,
        default=4096,
        help="benchmark mode: object payload size in bytes (default 4096)",
    )
    parser.add_argument(
        "--put-fraction",
        type=float,
        default=0.5,
        help="benchmark mode: fraction of requests that are PUTs (0..1, default 0.5); "
        "the remainder are GETs of pre-seeded objects",
    )
    parser.add_argument(
        "--seed-objects",
        type=int,
        default=0,
        help="benchmark mode: number of objects to pre-seed for GETs and PUT overwrites "
        "(0 = derive from --concurrent-requests)",
    )
    parser.add_argument(
        "--summary",
        default=None,
        help="write an aggregate latency/throughput summary (JSON) for this run; "
        "the A/B benchmark harness pools these across phases",
    )
    parser.add_argument(
        "--bench-phase",
        choices=("all", "prepare", "run", "cleanup"),
        default="all",
        help="benchmark mode split: 'prepare' creates+seeds the bucket, 'run' drives "
        "only the measured request window, 'cleanup' deletes; 'all' (default) does "
        "everything in one process. The A/B harness uses prepare/run/cleanup so the "
        "server-side CPU delta brackets only measured traffic",
    )
    parser.add_argument(
        "--bench-state",
        default=None,
        help="benchmark mode: path to the JSON state file shared between "
        "--bench-phase prepare/run/cleanup (bucket name + seed keys)",
    )
    return parser.parse_args()


def request_id_from_response(response):
    if not isinstance(response, dict):
        return None

    metadata = response.get("ResponseMetadata") or {}
    headers = metadata.get("HTTPHeaders") or {}
    return headers.get("x-amz-request-id") or metadata.get("RequestId")


class Recorder:
    """Collects per-op records for both the JSONL workload log and the manifest.

    The JSONL log keeps its historical shape (name/bucket/key/start_ns/end_ns/
    status/x_amz_request_id/error). The manifest adds an op classification
    (GET/PUT/OTHER) and rw (read/write) so the verifier can map RADOS spans to
    the request that operated on a given object.
    """

    def __init__(self, handle, buffered=False):
        self._handle = handle
        self._lock = threading.Lock()
        self._manifest_records = []
        # In buffered mode (benchmark) the per-op JSONL lines are held in memory
        # and written once, AFTER the timed section, so file I/O and its flush do
        # not fall inside the measured throughput window. Functional mode keeps
        # its historical per-op flush (buffered=False).
        self._buffered = buffered
        self._workload_buffer = []

    def record(self, name, bucket, key, start_ns, end_ns, status, op, rw, request_id=None, error=None):
        workload_record = {
            "name": name,
            "bucket": bucket,
            "key": key,
            "start_ns": start_ns,
            "end_ns": end_ns,
            "status": status,
        }
        if request_id:
            workload_record["x_amz_request_id"] = request_id
        if error:
            workload_record["error"] = error

        manifest_record = dict(workload_record)
        manifest_record["op"] = op
        manifest_record["rw"] = rw

        with self._lock:
            self._manifest_records.append(manifest_record)
            if self._buffered:
                self._workload_buffer.append(workload_record)
            else:
                self._handle.write(json.dumps(workload_record, sort_keys=True) + "\n")
                self._handle.flush()

    def flush_buffered(self):
        """Write all buffered workload lines (benchmark mode, post-timing)."""
        with self._lock:
            for record in self._workload_buffer:
                self._handle.write(json.dumps(record, sort_keys=True) + "\n")
            self._handle.flush()
            self._workload_buffer = []

    def manifest_records(self):
        with self._lock:
            return list(self._manifest_records)


def run_op(recorder, name, bucket, key, fn, op="OTHER", rw=None):
    start_ns = time.time_ns()
    status = "ok"
    error = None
    request_id = None
    try:
        response = fn()
        request_id = request_id_from_response(response)
        return response
    except Exception as exc:
        status = "error"
        error = repr(exc)
        request_id = request_id_from_response(getattr(exc, "response", None))
        raise
    finally:
        recorder.record(name, bucket, key, start_ns, time.time_ns(), status, op, rw, request_id, error)


def make_client(args):
    return boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def run_concurrent_object_roundtrip(args, recorder, bucket, key, index):
    client = make_client(args)
    run_op(
        recorder,
        f"concurrent_put_{index}",
        bucket,
        key,
        lambda: client.put_object(
            Bucket=bucket,
            Key=key,
            Body=(f"rgwtrace concurrent payload {index}\n").encode("utf-8"),
        ),
        op="PUT",
        rw="write",
    )

    def get_object():
        response = client.get_object(Bucket=bucket, Key=key)
        try:
            response["Body"].read()
        finally:
            response["Body"].close()
        return response

    run_op(recorder, f"concurrent_get_{index}", bucket, key, get_object, op="GET", rw="read")
    return key


def _percentile(sorted_values, quantile):
    """Linear-interpolated percentile over an already-sorted list (microseconds)."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * quantile
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return sorted_values[lo]
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def _latency_stats(latencies_us):
    values = sorted(latencies_us)
    stats = {
        "count": len(values),
        "min_us": values[0] if values else None,
        "max_us": values[-1] if values else None,
        "mean_us": (sum(values) / len(values)) if values else None,
        "p50_us": _percentile(values, 0.50),
        "p95_us": _percentile(values, 0.95),
        "p99_us": _percentile(values, 0.99),
        # Raw latencies are retained so a caller (the A/B harness) can pool
        # samples across repeats and recompute true pooled percentiles.
        "latencies_us": values,
    }
    return stats


def build_summary(records, wall_ns, args, bucket, mode):
    """Aggregate per-op latency percentiles and throughput from recorded ops.

    Only status=="ok" ops are counted. "ALL" pools PUT and GET (the measured
    request mix); setup/teardown ops (bucket create/delete, classified OTHER)
    are reported under their own op key but excluded from "ALL".
    """
    by_op = {}
    for record in records:
        if record.get("status") != "ok":
            continue
        start_ns = record.get("start_ns")
        end_ns = record.get("end_ns")
        if start_ns is None or end_ns is None:
            continue
        op = record.get("op") or "OTHER"
        by_op.setdefault(op, []).append((end_ns - start_ns) / 1000.0)

    ops = {op: _latency_stats(latencies) for op, latencies in by_op.items()}
    measured = []
    for op in ("PUT", "GET"):
        measured.extend(by_op.get(op, []))
    ops["ALL"] = _latency_stats(measured)

    wall_s = wall_ns / 1e9 if wall_ns else 0.0
    throughput_rps = (len(measured) / wall_s) if wall_s > 0 else None
    return {
        "version": 1,
        "mode": mode,
        "bucket": bucket,
        "requests": args.requests,
        "concurrency": max(0, args.concurrent_requests),
        "object_size": args.object_size,
        "put_fraction": args.put_fraction,
        "wall_ns": wall_ns,
        "throughput_rps": throughput_rps,
        "ops": ops,
    }


def write_summary(path, summary):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _benchmark_op_plan(args, seed_keys):
    """Build a deterministic (op, key) plan of length args.requests.

    PUTs overwrite keys from the bounded seed pool (so cleanup is trivial and
    object count stays fixed); GETs read from the same pool. The mix is laid out
    deterministically from --put-fraction so a run is reproducible.
    """
    total = max(0, args.requests)
    put_target = int(round(total * min(max(args.put_fraction, 0.0), 1.0)))
    plan = []
    puts = 0
    for index in range(total):
        # Deterministic Bresenham-style interleave of PUTs across the sequence.
        want_put = int(round((index + 1) * put_target / total)) > puts if total else False
        key = seed_keys[index % len(seed_keys)]
        if want_put:
            plan.append(("PUT", key))
            puts += 1
        else:
            plan.append(("GET", key))
    return plan


def _seed_keys(args):
    concurrency = max(1, args.concurrent_requests)
    seed_count = args.seed_objects if args.seed_objects > 0 else max(concurrency, 1)
    return [f"bench-obj-{index}" for index in range(seed_count)]


def _run_benchmark_worker(client, plan_slice, recorder, bucket, payload, worker_index):
    for op_index, (op, key) in enumerate(plan_slice):
        if op == "PUT":
            run_op(
                recorder,
                f"bench_put_w{worker_index}_{op_index}",
                bucket,
                key,
                lambda key=key: client.put_object(Bucket=bucket, Key=key, Body=payload),
                op="PUT",
                rw="write",
            )
        else:
            def get_object(key=key):
                response = client.get_object(Bucket=bucket, Key=key)
                try:
                    response["Body"].read()
                finally:
                    response["Body"].close()
                return response

            run_op(
                recorder,
                f"bench_get_w{worker_index}_{op_index}",
                bucket,
                key,
                get_object,
                op="GET",
                rw="read",
            )


def bench_prepare(args, bucket):
    """Create the bucket and seed objects (unmeasured). Returns the seed keys."""
    client = make_client(args)
    client.create_bucket(Bucket=bucket)
    payload = b"\0" * max(0, args.object_size)
    seed_keys = _seed_keys(args)
    for key in seed_keys:
        client.put_object(Bucket=bucket, Key=key, Body=payload)
    return seed_keys


def bench_run(args, recorder, bucket, seed_keys):
    """Drive only the measured request window and return its wall time (ns).

    All boto3 clients are constructed and the thread pool is pre-warmed BEFORE
    the timer starts, and per-op JSONL is buffered (see Recorder), so the timed
    window contains request work only -- not client/thread setup or file I/O.
    """
    payload = b"\0" * max(0, args.object_size)
    concurrency = max(1, args.concurrent_requests)
    plan = _benchmark_op_plan(args, seed_keys)
    slices = [plan[worker::concurrency] for worker in range(concurrency)]

    clients = [make_client(args) for _ in range(concurrency)]
    executor = ThreadPoolExecutor(max_workers=concurrency)
    try:
        # Force worker threads to spin up before the timed section.
        list(executor.map(lambda _idx: None, range(concurrency)))
        start_ns = time.time_ns()
        if args.requests > 0:
            futures = [
                executor.submit(
                    _run_benchmark_worker,
                    clients[worker],
                    slices[worker],
                    recorder,
                    bucket,
                    payload,
                    worker,
                )
                for worker in range(concurrency)
            ]
            for future in futures:
                future.result()
        wall_ns = time.time_ns() - start_ns
    finally:
        executor.shutdown(wait=True)
    return wall_ns


def bench_cleanup(args, bucket, seed_keys):
    """Delete seed objects and the bucket (unmeasured)."""
    client = make_client(args)
    for key in seed_keys:
        try:
            client.delete_object(Bucket=bucket, Key=key)
        except Exception:
            pass
    try:
        client.delete_bucket(Bucket=bucket)
    except Exception:
        pass


def write_bench_state(path, bucket, seed_keys):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"bucket": bucket, "seed_keys": seed_keys}, handle, sort_keys=True)
        handle.write("\n")


def read_bench_state(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def write_manifest(path, args, bucket, recorder):
    document = {
        "version": 1,
        "bucket": bucket,
        "unique_keys": bool(args.unique_keys),
        "concurrent_requests": max(0, args.concurrent_requests),
        "operations": recorder.manifest_records(),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main():
    args = parse_args()

    if args.requests > 0:
        phase = args.bench_phase

        if phase == "prepare":
            # Validate before any network side effect: preparing without a state
            # path would create and seed a bucket that no cleanup phase can find.
            if not args.bench_state:
                raise SystemExit("--bench-phase prepare requires --bench-state")
            bucket = args.bucket or f"rgwtrace-bench-{uuid.uuid4().hex[:12]}"
            seed_keys = bench_prepare(args, bucket)
            write_bench_state(args.bench_state, bucket, seed_keys)
            return

        if phase == "cleanup":
            if not args.bench_state:
                raise SystemExit("--bench-phase cleanup requires --bench-state")
            state = read_bench_state(args.bench_state)
            bench_cleanup(args, state["bucket"], state["seed_keys"])
            return

        if phase == "run":
            if not args.bench_state:
                raise SystemExit("--bench-phase run requires --bench-state")
            state = read_bench_state(args.bench_state)
            bucket, seed_keys = state["bucket"], state["seed_keys"]
            with open(args.output, "w", encoding="utf-8") as handle:
                recorder = Recorder(handle, buffered=True)
                wall_ns = bench_run(args, recorder, bucket, seed_keys)
                recorder.flush_buffered()
        else:  # phase == "all": single-shot prepare+run+cleanup
            bucket = args.bucket or f"rgwtrace-bench-{uuid.uuid4().hex[:12]}"
            with open(args.output, "w", encoding="utf-8") as handle:
                recorder = Recorder(handle, buffered=True)
                seed_keys = bench_prepare(args, bucket)
                wall_ns = bench_run(args, recorder, bucket, seed_keys)
                recorder.flush_buffered()
                bench_cleanup(args, bucket, seed_keys)

        summary = build_summary(recorder.manifest_records(), wall_ns, args, bucket, "benchmark")
        if args.summary:
            write_summary(args.summary, summary)
        if args.manifest:
            write_manifest(args.manifest, args, bucket, recorder)
        return

    bucket = args.bucket or f"rgwtrace-e2e-{uuid.uuid4().hex[:12]}"
    # A run token keeps object keys unique across requests (and across runs) so
    # the verifier's object->request mapping is unambiguous when --unique-keys is set.
    token = uuid.uuid4().hex[:12] if args.unique_keys else None

    def keyed(base, suffix):
        return f"{base}-{token}{suffix}" if token else f"{base}{suffix}"

    alpha_key = keyed("alpha", ".txt")
    copy_key = keyed("copy-alpha", ".txt")
    multipart_key = keyed("multipart", ".bin")
    concurrent_count = max(0, args.concurrent_requests)
    concurrent_keys = [keyed(f"concurrent-{index}", ".txt") for index in range(concurrent_count)]
    uploaded_keys = set()
    bucket_deleted = False

    client = make_client(args)

    with open(args.output, "w", encoding="utf-8") as handle:
        recorder = Recorder(handle)
        try:
            run_op(recorder, "create_bucket", bucket, None, lambda: client.create_bucket(Bucket=bucket))

            if args.bucket_shards:
                if args.bucket_shards < 2:
                    raise ValueError("--bucket-shards must be at least 2")
                subprocess.run([args.rgw_admin, "bucket", "reshard", "--bucket", bucket,
                                "--num-shards", str(args.bucket_shards), "--yes-i-really-mean-it"],
                               check=True, capture_output=True, text=True)
                stats = subprocess.run([args.rgw_admin, "bucket", "stats", "--bucket", bucket],
                                       check=True, capture_output=True, text=True)
                if json.loads(stats.stdout).get("num_shards") != args.bucket_shards:
                    raise RuntimeError("RGW bucket shard count does not match the requested test fixture")

            run_op(
                recorder,
                "put_object",
                bucket,
                alpha_key,
                lambda: client.put_object(
                    Bucket=bucket,
                    Key=alpha_key,
                    Body=b"rgwtrace alpha payload\n",
                ),
                op="PUT",
                rw="write",
            )
            uploaded_keys.add(alpha_key)

            run_op(recorder, "head_object", bucket, alpha_key, lambda: client.head_object(Bucket=bucket, Key=alpha_key))

            def get_alpha():
                response = client.get_object(Bucket=bucket, Key=alpha_key)
                try:
                    response["Body"].read()
                finally:
                    response["Body"].close()
                return response

            run_op(recorder, "get_object", bucket, alpha_key, get_alpha, op="GET", rw="read")
            # Classified as LIST (not OTHER) so the verifier can arm its list-shard
            # gate: RGW serves a bucket listing as ONE `call(rgw.bucket_list)` per
            # bucket-index SHARD, submitted through the cls_rgw AIO path -- a submit
            # path that never reaches `rgw_rados_operate`, and whose correlation is
            # therefore not covered by any GET/PUT assertion.
            #
            # No Prefix: a prefixed list can be served from fewer shards, and the gate
            # needs the listing to actually fan out across the bucket index.
            run_op(
                recorder,
                "list_objects",
                bucket,
                None,
                lambda: client.list_objects_v2(Bucket=bucket),
                op="LIST",
                rw="read",
            )

            run_op(
                recorder,
                "copy_object",
                bucket,
                copy_key,
                lambda: client.copy_object(
                    Bucket=bucket,
                    CopySource={"Bucket": bucket, "Key": alpha_key},
                    Key=copy_key,
                ),
            )
            uploaded_keys.add(copy_key)

            upload = run_op(
                recorder,
                "create_multipart_upload",
                bucket,
                multipart_key,
                lambda: client.create_multipart_upload(Bucket=bucket, Key=multipart_key),
            )
            upload_id = upload["UploadId"]
            parts = []
            try:
                for part_number, byte in [(1, b"a"), (2, b"b")]:
                    body = io.BytesIO(byte * (5 * 1024 * 1024))
                    response = run_op(
                        recorder,
                        f"upload_part_{part_number}",
                        bucket,
                        multipart_key,
                        lambda part_number=part_number, body=body: client.upload_part(
                            Bucket=bucket,
                            Key=multipart_key,
                            UploadId=upload_id,
                            PartNumber=part_number,
                            Body=body,
                        ),
                        op="PUT",
                        rw="write",
                    )
                    parts.append({"ETag": response["ETag"], "PartNumber": part_number})
                run_op(
                    recorder,
                    "complete_multipart_upload",
                    bucket,
                    multipart_key,
                    lambda: client.complete_multipart_upload(
                        Bucket=bucket,
                        Key=multipart_key,
                        UploadId=upload_id,
                        MultipartUpload={"Parts": parts},
                    ),
                )
            except Exception:
                client.abort_multipart_upload(Bucket=bucket, Key=multipart_key, UploadId=upload_id)
                raise
            uploaded_keys.add(multipart_key)

            if concurrent_count:
                with ThreadPoolExecutor(max_workers=concurrent_count) as executor:
                    futures = [
                        executor.submit(
                            run_concurrent_object_roundtrip,
                            args,
                            recorder,
                            bucket,
                            concurrent_keys[index],
                            index,
                        )
                        for index in range(concurrent_count)
                    ]
                    for future in futures:
                        uploaded_keys.add(future.result())

            for key in [copy_key, alpha_key, multipart_key, *concurrent_keys]:
                run_op(recorder, "delete_object", bucket, key, lambda key=key: client.delete_object(Bucket=bucket, Key=key))
                uploaded_keys.discard(key)

            run_op(recorder, "delete_bucket", bucket, None, lambda: client.delete_bucket(Bucket=bucket))
            bucket_deleted = True
        finally:
            for key in sorted(uploaded_keys):
                try:
                    client.delete_object(Bucket=bucket, Key=key)
                except Exception:
                    pass
            if not bucket_deleted:
                try:
                    client.delete_bucket(Bucket=bucket)
                except Exception:
                    pass
            if args.manifest:
                write_manifest(args.manifest, args, bucket, recorder)
            if args.summary:
                records = recorder.manifest_records()
                starts = [r["start_ns"] for r in records if r.get("start_ns") is not None]
                ends = [r["end_ns"] for r in records if r.get("end_ns") is not None]
                wall_ns = (max(ends) - min(starts)) if starts and ends else 0
                write_summary(args.summary, build_summary(records, wall_ns, args, bucket, "functional"))


if __name__ == "__main__":
    main()
