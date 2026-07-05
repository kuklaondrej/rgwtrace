#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
import io
import json
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

    def __init__(self, handle):
        self._handle = handle
        self._lock = threading.Lock()
        self._manifest_records = []

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

        line = json.dumps(workload_record, sort_keys=True) + "\n"
        with self._lock:
            self._handle.write(line)
            self._handle.flush()
            self._manifest_records.append(manifest_record)

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
            run_op(recorder, "list_objects", bucket, None, lambda: client.list_objects_v2(Bucket=bucket, Prefix="alpha"))

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


if __name__ == "__main__":
    main()
