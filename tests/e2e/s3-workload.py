#!/usr/bin/env python3
import argparse
import io
import json
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
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def write_record(handle, name, bucket, key, start_ns, end_ns, status, error=None):
    record = {
        "name": name,
        "bucket": bucket,
        "key": key,
        "start_ns": start_ns,
        "end_ns": end_ns,
        "status": status,
    }
    if error:
        record["error"] = error
    handle.write(json.dumps(record, sort_keys=True) + "\n")
    handle.flush()


def run_op(handle, name, bucket, key, fn):
    start_ns = time.time_ns()
    status = "ok"
    error = None
    try:
        return fn()
    except Exception as exc:
        status = "error"
        error = repr(exc)
        raise
    finally:
        write_record(handle, name, bucket, key, start_ns, time.time_ns(), status, error)


def main():
    args = parse_args()
    bucket = args.bucket or f"rgwtrace-e2e-{uuid.uuid4().hex[:12]}"
    alpha_key = "alpha.txt"
    copy_key = "copy-alpha.txt"
    multipart_key = "multipart.bin"
    uploaded_keys = set()

    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )

    with open(args.output, "w", encoding="utf-8") as handle:
        try:
            run_op(handle, "create_bucket", bucket, None, lambda: client.create_bucket(Bucket=bucket))

            run_op(
                handle,
                "put_object",
                bucket,
                alpha_key,
                lambda: client.put_object(
                    Bucket=bucket,
                    Key=alpha_key,
                    Body=b"rgwtrace alpha payload\n",
                ),
            )
            uploaded_keys.add(alpha_key)

            run_op(handle, "head_object", bucket, alpha_key, lambda: client.head_object(Bucket=bucket, Key=alpha_key))

            def get_alpha():
                response = client.get_object(Bucket=bucket, Key=alpha_key)
                response["Body"].read()

            run_op(handle, "get_object", bucket, alpha_key, get_alpha)
            run_op(handle, "list_objects", bucket, None, lambda: client.list_objects_v2(Bucket=bucket, Prefix="alpha"))

            run_op(
                handle,
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

            def multipart_upload():
                upload = client.create_multipart_upload(Bucket=bucket, Key=multipart_key)
                upload_id = upload["UploadId"]
                parts = []
                try:
                    for part_number, byte in [(1, b"a"), (2, b"b")]:
                        body = io.BytesIO(byte * (5 * 1024 * 1024))
                        response = client.upload_part(
                            Bucket=bucket,
                            Key=multipart_key,
                            UploadId=upload_id,
                            PartNumber=part_number,
                            Body=body,
                        )
                        parts.append({"ETag": response["ETag"], "PartNumber": part_number})
                    return client.complete_multipart_upload(
                        Bucket=bucket,
                        Key=multipart_key,
                        UploadId=upload_id,
                        MultipartUpload={"Parts": parts},
                    )
                except Exception:
                    client.abort_multipart_upload(Bucket=bucket, Key=multipart_key, UploadId=upload_id)
                    raise

            run_op(handle, "multipart_upload", bucket, multipart_key, multipart_upload)
            uploaded_keys.add(multipart_key)

            for key in [copy_key, alpha_key, multipart_key]:
                run_op(handle, "delete_object", bucket, key, lambda key=key: client.delete_object(Bucket=bucket, Key=key))
                uploaded_keys.discard(key)

            run_op(handle, "delete_bucket", bucket, None, lambda: client.delete_bucket(Bucket=bucket))
        finally:
            for key in sorted(uploaded_keys):
                try:
                    client.delete_object(Bucket=bucket, Key=key)
                except Exception:
                    pass
            try:
                client.delete_bucket(Bucket=bucket)
            except Exception:
                pass


if __name__ == "__main__":
    main()
