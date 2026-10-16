"""Regression checks for mandatory live-test evidence; no cluster needed."""
import importlib.util
import argparse
import subprocess
import sys
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("verifier", Path(__file__).with_name("verify-rgwtrace-json.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class RequiredCoverageTests(unittest.TestCase):
    def verify_shards(self, document, manifest=None):
        args = v.self_test_args()
        args.require_list_shards = 3
        return v.verify_document(args, document, v.list_shard_self_test_workload(),
                                 v.list_shard_self_test_manifest() if manifest is None else manifest)[1]

    def test_required_shards_pass_with_all_shards(self):
        self.assertEqual(self.verify_shards(v.list_shard_self_test_document(True)), [])

    def test_required_shards_cannot_skip(self):
        errors = self.verify_shards(v.list_shard_self_test_document(True, shards=1))
        self.assertTrue(any("required list shards" in error for error in errors), errors)

    def test_partial_shard_loss_fails_even_above_old_two_shard_gate(self):
        errors = self.verify_shards(v.list_shard_self_test_document(True, shards=2))
        self.assertTrue(any("required list shards" in error for error in errors), errors)

    def test_missing_list_manifest_fails(self):
        errors = self.verify_shards(v.list_shard_self_test_document(True), [])
        self.assertTrue(any("required list shards" in error for error in errors), errors)

    def test_duplicate_shard_objects_do_not_mask_a_missing_shard(self):
        document = v.list_shard_self_test_document(True)
        shards = [span for span in document["spans"] if v.is_bucket_list_span(span)]
        for item in shards[-1]["attributes"]:
            if item["key"] == "ceph.rados.object":
                item["value"] = v.attr_map(shards[0])["ceph.rados.object"]
        errors = self.verify_shards(document)
        self.assertTrue(any("required list shards" in error for error in errors), errors)

    def test_every_list_needs_coverage(self):
        manifest = v.list_shard_self_test_manifest()
        second = dict(next(record for record in manifest if record["op"] == "LIST"))
        second["x_amz_request_id"] = "unobserved-list"
        errors = self.verify_shards(v.list_shard_self_test_document(True), manifest + [second])
        self.assertTrue(any("required list shards" in error for error in errors), errors)

    def test_cross_thread_evidence_passes(self):
        args = v.self_test_args()
        args.require_cross_thread = True
        document = v.cross_thread_self_test_document()
        document["diagnostics"]["bpf_operate_seed_hits"] = 1
        _, errors = v.verify_document(args, document, v.valid_self_test_workload())
        self.assertEqual(errors, [])

    def test_no_end_fallback_passes(self):
        args = v.self_test_args()
        args.request_end = "absent"
        _, errors = v.verify_document(args, v.derived_duration_self_test_document(), v.valid_self_test_workload())
        self.assertEqual(errors, [])

    def test_no_end_rejects_per_submit_reseeding(self):
        args = v.self_test_args()
        args.request_end = "absent"
        document = v.derived_duration_self_test_document()
        document["diagnostics"]["bpf_operate_seed_hits"] = 1
        _, errors = v.verify_document(args, document, v.valid_self_test_workload())
        self.assertTrue(any("absent request-END" in error for error in errors), errors)

    def test_explicit_zero_shard_requirement_is_rejected(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("verify-rgwtrace-json.py")),
             "--self-test", "--require-list-shards", "0"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be at least 2", result.stderr)

    def test_rate_requirements_cannot_be_zero_nan_or_infinite(self):
        for value in ("0", "-0.1", "1.1", "nan", "inf", "-inf"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                v.correlation_rate(value)
        self.assertEqual(v.correlation_rate("0.8"), 0.8)
        self.assertEqual(v.correlation_rate("1"), 1)

    def test_cross_thread_requires_actual_activity(self):
        args = v.self_test_args()
        args.require_cross_thread = True
        _, errors = v.verify_document(args, v.valid_self_test_document(), v.valid_self_test_workload())
        self.assertTrue(any("required cross-thread" in error for error in errors), errors)

    def test_request_end_requirement_cannot_degrade_silently(self):
        args = v.self_test_args()
        args.request_end = "present"
        _, errors = v.verify_document(args, v.derived_duration_self_test_document(), v.valid_self_test_workload())
        self.assertTrue(any("required request-END" in error for error in errors), errors)

    def test_no_end_profile_rejects_attached_end(self):
        args = v.self_test_args()
        args.request_end = "absent"
        _, errors = v.verify_document(args, v.valid_self_test_document(), v.valid_self_test_workload())
        self.assertTrue(any("absent request-END" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
