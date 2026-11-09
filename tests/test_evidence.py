import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.reproduce import concurrent, in_flight, sequential, source_hashes
from experiments.verify import verify


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = {
            "schema_version": 1,
            "metadata": {"source_sha256": source_hashes()},
            "sequential": sequential(),
            "concurrency": [concurrent(7, 128), concurrent(64, 14)],
            "in_flight_revocation": in_flight(),
        }

    def test_verify(self):
        verify(self.report)
        cases = self.report["sequential"]
        self.assertEqual(25, len(cases))
        self.assertEqual(22, sum(not case["decision"]["allowed"] for case in cases))

    def test_reject_tampering(self):
        paths = [
            ("schema_version",),
            ("metadata", "source_sha256"),
            ("sequential", 0, "after"),
            ("sequential", 0, "after_sha256"),
            ("sequential", 3, "decision", "reason"),
            ("concurrency", 0, "initial_calls"),
            ("concurrency", 0, "initial_bytes"),
            ("concurrency", 0, "attempts"),
            ("concurrency", 0, "workers"),
            ("concurrency", 0, "decisions"),
            ("concurrency", 1, "decisions", 0, "remaining_bytes"),
            ("concurrency", 1, "admitted"),
            ("concurrency", 1, "denied"),
            ("concurrency", 1, "after"),
            ("in_flight_revocation", "before_completion"),
            ("in_flight_revocation", "after_completion"),
            ("in_flight_revocation", "result"),
            ("in_flight_revocation", "decisions"),
        ]
        for path in paths:
            with self.subTest(path=path):
                report = copy.deepcopy(self.report)
                target = report
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = "tampered"
                with self.assertRaises(ValueError):
                    verify(report)
        report = copy.deepcopy(self.report)
        report["concurrency"].pop()
        with self.assertRaises(ValueError):
            verify(report)

    def test_verifier_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(self.report), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "experiments.verify", str(path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(result.stdout)["verified"])
            for invalid in ["{", "{}", "null"]:
                path.write_text(invalid, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-m", "experiments.verify", str(path)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(2, result.returncode)
            path.unlink()
            result = subprocess.run(
                [sys.executable, "-m", "experiments.verify", str(path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(2, result.returncode)
