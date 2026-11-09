"""Replay fixed decisions and check concurrent ledger invariants without load."""

import argparse
import json
from pathlib import Path

from experiments.reproduce import sequential, source_hashes


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(report):
    require(report["schema_version"] == 1, "unsupported schema")
    require(
        report["metadata"]["source_sha256"] == source_hashes(), "source hash mismatch"
    )
    require(report["sequential"] == sequential(), "sequential replay mismatch")
    require(len(report["concurrency"]) == 2, "expected two budget cohorts")
    for record, (calls, byte_budget) in zip(
        report["concurrency"], [(7, 128), (64, 14)], strict=False
    ):
        require(record["initial_calls"] == calls, "initial calls mismatch")
        require(record["initial_bytes"] == byte_budget, "initial bytes mismatch")
        require(record["attempts"] == 64 and record["workers"] == 8, "cohort mismatch")
        require(len(record["decisions"]) == 64, "missing decisions")
        admitted = 0
        for sequence, decision in enumerate(record["decisions"], 1):
            allowed = calls > 0 and byte_budget >= 2
            reason = (
                "allowed" if allowed else "call_budget" if calls == 0 else "byte_budget"
            )
            if allowed:
                calls -= 1
                byte_budget -= 2
                admitted += 1
            require(
                decision
                == {
                    "sequence": sequence,
                    "grant_id": 1,
                    "tool": "append",
                    "resource": "/owned/note",
                    "allowed": allowed,
                    "reason": reason,
                    "charged_bytes": 2 if allowed else 0,
                    "remaining_calls": calls,
                    "remaining_bytes": byte_budget,
                },
                "concurrent ledger mismatch",
            )
        require(record["admitted"] == admitted == 7, "admission total mismatch")
        require(record["denied"] == 57, "denial total mismatch")
        require(record["after"] == {"/owned/note": "ok" * 7}, "side effect mismatch")
    flight = report["in_flight_revocation"]
    require(flight["before_completion"] == {}, "effect before release")
    require(
        flight["after_completion"] == {"/owned/note": "ok"}, "in-flight effect mismatch"
    )
    require(flight["result"] == "ok", "in-flight result mismatch")
    require(
        flight["decisions"]
        == [
            {
                "sequence": 1,
                "grant_id": 1,
                "tool": "append",
                "resource": "/owned/note",
                "allowed": True,
                "reason": "allowed",
                "charged_bytes": 2,
                "remaining_calls": 1,
                "remaining_bytes": 2,
            },
            {
                "sequence": 2,
                "grant_id": 1,
                "tool": "append",
                "resource": None,
                "allowed": False,
                "reason": "revoked",
                "charged_bytes": 0,
                "remaining_calls": 1,
                "remaining_bytes": 2,
            },
        ],
        "in-flight decisions mismatch",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        verify(json.loads(args.report.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"verification failed: {exc}\n")
    print(json.dumps({"verified": True, "report": str(args.report)}))


if __name__ == "__main__":
    main()
