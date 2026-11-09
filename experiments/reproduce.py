"""Record a fixed adversarial matrix against owned in-memory resources."""

import argparse
import hashlib
import json
import platform
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from agent_capabilities import Argument, Broker, Denied, Scope
from agent_capabilities.synthetic import MemoryNotes

ROOT = Path(__file__).resolve().parents[1]
SCOPE = Scope("append", "/owned", {"text": Argument(8, frozenset({"ok", "yes"}))})
CASES = [
    ("valid", {}, "allowed"),
    ("canonical_alias", {"resource": "/owned//./note/"}, "allowed"),
    ("scope_root", {"resource": "/owned"}, "allowed"),
    ("wrong_tool", {"tool": "read"}, "tool_scope"),
    ("unregistered_tool", {"tool": "shell"}, "tool_scope"),
    ("sibling_prefix", {"resource": "/owned-evil/note"}, "resource_scope"),
    ("outside_resource", {"resource": "/secret"}, "resource_scope"),
    ("parent_traversal", {"resource": "/owned/../secret"}, "invalid_resource"),
    ("percent_escape", {"resource": "/owned/%2e%2e/secret"}, "invalid_resource"),
    ("backslash", {"resource": "/owned\\secret"}, "invalid_resource"),
    ("nul", {"resource": "/owned/\x00secret"}, "invalid_resource"),
    ("unicode_path", {"resource": "/owned/\u2215secret"}, "invalid_resource"),
    ("relative_path", {"resource": "owned/note"}, "invalid_resource"),
    ("extra_argument", {"arguments": {"text": "ok", "admin": "1"}}, "argument_schema"),
    ("missing_argument", {"arguments": {}}, "argument_schema"),
    ("wrong_type", {"arguments": {"text": 1}}, "argument_schema"),
    ("oversized_argument", {"arguments": {"text": "x" * 9}}, "argument_scope"),
    ("forbidden_choice", {"arguments": {"text": "delete"}}, "argument_scope"),
    ("invalid_utf8", {"arguments": {"text": "\ud800"}}, "argument_encoding"),
    ("forged_token", {"token": "0" * 64}, "unknown_capability"),
    ("malformed_token", {"token": "policy:allow-all"}, "unknown_capability"),
    ("revoked", {}, "revoked"),
    ("expired", {}, "expired"),
    ("no_calls", {}, "call_budget"),
    ("no_bytes", {}, "byte_budget"),
]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def sequential():
    records = []
    for name, override, expected in CASES:
        now = [0.0]
        store = MemoryNotes()
        broker = Broker(
            {"append": store.append, "read": store.read}, clock=lambda now=now: now[0]
        )
        token = broker.issue(
            SCOPE,
            calls=0 if name == "no_calls" else 2,
            bytes=0 if name == "no_bytes" else 8,
            ttl=1,
        )
        if name == "revoked":
            broker.revoke(token)
        if name == "expired":
            now[0] = 1.0
        request = {
            "token": token,
            "tool": "append",
            "resource": "/owned/note",
            "arguments": {"text": "ok"},
        } | override
        before = store.snapshot()
        try:
            broker.execute(**request)
        except Denied:
            pass
        after = store.snapshot()
        decision = asdict(broker.decisions()[-1])
        if decision["reason"] != expected or (
            expected != "allowed" and before != after
        ):
            raise RuntimeError(f"unexpected result in {name}")
        records.append(
            {
                "case": name,
                "request": {k: v for k, v in request.items() if k != "token"},
                "expected_reason": expected,
                "decision": decision,
                "before": before,
                "after": after,
                "before_sha256": digest(before),
                "after_sha256": digest(after),
            }
        )
    return records


def concurrent(calls, byte_budget, attempts=64, workers=8):
    store = MemoryNotes()
    broker = Broker({"append": store.append})
    token = broker.issue(SCOPE, calls=calls, bytes=byte_budget, ttl=60)
    barrier = threading.Barrier(workers)

    def attempt(_):
        barrier.wait(timeout=10)
        try:
            broker.execute(token, "append", "/owned/note", {"text": "ok"})
            return True
        except Denied:
            return False

    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(attempt, range(attempts)))
    return {
        "initial_calls": calls,
        "initial_bytes": byte_budget,
        "attempts": attempts,
        "workers": workers,
        "admitted": sum(outcomes),
        "denied": attempts - sum(outcomes),
        "after": store.snapshot(),
        "decisions": [asdict(d) for d in broker.decisions()],
    }


def in_flight():
    store = MemoryNotes()
    entered, finish = threading.Event(), threading.Event()

    def slow(resource, arguments):
        entered.set()
        if not finish.wait(10):
            raise TimeoutError("in-flight experiment synchronization")
        return store.append(resource, arguments)

    broker = Broker({"append": slow})
    token = broker.issue(SCOPE, calls=2, bytes=4, ttl=60)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            broker.execute, token, "append", "/owned/note", {"text": "ok"}
        )
        try:
            if not entered.wait(10):
                raise TimeoutError("callback did not start")
            broker.revoke(token)
            before_completion = store.snapshot()
            try:
                broker.execute(token, "append", "/owned/note", {"text": "ok"})
            except Denied:
                pass
        finally:
            finish.set()
        result = future.result(timeout=10)
    return {
        "before_completion": before_completion,
        "after_completion": store.snapshot(),
        "result": result,
        "decisions": [asdict(d) for d in broker.decisions()],
    }


def source_hashes():
    return {
        str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
            p.read_bytes()
        ).hexdigest()
        for directory in ["agent_capabilities", "experiments"]
        for p in sorted((ROOT / directory).glob("*.py"))
    }


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new path")
    report = {
        "schema_version": 1,
        "metadata": {
            "created_utc": datetime.now(UTC).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu": command("sysctl", "-n", "machdep.cpu.brand_string")
            if platform.system() == "Darwin"
            else platform.processor(),
            "memory_bytes": int(command("sysctl", "-n", "hw.memsize"))
            if platform.system() == "Darwin"
            else None,
            "revision": command("git", "rev-parse", "HEAD"),
            "working_tree_clean": not bool(command("git", "status", "--porcelain")),
            "source_sha256": source_hashes(),
            "paid_api_calls": 0,
            "measurement": "fixed synthetic correctness experiment; no latency claims",
        },
        "sequential": sequential(),
        "concurrency": [concurrent(7, 128), concurrent(64, 14)],
        "in_flight_revocation": in_flight(),
    }
    from experiments.verify import verify

    verify(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"verified": True, "output": str(args.output)}))


if __name__ == "__main__":
    main()
