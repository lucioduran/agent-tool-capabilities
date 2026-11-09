import dataclasses
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from agent_capabilities import Argument, Broker, Denied, Scope, ToolFailed
from agent_capabilities.broker import canonical_resource
from agent_capabilities.synthetic import MemoryNotes


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.store = MemoryNotes()
        self.broker = Broker(
            {"append": self.store.append, "read": self.store.read},
            clock=lambda: self.now,
        )
        self.scope = Scope("append", "/owned", {"text": Argument(16)})
        self.token = self.issue()

    def issue(self, **kwargs):
        return self.broker.issue(
            self.scope, **({"calls": 5, "bytes": 32, "ttl": 10} | kwargs)
        )

    def call(self, **kwargs):
        return self.broker.execute(
            **(
                {
                    "token": self.token,
                    "tool": "append",
                    "resource": "/owned/note",
                    "arguments": {"text": "ok"},
                }
                | kwargs
            )
        )

    def denied(self, reason, **kwargs):
        before = self.store.snapshot()
        with self.assertRaises(Denied) as caught:
            self.call(**kwargs)
        self.assertEqual(reason, caught.exception.decision.reason)
        self.assertEqual(before, self.store.snapshot())
        self.assertEqual(0, caught.exception.decision.charged_bytes)
        self.assertFalse(caught.exception.decision.allowed)
        return caught.exception.decision

    def test_canonical_resources(self):
        for source, expected in [
            ("/owned//./note/", "/owned/note"),
            ("///", "/"),
            ("/owned/.../x", "/owned/.../x"),
        ]:
            self.assertEqual(expected, canonical_resource(source))
        self.call(resource="/owned//./note/")
        self.assertEqual({"/owned/note": "ok"}, self.store.snapshot())
        self.assertEqual("/owned/note", self.broker.decisions()[-1].resource)
        self.call(resource="/owned")
        root = self.broker.issue(Scope("read", "/", {}), calls=1, bytes=0, ttl=2)
        self.assertEqual("ok", self.broker.execute(root, "read", "/owned", {}))

    def test_resource_attacks(self):
        for resource in [
            "/owned/../secret",
            "/owned/%2e%2e/secret",
            "/owned\\secret",
            "/owned/\x00x",
            "/owned/\nx",
            "/owned/caf\u00e9",
            "owned/note",
            "https://owned/note",
            42,
            None,
        ]:
            with self.subTest(resource=resource):
                self.denied("invalid_resource", resource=resource)
        for resource in ["/owned-evil/x", "/other/note", "/", "/Owned/note"]:
            self.denied("resource_scope", resource=resource)

    def test_tool_scope(self):
        for tool in ["read", "shell", "Append", None, 1]:
            self.denied("tool_scope", tool=tool)

    def test_forged_and_cross_broker_tokens(self):
        for token in [None, 12, [], "", "0" * 64, "A" * 64, self.token + "00"]:
            self.denied("unknown_capability", token=token)
            self.assertFalse(self.broker.revoke(token))
        other = Broker({"append": self.store.append})
        alien = other.issue(self.scope, calls=1, bytes=4, ttl=1)
        self.denied("unknown_capability", token=alien)
        changed = ("0" if self.token[0] != "0" else "1") + self.token[1:]
        self.denied("unknown_capability", token=changed)

    def test_arguments(self):
        for arguments in [
            None,
            [],
            {},
            {"text": "x", "extra": "x"},
            {"text": 1},
            {1: "x"},
        ]:
            self.denied("argument_schema", arguments=arguments)
        self.denied("argument_encoding", arguments={"text": "\ud800"})
        self.denied("argument_scope", arguments={"text": "x" * 17})
        self.denied("argument_scope", arguments={"text": "\u00e9" * 9})
        scope = Scope("append", "/owned", {"text": Argument(3, frozenset({"yes"}))})
        token = self.broker.issue(scope, calls=1, bytes=3, ttl=1)
        self.denied("argument_scope", token=token, arguments={"text": "no"})
        self.assertEqual("yes", self.call(token=token, arguments={"text": "yes"}))

    def test_budgets_and_no_denial_charge(self):
        token = self.issue(calls=1, bytes=2)
        decision = self.denied("resource_scope", token=token, resource="/other")
        self.assertEqual((1, 2), (decision.remaining_calls, decision.remaining_bytes))
        self.call(token=token)
        self.denied("call_budget", token=token)
        token = self.issue(calls=5, bytes=1)
        self.denied("byte_budget", token=token)
        self.call(token=token, arguments={"text": "x"})
        self.denied("byte_budget", token=token)
        self.denied("call_budget", token=self.issue(calls=0))
        self.denied("byte_budget", token=self.issue(bytes=0))
        self.call(token=self.issue(bytes=0), arguments={"text": ""})

    def test_expiry_and_revocation(self):
        self.now = 109.999
        self.call()
        self.now = 110.0
        self.denied("expired")
        token = self.issue()
        self.assertTrue(self.broker.revoke(token))
        self.assertTrue(self.broker.revoke(token))
        self.denied("revoked", token=token)
        self.assertEqual("okok", self.call(token=self.issue()))

    def test_policy_and_log_are_immutable_snapshots(self):
        choices = {"ok"}
        rule = Argument(2, choices)
        choices.add("no")
        policies = {"text": rule}
        scope = Scope("append", "/owned", policies)
        policies.clear()
        token = self.broker.issue(scope, calls=3, bytes=6, ttl=1)
        self.denied("argument_scope", token=token, arguments={"text": "no"})
        self.call(token=token)
        snapshot = self.broker.decisions()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snapshot[0].reason = "allowed"
        with self.assertRaises(TypeError):
            scope.arguments["text"] = Argument(200)
        self.call(token=token)
        self.assertEqual(2, len(snapshot))
        self.assertEqual([1, 2, 3], [d.sequence for d in self.broker.decisions()])
        self.assertNotIn(token, repr(self.broker.decisions()))

    def test_registry_copy_and_argument_copy(self):
        entered, finish = threading.Event(), threading.Event()
        seen = []

        def callback(resource, arguments):
            entered.set()
            self.assertTrue(finish.wait(5))
            seen.append(dict(arguments))
            with self.assertRaises(TypeError):
                arguments["text"] = "changed"
            return "done"

        registry = {"append": callback}
        broker = Broker(registry)
        registry.clear()
        token = broker.issue(self.scope, calls=1, bytes=2, ttl=10)
        args = {"text": "ok"}
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(broker.execute, token, "append", "/owned", args)
            try:
                self.assertTrue(entered.wait(5))
                args["text"] = "changed"
            finally:
                finish.set()
            self.assertEqual("done", future.result(timeout=5))
        self.assertEqual([{"text": "ok"}], seen)

    def test_failure_consumes_budget_and_hides_exception(self):
        def broken(resource, arguments):
            raise RuntimeError("private payload")

        broker = Broker({"append": broken})
        token = broker.issue(self.scope, calls=1, bytes=2, ttl=10)
        with self.assertRaises(ToolFailed) as caught:
            broker.execute(token, "append", "/owned", {"text": "ok"})
        self.assertNotIn("private", str(caught.exception))
        with self.assertRaises(Denied) as denied:
            broker.execute(token, "append", "/owned", {"text": "ok"})
        self.assertEqual("call_budget", denied.exception.decision.reason)
        self.assertTrue(broker.decisions()[0].allowed)

    def test_concurrent_atomic_budgets(self):
        for calls, byte_budget, expected in [(7, 100, 7), (100, 14, 7)]:
            token = self.issue(calls=calls, bytes=byte_budget)
            barrier = threading.Barrier(8)

            def attempt(_, barrier=barrier, token=token):
                barrier.wait(timeout=5)
                try:
                    self.call(token=token)
                    return True
                except Denied:
                    return False

            with ThreadPoolExecutor(max_workers=8) as pool:
                outcomes = list(pool.map(attempt, range(32)))
            self.assertEqual(expected, sum(outcomes))
            last = self.broker.decisions()[-1]
            self.assertEqual(calls - expected, last.remaining_calls)
            self.assertEqual(byte_budget - 2 * expected, last.remaining_bytes)
        self.assertEqual("ok" * 14, self.store.snapshot()["/owned/note"])

    def test_revocation_during_in_flight_call(self):
        entered, finish = threading.Event(), threading.Event()

        def slow(resource, arguments):
            entered.set()
            if not finish.wait(5):
                raise TimeoutError("test synchronization")
            return self.store.append(resource, arguments)

        broker = Broker({"append": slow})
        token = broker.issue(self.scope, calls=2, bytes=4, ttl=10)
        with ThreadPoolExecutor(max_workers=1) as pool:
            active = pool.submit(
                broker.execute, token, "append", "/owned", {"text": "ok"}
            )
            try:
                self.assertTrue(entered.wait(5))
                self.assertTrue(broker.revoke(token))
                self.assertEqual({}, self.store.snapshot())
                with self.assertRaises(Denied) as caught:
                    broker.execute(token, "append", "/owned", {"text": "ok"})
                self.assertEqual("revoked", caught.exception.decision.reason)
            finally:
                finish.set()
            self.assertEqual("ok", active.result(timeout=5))
        self.assertEqual({"/owned": "ok"}, self.store.snapshot())

    def test_invalid_issuer_configuration(self):
        for amount in [-1, True, 1.5, "1"]:
            for field in ["calls", "bytes"]:
                with self.assertRaises(ValueError):
                    self.issue(**{field: amount})
            with self.assertRaises(ValueError):
                Argument(amount)
        for ttl in [0, -1, float("nan"), float("inf"), True, "1"]:
            with self.assertRaises(ValueError):
                self.issue(ttl=ttl)
        for name in ["", "Bad", "a\n", 1]:
            with self.assertRaises(ValueError):
                Scope(name, "/", {})
            with self.assertRaises(ValueError):
                Broker({name: self.store.read})
        with self.assertRaises(ValueError):
            Broker({"read": None})
        for policy in [{"text": None}, {1: Argument(1)}, {"Bad": Argument(1)}]:
            with self.assertRaises(ValueError):
                Scope("read", "/", policy)
        for choices in [{1}, {"long"}, {"\ud800"}]:
            with self.assertRaises(ValueError):
                Argument(1, choices)
        for scope in [None, Scope("missing", "/", {})]:
            with self.assertRaises(ValueError):
                self.broker.issue(scope, calls=1, bytes=1, ttl=1)
        self.now = float("inf")
        with self.assertRaises(ValueError):
            self.issue()

    def test_token_collision_retries(self):
        with patch(
            "agent_capabilities.broker.secrets.token_hex",
            side_effect=[self.token, "1" * 64],
        ):
            token = self.issue()
        self.assertEqual("1" * 64, token)
        self.assertNotEqual(self.token, token)

    def test_empty_choices_and_empty_read(self):
        token = self.broker.issue(
            Scope("append", "/", {"text": Argument(1, frozenset())}),
            calls=1,
            bytes=1,
            ttl=1,
        )
        self.denied("argument_scope", token=token, arguments={"text": ""})
        reader = self.broker.issue(Scope("read", "/", {}), calls=1, bytes=0, ttl=1)
        self.assertEqual("", self.broker.execute(reader, "read", "/missing", {}))
