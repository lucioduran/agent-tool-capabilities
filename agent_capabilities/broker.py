"""Process-local authority with atomic admission and budget reservation."""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

Tool = Callable[[str, Mapping[str, str]], str]
_PATH = re.compile(r"/[A-Za-z0-9_./-]*\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_TOKEN = re.compile(r"[0-9a-f]{64}\Z")


def canonical_resource(value: str) -> str:
    """Normalize virtual paths without interpreting OS paths or URLs."""
    if type(value) is not str or not _PATH.fullmatch(value):
        raise ValueError("resource must be an absolute ASCII virtual path")
    parts = value.split("/")
    if ".." in parts:
        raise ValueError("parent traversal is forbidden")
    return "/" + "/".join(p for p in parts if p not in ("", "."))


def _natural(value: int) -> bool:
    return type(value) is int and value >= 0


@dataclass(frozen=True)
class Argument:
    """A required string argument bounded by bytes and optional exact choices."""

    max_bytes: int
    choices: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if not _natural(self.max_bytes):
            raise ValueError("max_bytes must be a nonnegative integer")
        if self.choices is not None:
            choices = frozenset(self.choices)
            if any(type(v) is not str for v in choices):
                raise ValueError("choices must contain strings")
            try:
                if any(len(v.encode("utf-8")) > self.max_bytes for v in choices):
                    raise ValueError("choice exceeds max_bytes")
            except UnicodeError as exc:
                raise ValueError("choices must be valid UTF-8") from exc
            object.__setattr__(self, "choices", choices)


@dataclass(frozen=True)
class Scope:
    tool: str
    resource: str
    arguments: Mapping[str, Argument]

    def __post_init__(self) -> None:
        if type(self.tool) is not str or not _NAME.fullmatch(self.tool):
            raise ValueError("invalid tool name")
        object.__setattr__(self, "resource", canonical_resource(self.resource))
        arguments = dict(self.arguments)
        if any(
            type(k) is not str or not _NAME.fullmatch(k) or type(v) is not Argument
            for k, v in arguments.items()
        ):
            raise ValueError("invalid argument policy")
        object.__setattr__(self, "arguments", MappingProxyType(arguments))


@dataclass(frozen=True)
class Decision:
    sequence: int
    grant_id: int | None
    tool: str | None
    resource: str | None
    allowed: bool
    reason: str
    charged_bytes: int
    remaining_calls: int | None
    remaining_bytes: int | None


@dataclass
class _Grant:
    identifier: int
    scope: Scope
    expires: float
    calls: int
    bytes: int
    revoked: bool = False


class Denied(Exception):
    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.reason)


class ToolFailed(Exception):
    """An admitted callback failed; reserved budget remains consumed."""


class Broker:
    def __init__(
        self, tools: Mapping[str, Tool], *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        registered = dict(tools)
        if any(
            type(name) is not str or not _NAME.fullmatch(name) or not callable(tool)
            for name, tool in registered.items()
        ):
            raise ValueError("invalid tool registry")
        self._tools = registered
        self._clock = clock
        self._lock = threading.Lock()
        self._grants: dict[str, _Grant] = {}
        self._log: list[Decision] = []

    def issue(self, scope: Scope, *, calls: int, bytes: int, ttl: float) -> str:
        if type(scope) is not Scope or scope.tool not in self._tools:
            raise ValueError("scope must name a registered tool")
        if not _natural(calls) or not _natural(bytes):
            raise ValueError("budgets must be nonnegative integers")
        if type(ttl) not in (int, float) or not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("ttl must be positive and finite")
        with self._lock:
            expires = self._clock() + ttl
            if not math.isfinite(expires):
                raise ValueError("expiry must be finite")
            token = secrets.token_hex(32)
            key = hashlib.sha256(token.encode("ascii")).hexdigest()
            while key in self._grants:
                token = secrets.token_hex(32)
                key = hashlib.sha256(token.encode("ascii")).hexdigest()
            self._grants[key] = _Grant(
                len(self._grants) + 1, scope, expires, calls, bytes
            )
        return token

    def _lookup(self, token: object) -> _Grant | None:
        if type(token) is not str or not _TOKEN.fullmatch(token):
            return None
        return self._grants.get(hashlib.sha256(token.encode("ascii")).hexdigest())

    def revoke(self, token: str) -> bool:
        with self._lock:
            grant = self._lookup(token)
            if grant is None:
                return False
            grant.revoked = True
            return True

    def decisions(self) -> tuple[Decision, ...]:
        with self._lock:
            return tuple(self._log)

    def execute(
        self, token: str, tool: str, resource: str, arguments: dict[str, str]
    ) -> str:
        with self._lock:
            grant = self._lookup(token)
            canonical: str | None = None
            copied: dict[str, str] = {}
            cost = 0
            reason = "allowed"
            if grant is None:
                reason = "unknown_capability"
            elif grant.revoked:
                reason = "revoked"
            elif self._clock() >= grant.expires:
                reason = "expired"
            elif type(tool) is not str or tool != grant.scope.tool:
                reason = "tool_scope"
            else:
                try:
                    canonical = canonical_resource(resource)
                except ValueError:
                    reason = "invalid_resource"
                if reason == "allowed":
                    assert canonical is not None
                    prefix = grant.scope.resource
                    if not (
                        prefix == "/"
                        or canonical == prefix
                        or canonical.startswith(prefix + "/")
                    ):
                        reason = "resource_scope"
                if reason == "allowed":
                    if type(arguments) is not dict:
                        reason = "argument_schema"
                    else:
                        copied = arguments.copy()
                        if (
                            any(
                                type(k) is not str or type(v) is not str
                                for k, v in copied.items()
                            )
                            or copied.keys() != grant.scope.arguments.keys()
                        ):
                            reason = "argument_schema"
                if reason == "allowed":
                    for name, value in copied.items():
                        rule = grant.scope.arguments[name]
                        try:
                            size = len(value.encode("utf-8"))
                        except UnicodeError:
                            reason = "argument_encoding"
                            break
                        if size > rule.max_bytes or (
                            rule.choices is not None and value not in rule.choices
                        ):
                            reason = "argument_scope"
                            break
                        cost += size
                if reason == "allowed" and grant.calls < 1:
                    reason = "call_budget"
                if reason == "allowed" and grant.bytes < cost:
                    reason = "byte_budget"
            allowed = reason == "allowed"
            if allowed:
                assert grant is not None and canonical is not None
                grant.calls -= 1
                grant.bytes -= cost
            decision = Decision(
                len(self._log) + 1,
                grant.identifier if grant else None,
                tool if type(tool) is str else None,
                canonical,
                allowed,
                reason,
                cost if allowed else 0,
                grant.calls if grant else None,
                grant.bytes if grant else None,
            )
            self._log.append(decision)
            if not allowed:
                raise Denied(decision)
            callback = self._tools[tool]
        assert canonical is not None
        try:
            return callback(canonical, MappingProxyType(copied))
        except Exception:
            raise ToolFailed("admitted tool failed; budget consumed") from None
