"""Owned in-memory tools for demonstrations, with no filesystem or network access."""

from collections.abc import Mapping
from threading import Lock


class MemoryNotes:
    def __init__(self) -> None:
        self._lock = Lock()
        self._notes: dict[str, str] = {}

    def append(self, resource: str, arguments: Mapping[str, str]) -> str:
        with self._lock:
            self._notes[resource] = self._notes.get(resource, "") + arguments["text"]
            return self._notes[resource]

    def read(self, resource: str, arguments: Mapping[str, str]) -> str:
        with self._lock:
            return self._notes.get(resource, "")

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self._notes)
