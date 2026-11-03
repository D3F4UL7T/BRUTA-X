"""Simple in-process pub/sub event bus."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

Handler = Callable[[str, dict[str, Any]], None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._handlers[topic].append(handler)

    def publish(self, topic: str, payload: dict[str, Any] | None = None) -> None:
        payload = payload or {}
        for h in list(self._handlers.get(topic, [])):
            try:
                h(topic, payload)
            except Exception:
                continue
        for h in list(self._handlers.get("*", [])):
            try:
                h(topic, payload)
            except Exception:
                continue


BUS = EventBus()
