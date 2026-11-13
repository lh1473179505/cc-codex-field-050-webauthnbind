"""Ceremony verification. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any


def verify(
    ceremony: dict[str, Any],
    store: dict[str, dict[str, Any]],
    rp: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    raise NotImplementedError("verify is not implemented in this snapshot")
