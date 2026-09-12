"""
ScopeForgeX JWT Semantic Classification
=======================================

Pure helpers for recognizing compact JSON Web Tokens.

This module performs semantic classification only. It does not:
- execute jwt_tool;
- inspect network traffic;
- perform authentication;
- store or serialize tokens;
- create findings;
- decide authorization or scope.

A value is considered JWT-shaped only when it satisfies the minimum
structure expected of a compact signed JWT/JWS:

    base64url(header).base64url(payload).base64url(signature)

The header and payload must decode to JSON objects and the header must
contain a non-empty ``alg`` field.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any


_BASE64URL_SEGMENT_RE = re.compile(
    r"^[A-Za-z0-9_-]+$"
)


def _decode_base64url_json(
    segment: str,
) -> dict[str, Any] | None:
    """
    Decode one JWT JSON segment.

    Returns:
        A JSON object when the segment is valid, otherwise ``None``.
    """

    if not segment:
        return None

    if _BASE64URL_SEGMENT_RE.fullmatch(segment) is None:
        return None

    # Base64URL padding is optional in compact JWT serialization.
    padding = "=" * (-len(segment) % 4)

    try:
        decoded = base64.urlsafe_b64decode(
            segment + padding
        )
    except (
        ValueError,
        binascii.Error,
    ):
        return None

    try:
        parsed = json.loads(
            decoded.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return None

    if not isinstance(parsed, dict):
        return None

    return parsed


def is_jwt(value: str) -> bool:
    """
    Return whether ``value`` has a genuine compact JWT structure.

    The function intentionally performs semantic validation rather than
    prefix matching. In particular, values beginning with ``eyJ`` are not
    automatically considered JWTs.

    Args:
        value: Candidate string to classify.

    Returns:
        ``True`` when the value has three compact-JWT segments, contains
        valid Base64URL-encoded JSON objects for its header and payload,
        and has a non-empty ``alg`` header value. Otherwise ``False``.
    """

    if not isinstance(value, str):
        return False

    candidate = value.strip()

    if not candidate:
        return False

    segments = candidate.split(".")

    if len(segments) != 3:
        return False

    header_segment, payload_segment, signature_segment = segments

    if not signature_segment:
        # An empty signature is structurally possible for an unsecured
        # JWT using alg=none, so it must not be rejected here.
        pass
    elif _BASE64URL_SEGMENT_RE.fullmatch(
        signature_segment
    ) is None:
        return False

    header = _decode_base64url_json(
        header_segment
    )

    if header is None:
        return False

    payload = _decode_base64url_json(
        payload_segment
    )

    if payload is None:
        return False

    algorithm = header.get("alg")

    if not isinstance(algorithm, str):
        return False

    if not algorithm.strip():
        return False

    return True


__all__ = [
    "is_jwt",
]
