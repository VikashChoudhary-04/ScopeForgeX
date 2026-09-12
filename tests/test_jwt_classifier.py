"""
Tests for the pure ScopeForgeX JWT semantic classifier.
"""

from __future__ import annotations

import base64
import json

from scopeforgex.analysis.jwt import is_jwt


def _b64url_json(value: dict[str, object]) -> str:
    return (
        base64.urlsafe_b64encode(
            json.dumps(
                value,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )


def _jwt(
    *,
    header: dict[str, object] | None = None,
    payload: dict[str, object] | None = None,
    signature: str = "signature",
) -> str:
    encoded_header = _b64url_json(
        header
        or {
            "alg": "HS256",
            "typ": "JWT",
        }
    )
    encoded_payload = _b64url_json(
        payload
        or {
            "sub": "123",
        }
    )

    return (
        f"{encoded_header}."
        f"{encoded_payload}."
        f"{signature}"
    )


def test_valid_jwt_is_recognized():
    assert is_jwt(_jwt()) is True


def test_valid_jwt_with_realistic_claims_is_recognized():
    token = _jwt(
        payload={
            "sub": "user-123",
            "iss": "https://example.test",
            "aud": "api",
            "exp": 9999999999,
        }
    )

    assert is_jwt(token) is True


def test_unsecured_none_algorithm_jwt_is_structurally_recognized():
    token = _jwt(
        header={
            "alg": "none",
            "typ": "JWT",
        },
        signature="",
    )

    assert is_jwt(token) is True


def test_eyj_prefix_alone_is_not_enough():
    assert is_jwt("eyJnot-a-jwt") is False


def test_three_segments_with_invalid_header_are_rejected():
    assert is_jwt(
        "eyJnot-valid-json.payload.signature"
    ) is False


def test_three_segments_with_invalid_payload_are_rejected():
    header = _b64url_json(
        {
            "alg": "HS256",
        }
    )

    assert is_jwt(
        f"{header}.not-valid-json.signature"
    ) is False


def test_header_must_be_json_object():
    header = (
        base64.urlsafe_b64encode(
            b'["HS256"]'
        )
        .decode("ascii")
        .rstrip("=")
    )
    payload = _b64url_json(
        {
            "sub": "123",
        }
    )

    assert is_jwt(
        f"{header}.{payload}.signature"
    ) is False


def test_payload_must_be_json_object():
    header = _b64url_json(
        {
            "alg": "HS256",
        }
    )
    payload = (
        base64.urlsafe_b64encode(
            b'["user"]'
        )
        .decode("ascii")
        .rstrip("=")
    )

    assert is_jwt(
        f"{header}.{payload}.signature"
    ) is False


def test_alg_is_required():
    assert is_jwt(
        _jwt(
            header={
                "typ": "JWT",
            }
        )
    ) is False


def test_empty_alg_is_rejected():
    assert is_jwt(
        _jwt(
            header={
                "alg": "",
                "typ": "JWT",
            }
        )
    ) is False


def test_invalid_signature_characters_are_rejected():
    assert is_jwt(
        _jwt(
            signature="signature$"
        )
    ) is False


def test_wrong_segment_count_is_rejected():
    token = _jwt()

    assert is_jwt(token.rsplit(".", 1)[0]) is False
    assert is_jwt(f"{token}.extra") is False


def test_oauth_api_reference_is_not_a_jwt():
    assert is_jwt(
        "https://www.googleapis.com/oauth2/v1/userinfo"
        "?alt=json&access_token=EXPR"
    ) is False


def test_plain_secret_candidate_is_not_a_jwt():
    assert is_jwt(
        "my-api-secret-value"
    ) is False


def test_non_string_values_are_rejected():
    assert is_jwt(None) is False
    assert is_jwt(123) is False
    assert is_jwt(["token"]) is False


def test_whitespace_around_valid_jwt_is_accepted():
    token = _jwt()

    assert is_jwt(
        f"  {token}  "
    ) is True
