"""
Tests for JSLuice JWT candidate classification and safe observation handling.
"""

from __future__ import annotations

import base64
import hashlib
import json

from scopeforgex.collectors.jsluice import (
    JSLuiceCollector,
    OBSERVATION_API_REFERENCE,
    OBSERVATION_JWT_CANDIDATE,
    OBSERVATION_SECRET_CANDIDATE,
)


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
    return ".".join(
        (
            _b64url_json(
                header
                or {
                    "alg": "HS256",
                    "typ": "JWT",
                }
            ),
            _b64url_json(
                payload
                or {
                    "sub": "user-123",
                }
            ),
            signature,
        )
    )


def _extract(
    record: dict[str, object],
) -> list[dict[str, object]]:
    collector = JSLuiceCollector()

    parsed = collector._parse_record(
        record,
        target="http://127.0.0.1:3000",
    )

    assert parsed is not None

    return collector._extract_observations(
        parsed
    )


def test_genuine_jwt_secret_becomes_jwt_candidate():
    token = _jwt()

    observations = _extract(
        {
            "secret": token,
            "filename": (
                "http://127.0.0.1:3000/app.js"
            ),
        }
    )

    candidates = [
        observation
        for observation in observations
        if observation["observation_type"]
        == OBSERVATION_JWT_CANDIDATE
    ]

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate["value"] == "<JWT_REDACTED>"
    assert token not in str(candidate)

    metadata = candidate["metadata"]

    assert metadata["classification"] == "jwt_candidate"
    assert metadata["sensitive"] is True
    assert metadata["candidate_id"] == hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def test_generic_secret_remains_secret_candidate():
    secret = "my-api-secret-value"

    observations = _extract(
        {
            "secret": secret,
        }
    )

    candidates = [
        observation
        for observation in observations
        if observation["observation_type"]
        == OBSERVATION_SECRET_CANDIDATE
    ]

    assert len(candidates) == 1
    assert candidates[0]["value"] == secret


def test_oauth_api_reference_is_not_jwt_candidate():
    value = (
        "https://www.googleapis.com/oauth2/v1/userinfo"
        "?alt=json&access_token=EXPR"
    )

    observations = _extract(
        {
            "api_reference": value,
        }
    )

    assert all(
        observation["observation_type"]
        != OBSERVATION_JWT_CANDIDATE
        for observation in observations
    )

    assert any(
        observation["observation_type"]
        == OBSERVATION_API_REFERENCE
        for observation in observations
    )


def test_jwt_candidate_does_not_contain_raw_token_in_observation():
    token = _jwt(
        payload={
            "sub": "sensitive-user",
            "role": "admin",
        }
    )

    observations = _extract(
        {
            "secret": token,
        }
    )

    candidate = next(
        observation
        for observation in observations
        if observation["observation_type"]
        == OBSERVATION_JWT_CANDIDATE
    )

    serialized = json.dumps(
        candidate,
        sort_keys=True,
    )

    assert token not in serialized
    assert candidate["value"] == "<JWT_REDACTED>"
    assert "<JWT_REDACTED>" in serialized


def test_jwt_candidate_preserves_candidate_identity_without_token():
    token = _jwt()

    observations = _extract(
        {
            "secret": token,
        }
    )

    candidate = next(
        observation
        for observation in observations
        if observation["observation_type"]
        == OBSERVATION_JWT_CANDIDATE
    )

    assert candidate["metadata"]["candidate_id"] == hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def test_malformed_jwt_remains_generic_secret():
    malformed = (
        "eyJnot-valid."
        "not-valid."
        "not-valid"
    )

    observations = _extract(
        {
            "secret": malformed,
        }
    )

    assert any(
        observation["observation_type"]
        == OBSERVATION_SECRET_CANDIDATE
        for observation in observations
    )

    assert not any(
        observation["observation_type"]
        == OBSERVATION_JWT_CANDIDATE
        for observation in observations
    )


def test_real_parse_path_redacts_jwt_from_evidence():
    import json

    from scopeforgex.collectors.jsluice import (
        JSLuiceCollector,
        OBSERVATION_JWT_CANDIDATE,
    )
    from scopeforgex.models.execution_result import ExecutionResult

    token = _jwt()
    collector = JSLuiceCollector()

    record = {
        "secret": token,
        "filename": "http://127.0.0.1:3000/app.js",
    }

    result = ExecutionResult(
        tool="jsluice",
        capability="javascript_analysis",
        success=True,
        stdout=json.dumps(record),
        stderr="",
        artifacts=[],
        findings=[],
        warnings=[],
        errors=[],
        metadata={},
    )

    observations = collector.parse(
        result,
        {
            "target": "http://127.0.0.1:3000",
            "artifacts": [],
        },
    )

    candidates = [
        observation
        for observation in observations
        if observation.observation_type
        == OBSERVATION_JWT_CANDIDATE
    ]

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.value == "<JWT_REDACTED>"
    assert candidate.evidence["secret"] == "<JWT_REDACTED>"
    assert candidate.evidence["filename"] == (
        "http://127.0.0.1:3000/app.js"
    )

    serialized = json.dumps(
        candidate.as_dict(),
        sort_keys=True,
    )

    assert token not in serialized
    assert "<JWT_REDACTED>" in serialized


def test_jwt_evidence_sanitizer_preserves_unrelated_evidence():
    from scopeforgex.collectors.jsluice import JSLuiceCollector

    token = _jwt()

    evidence = {
        "secret": token,
        "filename": "http://127.0.0.1:3000/app.js",
        "type": "secret",
        "nested": {
            "secret": token,
            "other": "preserve-me",
        },
    }

    sanitized = JSLuiceCollector._sanitize_jwt_evidence(
        evidence,
        token,
    )

    assert sanitized["secret"] == "<JWT_REDACTED>"
    assert sanitized["nested"]["secret"] == "<JWT_REDACTED>"
    assert sanitized["filename"] == (
        "http://127.0.0.1:3000/app.js"
    )
    assert sanitized["type"] == "secret"
    assert sanitized["nested"]["other"] == "preserve-me"

    assert token not in str(sanitized)


def test_create_tool_context_passes_sensitive_jwt_without_workflow_ctx():
    from pathlib import Path
    from types import SimpleNamespace

    from scopeforgex.workflow import _create_tool_context

    token = _jwt()

    ctx = {
        "target": "http://127.0.0.1:3000",
        "outdir": "/tmp/scopeforgex-jwt-context-test",
        "profile": "full",
    }

    tool = SimpleNamespace(
        name="jwt_tool",
        input_type="jwt",
        phase="vulnerability_validation",
    )

    profile = {
        "validation": {
            "jwt_tool": {
                "options": {},
            },
        },
    }

    context = _create_tool_context(
        ctx,
        tool,
        profile,
        sensitive_input_data={
            "jwt": (token,),
        },
    )

    assert context.sensitive_input_data["jwt"] == (
        token,
    )
    assert token not in str(ctx)
    assert token not in repr(ctx)


def test_jwt_tool_uses_sensitive_candidate_not_assessment_target():
    from pathlib import Path

    from scopeforgex.registry.tool_base import ToolContext
    from scopeforgex.tools.stage4_exploit import JWTTool

    token = _jwt()

    context = ToolContext(
        target="http://127.0.0.1:3000",
        output_dir=Path(
            "/tmp/scopeforgex-jwt-tool-test"
        ),
        sensitive_input_data={
            "jwt": (token,),
        },
    )

    tool = JWTTool(context=context)

    arguments = tool.build_arguments()

    assert arguments == [
        "<JWT_CANDIDATE_1>"
    ]
    assert token not in str(arguments)
    assert "127.0.0.1" not in str(arguments)



def test_jwt_tool_with_multiple_candidates_uses_first_candidate_reference():
    from pathlib import Path

    from scopeforgex.registry.tool_base import ToolContext
    from scopeforgex.tools.stage4_exploit import JWTTool

    first_token = _jwt()
    second_token = _jwt(
        header={
            "alg": "HS384",
            "typ": "JWT",
        },
        payload={
            "sub": "456",
        },
    )

    context = ToolContext(
        target="http://127.0.0.1:3000",
        output_dir=Path(
            "/tmp/scopeforgex-jwt-tool-multi-candidate-test"
        ),
        sensitive_input_data={
            "jwt": (
                first_token,
                second_token,
            ),
        },
    )

    tool = JWTTool(context=context)

    arguments = tool.build_arguments()

    assert arguments == [
        "<JWT_CANDIDATE_1>"
    ]
    assert first_token not in str(arguments)
    assert second_token not in str(arguments)

    result = tool.run()

    assert result.success is True
    assert result.metadata["executed"] is False
    assert result.metadata["manual_review_required"] is True

    command = result.metadata["command"]

    assert command == (
        "jwt_tool '<JWT_CANDIDATE_1>'"
    )
    assert first_token not in command
    assert second_token not in command

def test_jwt_tool_without_candidate_is_skipped():
    from pathlib import Path

    from scopeforgex.registry.tool_base import ToolContext
    from scopeforgex.tools.stage4_exploit import JWTTool

    context = ToolContext(
        target="http://127.0.0.1:3000",
        output_dir=Path(
            "/tmp/scopeforgex-jwt-tool-skip-test"
        ),
        sensitive_input_data={},
    )

    tool = JWTTool(context=context)

    result = tool.run()

    assert result.success is False
    assert result.metadata["status"] == "skipped"
    assert "no JWT candidate" in result.metadata["skip_reason"]
    assert result.metadata["skip_reason"]
    assert result.metadata.get("command") is None


def test_jwt_tool_prepared_command_never_contains_raw_jwt():
    from pathlib import Path

    from scopeforgex.registry.tool_base import ToolContext
    from scopeforgex.tools.stage4_exploit import JWTTool

    token = _jwt()

    output_dir = Path(
        "/tmp/scopeforgex-jwt-tool-command-test"
    )

    context = ToolContext(
        target="http://127.0.0.1:3000",
        output_dir=output_dir,
        sensitive_input_data={
            "jwt": (token,),
        },
    )

    tool = JWTTool(context=context)

    result = tool.run()

    assert result.success is True
    assert result.metadata["executed"] is False
    assert result.metadata["manual_review_required"] is True

    command = result.metadata["command"]

    assert command == (
        "jwt_tool '<JWT_CANDIDATE_1>'"
    )
    assert token not in command

    prepared = (
        output_dir
        / "exploit"
        / "prepared_commands.txt"
    )

    assert prepared.exists()

    contents = prepared.read_text(
        encoding="utf-8"
    )

    assert token not in contents
    assert "<JWT_CANDIDATE_1>" in contents


def test_executor_sensitive_jwt_store_is_cleared_after_context_handoff():
    from pathlib import Path
    from types import SimpleNamespace

    from scopeforgex.runtime.tool_executor import ToolExecutor
    from scopeforgex.workflow import _create_tool_context

    token = _jwt()

    executor = ToolExecutor()

    executor.set_sensitive_inputs(
        "jwt",
        (token,),
    )

    tool = SimpleNamespace(
        name="jwt_tool",
        input_type="jwt",
        phase="vulnerability_validation",
    )

    profile = {
        "validation": {
            "jwt_tool": {
                "options": {},
            },
        },
    }

    ctx = {
        "target": "http://127.0.0.1:3000",
        "outdir": "/tmp/scopeforgex-jwt-clear-test",
        "profile": "full",
    }

    snapshot = executor.get_sensitive_inputs(
        "jwt"
    )

    context = _create_tool_context(
        ctx,
        tool,
        profile,
        sensitive_input_data={
            "jwt": snapshot,
        },
    )

    executor.clear_sensitive_inputs(
        "jwt"
    )

    assert context.sensitive_input_data["jwt"] == (
        token,
    )
    assert executor.get_sensitive_inputs("jwt") == ()
    assert token not in str(ctx)

def test_collect_result_hands_off_jwt_from_real_collector_boundary():
    import json
    from types import SimpleNamespace

    import scopeforgex.runtime.tool_executor as tool_executor_module
    from scopeforgex.collectors.jsluice import (
        JSLuiceCollector,
        OBSERVATION_JWT_CANDIDATE,
    )
    from scopeforgex.models.execution_result import ExecutionResult
    from scopeforgex.runtime.tool_executor import ToolExecutor

    token = _jwt(
        payload={
            "sub": "boundary-user",
            "role": "admin",
        }
    )

    record = {
        "secret": token,
        "filename": (
            "http://127.0.0.1:3000/app.js"
        ),
    }

    execution_result = ExecutionResult(
        tool="jsluice",
        capability="javascript_analysis",
        success=True,
        stdout=json.dumps(record),
        stderr="",
        artifacts=[],
        findings=[],
        warnings=[],
        errors=[],
        metadata={},
    )

    collector = JSLuiceCollector()

    original_get_collector = (
        tool_executor_module.get_collector_for_tool
    )

    try:
        tool_executor_module.get_collector_for_tool = (
            lambda definition: collector
        )

        executor = ToolExecutor()

        adapter = SimpleNamespace(
            name="jsluice",
        )

        result = executor._collect_result(
            adapter,
            execution_result,
            {
                "target": "http://127.0.0.1:3000",
                "profile": "full",
                "tool": "jsluice",
                "run_id": "jwt-boundary-test",
            },
        )

    finally:
        tool_executor_module.get_collector_for_tool = (
            original_get_collector
        )

    assert result is execution_result

    assert len(executor._collector_results) == 1

    collected = executor._collector_results[0]

    candidates = [
        observation
        for observation in collected.observations
        if observation.observation_type
        == OBSERVATION_JWT_CANDIDATE
    ]

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.value == "<JWT_REDACTED>"

    serialized_collector_result = json.dumps(
        collected.as_dict(),
        sort_keys=True,
    )

    serialized_observation = json.dumps(
        candidate.as_dict(),
        sort_keys=True,
    )

    assert token not in serialized_collector_result
    assert token not in serialized_observation

    assert executor.get_sensitive_inputs(
        "jwt"
    ) == (
        token,
    )

    assert collector.get_sensitive_inputs(
        "jwt"
    ) == ()

    executor.clear_sensitive_inputs(
        "jwt"
    )

    assert executor.get_sensitive_inputs(
        "jwt"
    ) == ()
