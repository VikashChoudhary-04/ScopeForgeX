from __future__ import annotations

from types import SimpleNamespace

from scopeforgex.models import ExecutionResult
from scopeforgex.workflow import (
    _conditional_tool_skip_result,
)


def _tool(
    name: str,
    input_type: str,
    capability: str,
):
    return SimpleNamespace(
        name=name,
        input_type=input_type,
        capability=capability,
        phase="vulnerability_validation",
    )


def _profile(
    name: str,
):
    return {
        "validation": {
            name: {
                "enabled": True,
                "mode": "conditional",
            },
        },
    }


class FakeExecutor:
    def __init__(
        self,
        observations=(),
        jwt_inputs=(),
    ):
        self.last_collector_observations = observations
        self._jwt_inputs = tuple(jwt_inputs)

    def get_sensitive_inputs(
        self,
        key,
    ):
        if key == "jwt":
            return self._jwt_inputs

        return ()


def test_sqlmap_skipped_without_url_candidate():
    tool = _tool(
        "sqlmap",
        "url",
        "sql_injection_validation",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.test"},
        _profile("sqlmap"),
        executor,
    )

    assert isinstance(
        result,
        ExecutionResult,
    )
    assert result.status == "skipped"
    assert result.success is False
    assert result.errors == []
    assert result.metadata["status"] == "skipped"
    assert "no applicable url candidate" in result.metadata["skip_reason"]


def test_dalfox_skipped_without_url_candidate():
    tool = _tool(
        "dalfox",
        "url",
        "xss_validation",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.test"},
        _profile("dalfox"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert "no applicable url candidate" in result.metadata["skip_reason"]


def test_sstimap_skipped_without_url_candidate():
    tool = _tool(
        "sstimap",
        "url",
        "ssti_validation",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.test"},
        _profile("sstimap"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert "no applicable url candidate" in result.metadata["skip_reason"]


def test_jwt_tool_skipped_without_jwt_candidate():
    tool = _tool(
        "jwt_tool",
        "jwt",
        "jwt_security_validation",
    )

    executor = FakeExecutor(
        jwt_inputs=(),
    )

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.test"},
        _profile("jwt_tool"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert "no applicable JWT candidate" in result.metadata["skip_reason"]


def test_sqlmap_conditional_tool_proceeds_with_url_candidate():
    tool = _tool(
        "sqlmap",
        "url",
        "sql_injection_validation",
    )

    observation = SimpleNamespace(
        observation_type="ENDPOINT",
        value="https://example.test/login?id=1",
        url="https://example.test/login?id=1",
    )

    executor = FakeExecutor(
        observations=(observation,),
    )

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.test"},
        _profile("sqlmap"),
        executor,
    )

    assert result is None


def test_jwt_tool_conditional_proceeds_with_jwt_candidate():
    tool = _tool(
        "jwt_tool",
        "jwt",
        "jwt_security_validation",
    )

    executor = FakeExecutor(
        jwt_inputs=(
            "eyJhbGciOiJIUzI1NiJ9.test.signature",
        ),
    )

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.test"},
        _profile("jwt_tool"),
        executor,
    )

    assert result is None


def test_non_conditional_tool_is_not_skipped():
    tool = _tool(
        "sqlmap",
        "url",
        "sql_injection_validation",
    )

    profile = {
        "validation": {
            "sqlmap": {
                "enabled": True,
                "mode": "explicit",
            },
        },
    }

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.test"},
        profile,
        executor,
    )

    assert result is None
