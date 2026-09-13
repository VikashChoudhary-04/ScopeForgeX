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
        last_collector_observations=None,
        jwt_inputs=(),
    ):
        self.observations = tuple(observations)
        if last_collector_observations is None:
            last_collector_observations = observations
        self.last_collector_observations = tuple(last_collector_observations)
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


def test_sqlmap_uses_assessment_wide_candidate_not_only_latest_collector():
    tool = _tool(
        "sqlmap",
        "url",
        "sql_injection_validation",
    )

    observation = SimpleNamespace(
        observation_type="ENDPOINT",
        value="https://example.test/login?id=1",
        url="https://example.test/login?id=1",
        resource_type=None,
    )

    executor = FakeExecutor(
        observations=(observation,),
        last_collector_observations=(),
    )

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.test"},
        _profile("sqlmap"),
        executor,
    )

    assert result is None


def test_target_hostname_recognizes_ipv6_literal():
    from scopeforgex.workflow import _target_hostname

    assert _target_hostname("::1") == "::1"
    assert _target_hostname("[::1]") == "::1"


def test_target_hostname_recognizes_bracketed_ipv6_with_port():
    from scopeforgex.workflow import _target_hostname

    assert _target_hostname("[::1]:3000") == "::1"
    assert _target_hostname("http://[::1]:3000") == "::1"


def test_dig_skipped_for_ipv4_literal_target():
    tool = _tool(
        "dig",
        "host",
        "dns_reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "127.0.0.1"},
        _profile("dig"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert result.success is False
    assert result.errors == []
    assert "IP-literal target" in result.metadata["skip_reason"]


def test_dig_skipped_for_ipv4_url_target():
    tool = _tool(
        "dig",
        "host",
        "dns_reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "http://127.0.0.1:3000"},
        _profile("dig"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert "IP-literal target" in result.metadata["skip_reason"]


def test_dig_skipped_for_ipv6_literal_target():
    tool = _tool(
        "dig",
        "host",
        "dns_reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "::1"},
        _profile("dig"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert "IP-literal target" in result.metadata["skip_reason"]


def test_dig_proceeds_for_hostname_target():
    tool = _tool(
        "dig",
        "host",
        "dns_reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "example.com"},
        _profile("dig"),
        executor,
    )

    assert result is None
