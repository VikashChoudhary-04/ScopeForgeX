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
    phase: str = "vulnerability_validation",
):
    return SimpleNamespace(
        name=name,
        input_type=input_type,
        capability=capability,
        phase=phase,
    )


def _profile(
    name: str,
    section: str = "validation",
):
    return {
        section: {
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


def test_amass_conditional_proceeds_for_domain_target():
    tool = _tool(
        "amass",
        "domain",
        "attack_surface_discovery",
        phase="reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "example.com"},
        _profile("amass", section="reconnaissance"),
        executor,
    )

    assert result is None


def test_amass_conditional_proceeds_for_https_domain_target():
    tool = _tool(
        "amass",
        "domain",
        "attack_surface_discovery",
        phase="reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "https://example.com"},
        _profile("amass", section="reconnaissance"),
        executor,
    )

    assert result is None


def test_amass_skipped_for_localhost_target():
    tool = _tool(
        "amass",
        "domain",
        "attack_surface_discovery",
        phase="reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "localhost"},
        _profile("amass", section="reconnaissance"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert "no applicable domain target" in result.metadata["skip_reason"]


def test_amass_skipped_for_localhost_url_target():
    tool = _tool(
        "amass",
        "domain",
        "attack_surface_discovery",
        phase="reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "http://localhost:3000"},
        _profile("amass", section="reconnaissance"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert "no applicable domain target" in result.metadata["skip_reason"]


def test_amass_skipped_for_ipv4_target():
    tool = _tool(
        "amass",
        "domain",
        "attack_surface_discovery",
        phase="reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "127.0.0.1"},
        _profile("amass", section="reconnaissance"),
        executor,
    )

    assert result is not None
    assert result.status == "skipped"
    assert "IP-literal target" in result.metadata["skip_reason"]


def test_amass_skipped_for_ipv6_target():
    tool = _tool(
        "amass",
        "domain",
        "attack_surface_discovery",
        phase="reconnaissance",
    )

    executor = FakeExecutor()

    result = _conditional_tool_skip_result(
        tool,
        {"target": "::1"},
        _profile("amass", section="reconnaissance"),
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

def test_stage4_url_validation_target_promotes_projected_url_without_mutating_context():
    from scopeforgex.workflow import _stage4_url_validation_target

    tool = _tool(
        "sqlmap",
        "url",
        "sql_injection_validation",
    )

    ctx = {
        "target": "example.test",
        "input_data": (
            "http://example.test/login?id=1",
        ),
    }

    result = _stage4_url_validation_target(
        tool,
        ctx,
    )

    assert result == "http://example.test/login?id=1"
    assert ctx["target"] == "example.test"


def test_stage4_url_validation_target_accepts_https():
    from scopeforgex.workflow import _stage4_url_validation_target

    tool = _tool(
        "dalfox",
        "url",
        "xss_validation",
    )

    ctx = {
        "target": "example.test",
        "input_data": (
            "https://example.test/search?q=test",
        ),
    }

    result = _stage4_url_validation_target(
        tool,
        ctx,
    )

    assert result == "https://example.test/search?q=test"


def test_stage4_url_validation_target_returns_none_without_projected_url():
    from scopeforgex.workflow import _stage4_url_validation_target

    tool = _tool(
        "sstimap",
        "url",
        "ssti_validation",
    )

    ctx = {
        "target": "example.test",
        "input_data": (),
    }

    assert _stage4_url_validation_target(
        tool,
        ctx,
    ) is None


def test_stage4_url_validation_target_does_not_apply_to_other_phases():
    from scopeforgex.workflow import _stage4_url_validation_target

    tool = SimpleNamespace(
        name="katana",
        input_type="url",
        capability="endpoint_discovery",
        phase="enumeration",
    )

    ctx = {
        "target": "example.test",
        "input_data": (
            "http://example.test/",
        ),
    }

    assert _stage4_url_validation_target(
        tool,
        ctx,
    ) is None


def test_stage4_url_validation_target_does_not_accept_markdown_literal():
    from scopeforgex.workflow import _stage4_url_validation_target

    tool = _tool(
        "sqlmap",
        "url",
        "sql_injection_validation",
    )

    ctx = {
        "target": "example.test",
        "input_data": (
            "[http://example.test/](http://example.test/)",
        ),
    }

    assert _stage4_url_validation_target(
        tool,
        ctx,
    ) is None
