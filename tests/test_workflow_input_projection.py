from pathlib import Path
from types import SimpleNamespace

from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.tools.stage2_enum_web import HttpxTool
from scopeforgex.workflow import (
    _project_observation_inputs,
)


def _observation(
    *,
    observation_type="URL",
    value=None,
    url=None,
    host=None,
):
    return SimpleNamespace(
        observation_type=observation_type,
        value=value,
        url=url,
        host=host,
    )


def test_url_projection_filters_external_hosts_when_target_is_supplied():
    tool = SimpleNamespace(
        input_type="host_or_url_list",
        capability="http_service_enumeration",
    )

    observations = [
        _observation(
            observation_type="URL",
            url="http://example.com/login",
        ),
        _observation(
            observation_type="ENDPOINT",
            url="https://example.com/api/users",
        ),
        _observation(
            observation_type="URL",
            url="https://twitter.com/intent/tweet",
        ),
        _observation(
            observation_type="URL",
            url="https://google.com/",
        ),
        _observation(
            observation_type="URL",
            url="https://example.com.evil.test/",
        ),
    ]

    projected = _project_observation_inputs(
        tool,
        observations,
        "http://example.com:8080/assessment",
    )

    assert projected == (
        "http://example.com/login",
        "https://example.com/api/users",
    )


def test_url_projection_matches_ip_target_exactly_when_target_is_supplied():
    tool = SimpleNamespace(
        input_type="host_or_url_list",
        capability="http_service_enumeration",
    )

    observations = [
        _observation(
            observation_type="URL",
            url="http://127.0.0.1:3000/api",
        ),
        _observation(
            observation_type="URL",
            url="https://127.0.0.1:8443/login",
        ),
        _observation(
            observation_type="URL",
            url="http://127.0.0.2:3000/api",
        ),
    ]

    projected = _project_observation_inputs(
        tool,
        observations,
        "http://127.0.0.1:3000",
    )

    assert projected == (
        "http://127.0.0.1:3000/api",
        "https://127.0.0.1:8443/login",
    )


def test_url_projection_does_not_implicitly_authorize_subdomains():
    tool = SimpleNamespace(
        input_type="host_or_url_list",
        capability="http_service_enumeration",
    )

    observations = [
        _observation(
            observation_type="URL",
            url="https://example.com/",
        ),
        _observation(
            observation_type="URL",
            url="https://api.example.com/",
        ),
    ]

    projected = _project_observation_inputs(
        tool,
        observations,
        "https://example.com",
    )

    assert projected == (
        "https://example.com/",
    )


def test_url_projection_uses_normalized_observation_url():
    tool = SimpleNamespace(
        input_type="url",
    )

    observations = [
        _observation(
            observation_type="URL",
            value="http://example.com/",
            url="http://example.com/",
        ),
        _observation(
            observation_type="ENDPOINT",
            value="http://example.com/api",
            url="http://example.com/api",
        ),
    ]

    assert _project_observation_inputs(
        tool,
        observations,
    ) == (
        "http://example.com/",
        "http://example.com/api",
    )


def test_url_projection_deduplicates_and_rejects_non_urls():
    tool = SimpleNamespace(
        input_type="url",
    )

    observations = [
        _observation(
            observation_type="URL",
            value="http://example.com/",
            url="http://example.com/",
        ),
        _observation(
            observation_type="ENDPOINT",
            value="http://example.com/",
            url="http://example.com/",
        ),
        _observation(
            observation_type="PARAMETER",
            value="id",
            url="http://example.com/?id=1",
        ),
        _observation(
            observation_type="ROUTE",
            value="/api",
            url=None,
        ),
        _observation(
            observation_type="SERVICE",
            value="http",
            url=None,
        ),
    ]

    assert _project_observation_inputs(
        tool,
        observations,
    ) == (
        "http://example.com/",
    )


def test_url_projection_ignores_url_attached_to_non_url_observation():
    tool = SimpleNamespace(
        input_type="url",
    )

    observations = [
        _observation(
            observation_type="PARAMETER",
            value="id",
            url="http://example.com/?id=1",
        ),
        _observation(
            observation_type="FORM",
            value="login",
            url="http://example.com/login",
        ),
        _observation(
            observation_type="RESOURCE",
            value="script.js",
            url="http://example.com/script.js",
        ),
    ]

    assert _project_observation_inputs(
        tool,
        observations,
    ) == ()


def test_url_projection_can_use_absolute_value_when_url_is_missing():
    tool = SimpleNamespace(
        input_type="url",
    )

    observations = [
        _observation(
            observation_type="URL",
            value="https://example.org/login",
            url=None,
        ),
    ]

    assert _project_observation_inputs(
        tool,
        observations,
    ) == (
        "https://example.org/login",
    )


def test_non_url_input_type_does_not_receive_url_observations():
    tool = SimpleNamespace(
        input_type="jwt",
    )

    observations = [
        _observation(
            observation_type="URL",
            value="http://example.com/",
            url="http://example.com/",
        ),
    ]

    assert _project_observation_inputs(
        tool,
        observations,
    ) == ()


def test_httpx_uses_multiple_input_data_targets():
    context = ToolContext(
        target="http://original.example",
        output_dir=Path("/tmp/scopeforgex-httpx-test"),
        input_data=(
            "http://example.com/",
            "http://example.com/api",
        ),
    )

    arguments = HttpxTool(
        context
    ).build_arguments()

    assert arguments.count("-u") == 2
    assert arguments[-4:] == [
        "-u",
        "http://example.com/",
        "-u",
        "http://example.com/api",
    ]


def test_httpx_falls_back_to_original_target_without_input_data():
    context = ToolContext(
        target="http://original.example",
        output_dir=Path("/tmp/scopeforgex-httpx-test"),
        input_data=(),
    )

    arguments = HttpxTool(
        context
    ).build_arguments()

    assert arguments[-2:] == [
        "-u",
        "http://original.example",
    ]


def test_javascript_capability_projects_javascript_resource_only():
    from types import SimpleNamespace

    from scopeforgex.workflow import _project_observation_inputs

    tool = SimpleNamespace(
        input_type="url",
        capability="javascript_attack_surface_analysis",
    )

    observations = [
        SimpleNamespace(
            observation_type="RESOURCE",
            url="http://example.test/app.js",
            value="http://example.test/app.js",
            metadata={"resource_type": "javascript"},
        ),
        SimpleNamespace(
            observation_type="RESOURCE",
            url="http://example.test/styles.css",
            value="http://example.test/styles.css",
            metadata={"resource_type": "stylesheet"},
        ),
        SimpleNamespace(
            observation_type="URL",
            url="http://example.test/",
            value="http://example.test/",
            metadata={},
        ),
        SimpleNamespace(
            observation_type="JS_URL",
            url="http://example.test/runtime.js",
            value="http://example.test/runtime.js",
            metadata={},
        ),
        SimpleNamespace(
            observation_type="JS_ENDPOINT",
            url="http://example.test/api.js",
            value="http://example.test/api.js",
            metadata={},
        ),
    ]

    assert _project_observation_inputs(
        tool,
        observations,
    ) == (
        "http://example.test/app.js",
        "http://example.test/runtime.js",
        "http://example.test/api.js",
    )


def test_javascript_capability_rejects_non_javascript_resources():
    from types import SimpleNamespace

    from scopeforgex.workflow import _project_observation_inputs

    tool = SimpleNamespace(
        input_type="url",
        capability="javascript_attack_surface_analysis",
    )

    observations = [
        SimpleNamespace(
            observation_type="RESOURCE",
            url="http://example.test/styles.css",
            value="http://example.test/styles.css",
            metadata={"resource_type": "stylesheet"},
        ),
        SimpleNamespace(
            observation_type="RESOURCE",
            url="http://example.test/logo.png",
            value="http://example.test/logo.png",
            metadata={"resource_type": "image"},
        ),
        SimpleNamespace(
            observation_type="URL",
            url="http://example.test/",
            value="http://example.test/",
            metadata={},
        ),
    ]

    assert _project_observation_inputs(
        tool,
        observations,
    ) == ()


def test_non_javascript_url_consumer_keeps_generic_url_projection():
    from types import SimpleNamespace

    from scopeforgex.workflow import _project_observation_inputs

    tool = SimpleNamespace(
        input_type="url",
        capability="http_service_enumeration",
    )

    observations = [
        SimpleNamespace(
            observation_type="URL",
            url="http://example.test/",
            value="http://example.test/",
            metadata={},
        ),
        SimpleNamespace(
            observation_type="RESOURCE",
            url="http://example.test/app.js",
            value="http://example.test/app.js",
            metadata={"resource_type": "javascript"},
        ),
    ]

    assert _project_observation_inputs(
        tool,
        observations,
    ) == (
        "http://example.test/",
    )


def test_jsluice_observation_types_are_attack_surface_inventory():
    from scopeforgex.analysis.pipeline import AnalysisPipeline
    from scopeforgex.collectors.base import CollectorObservation

    pipeline = AnalysisPipeline()

    inventory_cases = (
        ("JS_ENDPOINT", "https://twitter.com/example", "twitter.com"),
        ("JS_URL", "https://googleapis.com/example.js", "googleapis.com"),
        ("API_REFERENCE", "https://example.com/api/docs", "example.com"),
    )

    for observation_type, url, host in inventory_cases:
        observation = CollectorObservation(
            observation_type=observation_type,
            value=url,
            target="http://127.0.0.1:3000",
            host=host,
            url=url,
            source_tool="jsluice",
            detection_method=f"JSLuice {observation_type}",
            confidence="informational",
        )

        assert pipeline._is_attack_surface_observation(observation) is True

    secret = CollectorObservation(
        observation_type="SECRET_CANDIDATE",
        value="potential-secret-value",
        target="http://127.0.0.1:3000",
        source_tool="jsluice",
        detection_method="JSLuice SECRET_CANDIDATE",
        confidence="informational",
    )

    assert pipeline._is_attack_surface_observation(secret) is False
