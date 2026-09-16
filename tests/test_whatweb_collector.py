from scopeforgex.collectors.whatweb import WhatWebCollector
from scopeforgex.models.execution_result import ExecutionResult


def test_ansi_formatted_markdown_text_preserves_raw_evidence_and_cleans_asset_fields():
    collector = WhatWebCollector()

    raw = (
        "\x1b[1m\x1b[34m"
        "[https://warrantyindia.com](https://warrantyindia.com)"
        " [200 OK] "
        "\x1b[1mApache\x1b[0m, "
        "\x1b[1mBootstrap\x1b[0m"
        "[\x1b[1m\x1b[32m4.5.2\x1b[0m]"
    )

    execution_result = ExecutionResult.success_result(
        tool="whatweb",
        capability="test_whatweb",
        stdout=raw,
        stderr="",
        artifacts=[],
    )

    observations = collector.parse(
        execution_result,
        {
            "target": "warrantyindia.com",
        },
    )

    assert observations

    for observation in observations:
        assert observation.url == "https://warrantyindia.com"
        assert observation.host == "warrantyindia.com"

        assert "\x1b" not in observation.url
        assert "\x1b" not in observation.host
        assert "\x1b" not in observation.evidence["technology"]

        if "version" in observation.evidence:
            assert "\x1b" not in observation.evidence["version"]

    assert observations[0].evidence["record"] == raw
    assert "\x1b" in observations[0].evidence["record"]


def test_text_parser_unwraps_clean_markdown_url():
    collector = WhatWebCollector()

    raw = (
        "[https://warrantyindia.com](https://warrantyindia.com/)"
        " [200 OK] Apache, Bootstrap[4.5.2]"
    )

    parsed = collector._parse_text_record(raw)

    assert parsed
    assert parsed[0]["url"] == "https://warrantyindia.com/"


def test_text_parser_preserves_plain_url_support():
    collector = WhatWebCollector()

    raw = (
        "https://warrantyindia.com"
        " [200 OK] Apache, Bootstrap[4.5.2]"
    )

    parsed = collector._parse_text_record(raw)

    assert parsed
    assert parsed[0]["url"] == "https://warrantyindia.com"
