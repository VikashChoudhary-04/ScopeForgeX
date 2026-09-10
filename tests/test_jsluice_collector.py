from __future__ import annotations

from scopeforgex.collectors.registry import create_collector


TARGET = "http://127.0.0.1:3000"
SOURCE = "http://127.0.0.1:3000/main.js"


def test_jsluice_relative_url_field_becomes_api_reference() -> None:
    collector = create_collector("jsluice")

    record = {
        "filename": SOURCE,
        "source": '"/api/Products"',
        "type": "stringLiteral",
        "url": "/api/Products",
    }

    parsed = collector._parse_record(
        record,
        target=TARGET,
    )

    assert parsed is not None
    assert parsed["url"] is None
    assert parsed["endpoint"] == "/api/Products"
    assert parsed["source_url"] == TARGET

    observations = collector._extract_observations(
        parsed
    )

    assert len(observations) == 1

    observation = observations[0]

    assert observation["observation_type"] == "API_REFERENCE"
    assert observation["value"] == "/api/Products"
    assert observation["url"] == (
        "http://127.0.0.1:3000/api/Products"
    )


def test_jsluice_relative_rest_reference_becomes_api_reference() -> None:
    collector = create_collector("jsluice")

    record = {
        "filename": SOURCE,
        "source": '"/rest/admin"',
        "type": "stringLiteral",
        "url": "/rest/admin",
    }

    parsed = collector._parse_record(
        record,
        target=TARGET,
    )

    assert parsed is not None
    assert parsed["endpoint"] == "/rest/admin"

    observations = collector._extract_observations(
        parsed
    )

    assert len(observations) == 1

    observation = observations[0]

    assert observation["observation_type"] == "API_REFERENCE"
    assert observation["value"] == "/rest/admin"
    assert observation["url"] == (
        "http://127.0.0.1:3000/rest/admin"
    )


def test_jsluice_relative_reference_preserves_query() -> None:
    collector = create_collector("jsluice")

    record = {
        "filename": SOURCE,
        "source": '"/rest/user/security-question?email="',
        "type": "stringLiteral",
        "url": "/rest/user/security-question?email=",
    }

    parsed = collector._parse_record(
        record,
        target=TARGET,
    )

    assert parsed is not None

    observations = collector._extract_observations(
        parsed
    )

    assert len(observations) == 1

    observation = observations[0]

    assert observation["value"] == (
        "/rest/user/security-question?email="
    )

    assert observation["url"] == (
        "http://127.0.0.1:3000/rest/user/security-question?email="
    )


def test_jsluice_absolute_url_behavior_is_preserved() -> None:
    collector = create_collector("jsluice")

    absolute_url = (
        "https://example.com/static/app.js"
    )

    record = {
        "filename": absolute_url,
        "source": absolute_url,
        "type": "url",
        "url": absolute_url,
    }

    parsed = collector._parse_record(
        record,
        target=TARGET,
    )

    assert parsed is not None
    assert parsed["url"] == absolute_url

    observations = collector._extract_observations(
        parsed
    )

    assert observations

    assert any(
        observation["url"] == absolute_url
        for observation in observations
    )


def test_jsluice_related_url_resolves_without_network_access() -> None:
    collector = create_collector("jsluice")

    result = collector._related_url(
        "/api/Products",
        TARGET,
    )

    assert result == (
        "http://127.0.0.1:3000/api/Products"
    )


def test_jsluice_raw_evidence_is_preserved() -> None:
    collector = create_collector("jsluice")

    record = {
        "filename": SOURCE,
        "source": '"/api/Products"',
        "type": "stringLiteral",
        "url": "/api/Products",
    }

    parsed = collector._parse_record(
        record,
        target=TARGET,
    )

    assert parsed is not None
    assert parsed["raw"] == record
    assert parsed["metadata"] == record


def test_jsluice_target_is_used_as_resolution_base() -> None:
    collector = create_collector("jsluice")

    record = {
        "filename": "not-an-http-url",
        "source": '"/api/Products"',
        "type": "stringLiteral",
        "url": "/api/Products",
    }

    parsed = collector._parse_record(
        record,
        target=TARGET,
    )

    assert parsed is not None
    assert parsed["source_url"] == TARGET

    observations = collector._extract_observations(
        parsed
    )

    assert observations[0]["url"] == (
        "http://127.0.0.1:3000/api/Products"
    )
