from scopeforgex.collectors.httpx import HTTPXCollector


def test_plain_text_httpx_record_extracts_leading_url():
    collector = HTTPXCollector()

    records = collector._iter_records(
        "http://127.0.0.1:3000 [200] [OWASP Juice Shop] []"
    )

    parsed = collector._parse_record(
        records[0]
    )

    assert parsed is not None
    assert parsed["url"] == (
        "http://127.0.0.1:3000"
    )


def test_plain_text_httpx_url_without_metadata_is_preserved():
    collector = HTTPXCollector()

    records = collector._iter_records(
        "http://127.0.0.1:3000"
    )

    parsed = collector._parse_record(
        records[0]
    )

    assert parsed is not None
    assert parsed["url"] == (
        "http://127.0.0.1:3000"
    )
