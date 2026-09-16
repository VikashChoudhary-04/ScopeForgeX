from scopeforgex.findings.normalizer import FindingNormalizer


def test_url_normalization_contract():
    normalizer = FindingNormalizer()

    cases = (
        (
            "plain_http",
            "http://example.com",
            "http://example.com",
        ),
        (
            "plain_https",
            "https://example.com/path",
            "https://example.com/path",
        ),
        (
            "markdown_http",
            "[http://example.com](http://example.com/)",
            "http://example.com/",
        ),
        (
            "markdown_https",
            "[https://example.com/path](https://example.com/path)",
            "https://example.com/path",
        ),
        (
            "ansi",
            "\x1b[1mhttps://example.com/path\x1b[0m",
            "https://example.com/path",
        ),
        (
            "ansi_markdown",
            "\x1b[1m"
            "[https://example.com/path]"
            "(https://example.com/path\x1b[0m)"
            "\x1b[0m",
            "https://example.com/path",
        ),
    )

    for name, value, expected in cases:
        finding = normalizer.normalize(
            {
                "finding_id": f"NORMALIZER-URL-{name.upper()}",
                "title": "URL normalization test",
                "target": "example.com",
                "url": value,
                "evidence": {
                    "record": value,
                },
            }
        )

        assert finding.url == expected, (
            f"{name}: expected {expected!r}, got {finding.url!r}"
        )

        # Canonical normalization must never mutate raw evidence.
        assert finding.evidence["record"] == value
