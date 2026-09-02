"""
ScopeForgeX CISA KEV Client
===========================

Cache-aware reader for the CISA Known Exploited Vulnerabilities catalog.

KEV is an enrichment and prioritization signal. It does not establish that
the assessed target is compromised or that a vulnerability is exploitable on
that particular target.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KEVClient:
    """
    Read and optionally refresh the CISA KEV catalog.
    """

    def __init__(
        self,
        *,
        cache_file: str | Path = (
            ".cache/scopeforgex/kev/"
            "known_exploited_vulnerabilities.json"
        ),
        timeout: int = 30,
        cache_ttl: int = 86400,
        allow_network: bool = False,
    ) -> None:
        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero."
            )

        if cache_ttl < 0:
            raise ValueError(
                "cache_ttl cannot be negative."
            )

        self.cache_file = Path(
            cache_file
        )

        self.timeout = int(
            timeout
        )

        self.cache_ttl = int(
            cache_ttl
        )

        self.allow_network = bool(
            allow_network
        )

    ###########################################################################
    # Catalog
    ###########################################################################

    def catalog(
        self,
    ) -> dict[str, Any]:
        """
        Return the cached or freshly downloaded KEV catalog.
        """

        cached = self._read_cache()

        if cached is not None:
            return cached

        if not self.allow_network:
            return {}

        request = Request(
            KEV_URL,
            headers={
                "Accept": "application/json",
                "User-Agent": (
                    "ScopeForgeX-"
                    "Vulnerability-Intelligence/1.0"
                ),
            },
            method="GET",
        )

        try:
            with urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                payload = json.loads(
                    response.read().decode(
                        "utf-8",
                        errors="replace",
                    )
                )

            if not isinstance(
                payload,
                dict,
            ):
                return {}

            self._write_cache(
                payload
            )

            return payload

        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ):
            return {}

    ###########################################################################
    # Lookup
    ###########################################################################

    def find(
        self,
        cve: str,
    ) -> dict[str, Any] | None:
        """
        Return the KEV entry for one CVE when present.
        """

        identifier = str(
            cve
        ).strip().upper()

        if not identifier:
            return None

        entries = self.catalog().get(
            "vulnerabilities",
            [],
        )

        if not isinstance(
            entries,
            list,
        ):
            return None

        for entry in entries:
            if not isinstance(
                entry,
                dict,
            ):
                continue

            entry_id = str(
                entry.get(
                    "cveID",
                    "",
                )
            ).strip().upper()

            if entry_id == identifier:
                return dict(
                    entry
                )

        return None

    ###########################################################################
    # Cache
    ###########################################################################

    def _read_cache(
        self,
    ) -> dict[str, Any] | None:
        """
        Read an unexpired KEV catalog cache.
        """

        try:
            if (
                not self.cache_file.is_file()
                or self.cache_ttl == 0
            ):
                return None

            age = (
                time.time()
                - self.cache_file.stat().st_mtime
            )

            if age > self.cache_ttl:
                return None

            payload = json.loads(
                self.cache_file.read_text(
                    encoding="utf-8"
                )
            )

            if isinstance(
                payload,
                dict,
            ):
                return payload

            return None

        except (
            OSError,
            ValueError,
            json.JSONDecodeError,
        ):
            return None

    def _write_cache(
        self,
        payload: dict[str, Any],
    ) -> None:
        """
        Atomically write the KEV catalog cache.
        """

        try:
            self.cache_file.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            temporary = (
                self.cache_file.with_name(
                    self.cache_file.name
                    + ".tmp"
                )
            )

            temporary.write_text(
                json.dumps(
                    payload,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            temporary.replace(
                self.cache_file
            )

        except OSError:
            pass


__all__ = [
    "KEV_URL",
    "KEVClient",
]
