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

DEFAULT_TIMEOUT = 30
DEFAULT_CACHE_TTL = 86400

MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 2.0
MAX_RETRY_DELAY = 30.0


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
        timeout: int = DEFAULT_TIMEOUT,
        cache_ttl: int = DEFAULT_CACHE_TTL,
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

        self._catalog_cache: dict[
            str,
            Any,
        ] | None = None

        self._kev_index: dict[
            str,
            dict[str, Any],
        ] | None = None

    ###########################################################################
    # Catalog
    ###########################################################################

    def catalog(
        self,
    ) -> dict[str, Any]:
        """
        Return the cached or freshly downloaded KEV catalog.

        The catalog is retained in memory for the lifetime of this client so
        repeated CVE lookups do not repeatedly parse the same JSON document.
        """

        if self._catalog_cache is not None:
            return self._catalog_cache

        cached = self._read_cache()

        if cached is not None:
            self._catalog_cache = cached
            self._build_index(
                cached
            )
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

        for attempt in range(
            MAX_RETRIES + 1
        ):
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

                self._catalog_cache = payload

                self._build_index(
                    payload
                )

                return payload

            except HTTPError as exc:

                if (
                    exc.code != 429
                    or attempt >= MAX_RETRIES
                ):
                    return {}

                time.sleep(
                    self._retry_delay(
                        exc,
                        attempt,
                    )
                )

            except (
                URLError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
            ):
                return {}

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

        CVE lookup uses an in-memory index populated when the catalog is first
        loaded, avoiding a full catalog scan for every vulnerability.
        """

        identifier = str(
            cve
        ).strip().upper()

        if not identifier:
            return None

        catalog = self.catalog()

        if not catalog:
            return None

        if self._kev_index is None:
            self._build_index(
                catalog
            )

        if self._kev_index is None:
            return None

        entry = self._kev_index.get(
            identifier
        )

        if entry is None:
            return None

        return dict(
            entry
        )

    ###########################################################################
    # Index
    ###########################################################################

    def _build_index(
        self,
        payload: dict[str, Any],
    ) -> None:
        """
        Build a normalized CVE-to-KEV-entry lookup index.
        """

        entries = payload.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(
            entries,
            list,
        ):
            self._kev_index = {}
            return

        index: dict[
            str,
            dict[str, Any],
        ] = {}

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

            if not entry_id:
                continue

            if entry_id in index:
                continue

            index[
                entry_id
            ] = dict(
                entry
            )

        self._kev_index = index

    @staticmethod
    def _retry_delay(
        error: HTTPError,
        attempt: int,
    ) -> float:
        """
        Calculate a bounded retry delay for a rate-limit response.
        """

        retry_after = error.headers.get(
            "Retry-After"
        )

        if retry_after:
            try:
                delay = float(
                    retry_after
                )

                if delay >= 0:
                    return min(
                        delay,
                        MAX_RETRY_DELAY,
                    )

            except (
                TypeError,
                ValueError,
            ):
                pass

        return min(
            DEFAULT_RETRY_DELAY
            * (
                2 ** attempt
            ),
            MAX_RETRY_DELAY,
        )

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
