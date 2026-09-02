"""
ScopeForgeX NVD Client
======================

Small, dependency-free client for the NVD 2.0 CPE and CVE APIs.

Design rules
------------

- Network access is explicitly opt-in.
- Responses are cached on disk.
- CPE resolution never guesses between ambiguous candidates.
- CVE applicability is evaluated against a specific CPE name.
- NVD results represent vulnerability intelligence, not target-specific
  exploitation confirmation.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_BASE_URL = (
    "https://services.nvd.nist.gov/rest/json"
)

CPE_ENDPOINT = (
    f"{NVD_BASE_URL}/cpes/2.0"
)

CVE_ENDPOINT = (
    f"{NVD_BASE_URL}/cves/2.0"
)

DEFAULT_TIMEOUT = 30

DEFAULT_CACHE_TTL = 86400


def _cache_key(
    url: str,
    params: dict[str, Any],
) -> str:
    """
    Build a stable cache key for one API request.
    """

    query = urlencode(
        sorted(
            (
                str(key),
                str(value),
            )
            for key, value in params.items()
        )
    )

    return hashlib.sha256(
        f"{url}?{query}".encode(
            "utf-8"
        )
    ).hexdigest()


def _copy(
    value: Any,
) -> Any:
    """
    Return a JSON-safe deep copy.
    """

    return json.loads(
        json.dumps(
            value
        )
    )


class NVDClient:
    """
    Dependency-free NVD 2.0 API client.

    The client is intentionally usable without third-party dependencies so
    ScopeForgeX does not need another package merely to consume NVD data.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        cache_dir: str | Path = (
            ".cache/scopeforgex/nvd"
        ),
        timeout: int = DEFAULT_TIMEOUT,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        allow_network: bool = False,
        user_agent: str = (
            "ScopeForgeX-"
            "Vulnerability-Intelligence/1.0"
        ),
    ) -> None:
        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero."
            )

        if cache_ttl < 0:
            raise ValueError(
                "cache_ttl cannot be negative."
            )

        self.api_key = (
            api_key
            or os.getenv(
                "NVD_API_KEY"
            )
            or None
        )

        self.cache_dir = Path(
            cache_dir
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

        self.user_agent = (
            user_agent
        )

    ###########################################################################
    # CPE Search
    ###########################################################################

    def search_cpes(
        self,
        *,
        keyword: str,
        version: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Return CPE candidates matching a product keyword and optional version.

        This is candidate discovery only. It does not itself establish that
        a vulnerability applies.
        """

        keyword = str(
            keyword
        ).strip()

        if not keyword:
            return []

        payload = self._get_json(
            CPE_ENDPOINT,
            {
                "keywordSearch": keyword,
                "resultsPerPage": min(
                    max(
                        int(limit),
                        1,
                    ),
                    10000,
                ),
            },
        )

        products = payload.get(
            "products",
            [],
        )

        if not isinstance(
            products,
            list,
        ):
            return []

        candidates: list[
            dict[str, Any]
        ] = []

        for item in products:
            if not isinstance(
                item,
                dict,
            ):
                continue

            cpe = item.get(
                "cpe",
                {},
            )

            if not isinstance(
                cpe,
                dict,
            ):
                continue

            criteria = (
                cpe.get(
                    "criteria"
                )
                or cpe.get(
                    "cpe23Uri"
                )
                or ""
            )

            if (
                not isinstance(
                    criteria,
                    str,
                )
                or not criteria
            ):
                continue

            if (
                version
                and not self._candidate_version_matches(
                    criteria,
                    version,
                )
            ):
                continue

            candidates.append(
                _copy(
                    item
                )
            )

        return candidates

    ###########################################################################
    # CPE Resolution
    ###########################################################################

    def resolve_cpe(
        self,
        *,
        product: str,
        version: str | None = None,
        vendor: str | None = None,
    ) -> tuple[str | None, list[str]]:
        """
        Resolve an observed product/version to one CPE.

        Returns:

            (
                resolved_cpe,
                candidate_cpes,
            )

        A CPE is returned only when the candidate set contains exactly one
        identity.

        Ambiguous results return ``None`` instead of manufacturing a CPE.
        """

        terms = [
            str(value).strip()
            for value in (
                vendor,
                product,
            )
            if value
            and str(value).strip()
        ]

        if not terms:
            return (
                None,
                [],
            )

        candidates = self.search_cpes(
            keyword=" ".join(
                terms
            ),
            version=version,
        )

        cpes: list[str] = []

        for item in candidates:
            cpe = item.get(
                "cpe",
                {},
            )

            if not isinstance(
                cpe,
                dict,
            ):
                continue

            criteria = (
                cpe.get(
                    "criteria"
                )
                or cpe.get(
                    "cpe23Uri"
                )
                or ""
            )

            if (
                isinstance(
                    criteria,
                    str,
                )
                and criteria
            ):
                cpes.append(
                    criteria
                )

        unique = list(
            dict.fromkeys(
                cpes
            )
        )

        if len(unique) == 1:
            return (
                unique[0],
                unique,
            )

        return (
            None,
            unique,
        )

    ###########################################################################
    # CVE Applicability
    ###########################################################################

    def cves_for_cpe(
        self,
        cpe: str,
        *,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        """
        Return NVD CVE records applicable to the supplied CPE name.
        """

        cpe = str(
            cpe
        ).strip()

        if not cpe:
            return []

        payload = self._get_json(
            CVE_ENDPOINT,
            {
                "cpeName": cpe,
                "resultsPerPage": min(
                    max(
                        int(limit),
                        1,
                    ),
                    2000,
                ),
            },
        )

        vulnerabilities = payload.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(
            vulnerabilities,
            list,
        ):
            return []

        return [
            _copy(
                item
            )
            for item in vulnerabilities
            if isinstance(
                item,
                dict,
            )
        ]

    ###########################################################################
    # HTTP / Cache
    ###########################################################################

    def _get_json(
        self,
        url: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Get one JSON API response through the local cache when possible.
        """

        cache_file = (
            self.cache_dir
            / (
                f"{_cache_key(url, params)}"
                ".json"
            )
        )

        cached = self._read_cache(
            cache_file
        )

        if cached is not None:
            return cached

        if not self.allow_network:
            return {}

        headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }

        if self.api_key:
            headers[
                "apiKey"
            ] = self.api_key

        try:
            query = urlencode(
                params
            )

            request = Request(
                f"{url}?{query}",
                headers=headers,
                method="GET",
            )

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
                cache_file,
                payload,
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

    def _read_cache(
        self,
        cache_file: Path,
    ) -> dict[str, Any] | None:
        """
        Read a valid cached response.
        """

        try:
            if (
                not cache_file.is_file()
                or self.cache_ttl == 0
            ):
                return None

            age = (
                time.time()
                - cache_file.stat().st_mtime
            )

            if age > self.cache_ttl:
                return None

            payload = json.loads(
                cache_file.read_text(
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

    @staticmethod
    def _candidate_version_matches(
        cpe: str,
        version: str,
    ) -> bool:
        """
        Perform a conservative candidate-level version check.

        NVD remains authoritative for actual CVE applicability.
        """

        parts = cpe.split(
            ":"
        )

        if len(parts) != 13:
            return False

        cpe_version = parts[5]

        if cpe_version in {
            "*",
            "-",
        }:
            return True

        return (
            cpe_version.lower()
            == str(
                version
            ).strip().lower()
        )

    def _write_cache(
        self,
        cache_file: Path,
        payload: dict[str, Any],
    ) -> None:
        """
        Atomically write one API response to disk.
        """

        try:
            cache_file.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            temporary = (
                cache_file.with_suffix(
                    ".tmp"
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
                cache_file
            )

        except OSError:
            pass


__all__ = [
    "CPE_ENDPOINT",
    "CVE_ENDPOINT",
    "NVD_BASE_URL",
    "NVDClient",
]
