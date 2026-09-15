"""
ScopeForgeX NVD Client
======================

Small, dependency-free client for the NVD 2.0 CPE and CVE APIs.

Design rules
------------

- Network access is explicitly opt-in.
- Responses are cached on disk.
- CPE resolution never guesses between ambiguous candidates.
- CVE applicability is evaluated against NVD applicability statements.
- NVD results represent vulnerability intelligence, not target-specific
  exploitation confirmation.
- Paginated NVD responses are consumed up to the requested result limit.
- Transient NVD rate limiting is handled with bounded retries.
- Product/version CVE correlation uses NVD virtualMatchString candidate
  discovery followed by local evaluation of the returned applicability
  statements.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
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

DEFAULT_PAGE_SIZE = 2000

MAX_CPE_PAGE_SIZE = 10000

MAX_CVE_PAGE_SIZE = 2000

MAX_RETRIES = 3

DEFAULT_RETRY_DELAY = 2.0

MAX_RETRY_DELAY = 30.0

_CPE_23_FIELD_COUNT = 13

_CPE_VERSION_INDEX = 5


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


def _positive_int(
    value: Any,
    default: int,
) -> int:
    """
    Normalize a positive integer value.
    """

    try:
        normalized = int(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return default

    if normalized <= 0:
        return default

    return normalized


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

        This is candidate discovery only. It does not establish vulnerability
        applicability.

        NVD CPE API records contain the actual CPE name under:

            products[].cpe.cpeName
        """

        keyword = str(
            keyword
        ).strip()

        if not keyword:
            return []

        requested_limit = min(
            _positive_int(
                limit,
                100,
            ),
            MAX_CPE_PAGE_SIZE,
        )

        candidates: list[
            dict[str, Any]
        ] = []

        start_index = 0

        while len(candidates) < requested_limit:
            remaining = (
                requested_limit
                - len(candidates)
            )

            page_size = min(
                remaining,
                MAX_CPE_PAGE_SIZE,
            )

            payload = self._get_json(
                CPE_ENDPOINT,
                {
                    "keywordSearch": keyword,
                    "startIndex": start_index,
                    "resultsPerPage": page_size,
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
                break

            if not products:
                break

            processed = 0

            for item in products:
                processed += 1

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

                cpe_name = (
                    self._cpe_name_from_record(
                        cpe
                    )
                )

                if not cpe_name:
                    continue

                if (
                    version
                    and not self._candidate_version_matches(
                        cpe_name,
                        version,
                    )
                ):
                    continue

                candidates.append(
                    _copy(item)
                )

                if (
                    len(candidates)
                    >= requested_limit
                ):
                    break

            if processed == 0:
                break

            start_index += processed

            total_results = (
                self._total_results(
                    payload
                )
            )

            if (
                total_results is not None
                and start_index >= total_results
            ):
                break

            if len(products) < page_size:
                break

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
        Resolve an observed product/version to one CPE identity.

        NVD keyword search is intentionally broad. Multiple CPE records can
        therefore describe the same product family, platform-specific
        variants, or unrelated products containing the search term.

        Resolution is conservative and generic:

        * exact CPE product identity is preferred;
        * an explicitly supplied vendor is preferred when it matches;
        * an exact observed version is strongly preferred;
        * stable/base CPEs are preferred over release/update variants when
          the observation provides no corresponding qualifier;
        * unrelated keyword matches are rejected;
        * genuine ambiguity remains unresolved.

        When no exact-version candidate can be selected, the resolver falls
        back to a unique product family.
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

        keyword = " ".join(
            terms
        )

        candidates = self.search_cpes(
            keyword=keyword,
            version=version,
            limit=100,
        )

        ranked = self._rank_cpe_candidates(
            candidates=candidates,
            product=product,
            vendor=vendor,
            version=version,
        )

        if ranked:
            best_score = ranked[0][0]

            best = [
                cpe_name
                for score, cpe_name
                in ranked
                if score == best_score
            ]

            if len(best) == 1:
                return (
                    best[0],
                    list(
                        dict.fromkeys(
                            cpe_name
                            for _, cpe_name
                            in ranked
                        )
                    ),
                )

            return (
                None,
                list(
                    dict.fromkeys(
                        cpe_name
                        for _, cpe_name
                        in ranked
                    )
                ),
            )

        # If the version-aware lookup did not produce a usable identity,
        # retry without a version filter so a unique product family can
        # still be resolved when the exact version is absent from NVD.
        family_candidates = self.search_cpes(
            keyword=keyword,
            version=None,
            limit=100,
        )

        family_ranked = self._rank_cpe_candidates(
            candidates=family_candidates,
            product=product,
            vendor=vendor,
            version=None,
        )

        families: list[str] = []

        for _, cpe_name in family_ranked:
            family = self._virtual_match_cpe(
                cpe_name
            )

            if family:
                families.append(
                    family
                )

        unique_families = list(
            dict.fromkeys(
                families
            )
        )

        if len(unique_families) == 1:
            return (
                unique_families[0],
                unique_families,
            )

        return (
            None,
            unique_families,
        )

    @classmethod
    def _rank_cpe_candidates(
        cls,
        *,
        candidates: list[dict[str, Any]],
        product: str,
        vendor: str | None,
        version: str | None,
    ) -> list[tuple[int, str]]:
        """
        Rank NVD CPE records using generic CPE identity signals.

        No product-specific mappings are used. The ranking only considers
        structured CPE components and NVD CPE titles.
        """

        requested_product = cls._normalize_cpe_identity(
            product
        )

        requested_vendor = cls._normalize_cpe_identity(
            vendor
        )

        requested_version = (
            str(version).strip()
            if version
            else ""
        )

        ranked: list[tuple[int, str]] = []

        for item in candidates:
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

            cpe_name = cls._cpe_name_from_record(
                cpe
            )

            if not cpe_name:
                continue

            parts = cls._parse_cpe23(
                cpe_name
            )

            if parts is None:
                continue

            cpe_vendor = cls._normalize_cpe_identity(
                cls._unescape_cpe_component(
                    parts[3]
                )
            )

            cpe_product = cls._normalize_cpe_identity(
                cls._unescape_cpe_component(
                    parts[4]
                )
            )

            cpe_version = cls._unescape_cpe_component(
                parts[_CPE_VERSION_INDEX]
            )

            titles = cpe.get(
                "titles",
                [],
            )

            title_text = " ".join(
                str(entry.get("title", ""))
                for entry in titles
                if isinstance(
                    entry,
                    dict,
                )
            )

            normalized_title = cls._normalize_cpe_identity(
                title_text
            )

            score = 0

            # Product identity is mandatory. Exact CPE product equality is
            # strongest; a title match is weaker and exists for names whose
            # human form differs from the CPE component.
            if (
                requested_product
                and cpe_product == requested_product
            ):
                score += 100
            elif (
                requested_product
                and requested_product in normalized_title
            ):
                score += 40
            else:
                continue

            # An explicit vendor is an additional identity constraint.
            if requested_vendor:
                if cpe_vendor == requested_vendor:
                    score += 50
                elif requested_vendor in normalized_title:
                    score += 15
                else:
                    continue

            # Exact observed versions are strongly preferred. NVD search_cpes
            # already filters fixed version candidates, but this also handles
            # direct/mock candidate sets safely.
            if requested_version:
                if (
                    cpe_version not in {
                        "*",
                        "-",
                    }
                    and cls._version_equal(
                        cpe_version,
                        requested_version,
                    )
                ):
                    score += 100
                elif cpe_version == "*":
                    score += 10
                else:
                    continue

            # When no qualifier was observed, prefer the base/stable CPE.
            # '*' means ANY and is the canonical unqualified value.
            # '-' means NOT APPLICABLE and should not tie with '*'.
            update = parts[6]

            if update == "*":
                score += 20
            elif update == "-":
                score -= 10
            else:
                score -= 20

            # Platform/deployment-specific identities should only win when
            # the observed evidence supplies a corresponding signal. Since
            # resolve_cpe currently receives only product/vendor/version,
            # such qualifiers are conservatively penalized.
            qualifiers = (
                parts[7],   # edition
                parts[8],   # language
                parts[9],   # sw_edition
                parts[10],  # target_sw
                parts[11],  # target_hw
                parts[12],  # other
            )

            for qualifier in qualifiers:
                if qualifier not in {
                    "*",
                    "-",
                    "",
                }:
                    score -= 10

            if item.get("deprecated") is True:
                score -= 25

            ranked.append(
                (
                    score,
                    cpe_name,
                )
            )

        return sorted(
            ranked,
            key=lambda entry: (
                -entry[0],
                entry[1],
            ),
        )

    @staticmethod
    def _normalize_cpe_identity(
        value: str | None,
    ) -> str:
        """
        Normalize human/CPE identity text for generic comparison.

        Separators and punctuation are ignored so human names such as
        ``http-server`` and CPE components such as ``http_server`` can be
        compared without product-specific aliases.
        """

        return re.sub(
            r"[^a-z0-9]+",
            "",
            str(
                value or ""
            ).strip().lower(),
        )

    ###########################################################################
    # CVE Candidate Discovery
    ###########################################################################

    def search_cves(
        self,
        *,
        keyword: str,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        """
        Retrieve CVE records using NVD keyword search.

        This method is retained for generic CVE discovery.

        It must not be treated as authoritative product/version correlation.
        For software applicability, use cves_for_software(), which uses
        NVD's virtualMatchString mechanism.
        """

        keyword = str(
            keyword
        ).strip()

        if not keyword:
            return []

        requested_limit = min(
            _positive_int(
                limit,
                DEFAULT_PAGE_SIZE,
            ),
            MAX_CVE_PAGE_SIZE,
        )

        return self._paginate_cve_request(
            {
                "keywordSearch": keyword,
            },
            requested_limit,
        )

    def search_cves_by_virtual_match_string(
        self,
        *,
        virtual_match_string: str,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        """
        Retrieve CVE candidates using NVD's virtualMatchString parameter.

        virtualMatchString is used only for candidate discovery. The returned
        CVE configurations must still be evaluated before a CVE is considered
        applicable to an observed software version.
        """

        virtual_match_string = str(
            virtual_match_string or ""
        ).strip()

        if not virtual_match_string:
            return []

        if not self._is_formatted_cpe_23(
            virtual_match_string
        ):
            return []

        requested_limit = min(
            _positive_int(
                limit,
                DEFAULT_PAGE_SIZE,
            ),
            MAX_CVE_PAGE_SIZE,
        )

        return self._paginate_cve_request(
            {
                "virtualMatchString": (
                    virtual_match_string
                ),
            },
            requested_limit,
        )

    def _paginate_cve_request(
        self,
        base_params: dict[str, Any],
        requested_limit: int,
    ) -> list[dict[str, Any]]:
        """
        Consume paginated CVE API responses up to requested_limit.
        """

        vulnerabilities: list[
            dict[str, Any]
        ] = []

        start_index = 0

        while len(vulnerabilities) < requested_limit:
            remaining = (
                requested_limit
                - len(vulnerabilities)
            )

            page_size = min(
                remaining,
                MAX_CVE_PAGE_SIZE,
            )

            params = dict(
                base_params
            )

            params.update(
                {
                    "startIndex": start_index,
                    "resultsPerPage": page_size,
                }
            )

            payload = self._get_json(
                CVE_ENDPOINT,
                params,
            )

            page = payload.get(
                "vulnerabilities",
                [],
            )

            if not isinstance(
                page,
                list,
            ):
                break

            if not page:
                break

            processed = 0

            for item in page:
                processed += 1

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                vulnerabilities.append(
                    _copy(item)
                )

                if (
                    len(vulnerabilities)
                    >= requested_limit
                ):
                    break

            if processed == 0:
                break

            start_index += processed

            total_results = (
                self._total_results(
                    payload
                )
            )

            if (
                total_results is not None
                and start_index >= total_results
            ):
                break

            if len(page) < page_size:
                break

        return vulnerabilities

    ###########################################################################
    # CVE Applicability
    ###########################################################################

    def cves_for_software(
        self,
        *,
        cpe: str,
        version: str,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        """
        Return CVEs whose NVD applicability rules match observed software.

        Pipeline:

            observed CPE
                |
                v
            virtualMatchString
                |
                v
            candidate CVEs
                |
                v
            NVD applicability configurations
                |
                v
            applicable CVEs

        The version is never treated as vulnerable merely because a CVE was
        returned by virtualMatchString.
        """

        cpe = str(
            cpe or ""
        ).strip()

        version = str(
            version or ""
        ).strip()

        if not cpe or not version:
            return []

        if not self._is_formatted_cpe_23(
            cpe
        ):
            return []

        virtual_match_string = (
            self._virtual_match_cpe(
                cpe
            )
        )

        if not virtual_match_string:
            return []

        records = (
            self.search_cves_by_virtual_match_string(
                virtual_match_string=(
                    virtual_match_string
                ),
                limit=limit,
            )
        )

        results: list[
            dict[str, Any]
        ] = []

        seen: set[str] = set()

        for record in records:
            cve = record.get(
                "cve",
                {},
            )

            if not isinstance(
                cve,
                dict,
            ):
                continue

            identifier = str(
                cve.get(
                    "id",
                    "",
                )
            ).strip().upper()

            if (
                not identifier
                or identifier in seen
            ):
                continue

            if not self._cve_applies_to_software(
                cve,
                cpe,
                version,
            ):
                continue

            seen.add(
                identifier
            )

            results.append(
                _copy(record)
            )

        return results

    def _cve_applies_to_software(
        self,
        cve: dict[str, Any],
        observed_cpe: str,
        observed_version: str,
    ) -> bool:
        """
        Determine whether at least one NVD configuration applies.
        """

        configurations = cve.get(
            "configurations",
            [],
        )

        if not isinstance(
            configurations,
            list,
        ):
            return False

        for configuration in configurations:
            if not isinstance(
                configuration,
                dict,
            ):
                continue

            if self._configuration_applies(
                configuration,
                observed_cpe,
                observed_version,
            ):
                return True

        return False

    def _configuration_applies(
        self,
        configuration: dict[str, Any],
        observed_cpe: str,
        observed_version: str,
    ) -> bool:
        """
        Evaluate one NVD configuration.

        NVD configurations normally contain one or more logical nodes.
        """

        nodes = configuration.get(
            "nodes",
            [],
        )

        if not isinstance(
            nodes,
            list,
        ):
            return False

        for node in nodes:
            if not isinstance(
                node,
                dict,
            ):
                continue

            if self._node_applies(
                node,
                observed_cpe,
                observed_version,
            ):
                return True

        return False

    def _node_applies(
        self,
        node: dict[str, Any],
        observed_cpe: str,
        observed_version: str,
    ) -> bool:
        """
        Evaluate one NVD logical applicability node.
        """

        evaluations: list[
            bool
        ] = []

        matches = node.get(
            "cpeMatch",
            [],
        )

        if isinstance(
            matches,
            list,
        ):
            for match in matches:
                if not isinstance(
                    match,
                    dict,
                ):
                    continue

                if match.get(
                    "vulnerable"
                ) is False:
                    continue

                criteria = str(
                    match.get(
                        "criteria",
                        "",
                    )
                ).strip()

                if not criteria:
                    continue

                evaluations.append(
                    self._cpe_match_applies(
                        match,
                        criteria,
                        observed_cpe,
                        observed_version,
                    )
                )

        children = node.get(
            "children",
            [],
        )

        if isinstance(
            children,
            list,
        ):
            for child in children:
                if not isinstance(
                    child,
                    dict,
                ):
                    continue

                evaluations.append(
                    self._node_applies(
                        child,
                        observed_cpe,
                        observed_version,
                    )
                )

        if not evaluations:
            return False

        operator = str(
            node.get(
                "operator",
                "OR",
            )
        ).upper()

        if operator == "AND":
            result = all(
                evaluations
            )
        else:
            result = any(
                evaluations
            )

        if node.get(
            "negate"
        ) is True:
            result = not result

        return result

    def _cpe_match_applies(
        self,
        match: dict[str, Any],
        criteria: str,
        observed_cpe: str,
        observed_version: str,
    ) -> bool:
        """
        Evaluate one NVD CPE match criterion.

        This method handles:

        - CPE identity matching
        - exact criteria versions
        - ANY (`*`)
        - NOT APPLICABLE (`-`)
        - versionStartIncluding
        - versionStartExcluding
        - versionEndIncluding
        - versionEndExcluding
        """

        criteria_parts = (
            self._parse_cpe23(
                criteria
            )
        )

        observed_parts = (
            self._parse_cpe23(
                observed_cpe
            )
        )

        if (
            criteria_parts is None
            or observed_parts is None
        ):
            return False

        for index in range(
            2,
            _CPE_23_FIELD_COUNT,
        ):
            if index == _CPE_VERSION_INDEX:
                continue

            expected = criteria_parts[
                index
            ]

            actual = observed_parts[
                index
            ]

            if expected == "*":
                continue

            if expected == "-":
                if actual != "-":
                    return False

                continue

            if not self._cpe_component_matches(
                expected,
                actual,
            ):
                return False

        criteria_version = (
            criteria_parts[
                _CPE_VERSION_INDEX
            ]
        )

        if criteria_version == "-":
            if (
                observed_parts[
                    _CPE_VERSION_INDEX
                ]
                != "-"
            ):
                return False

        elif criteria_version != "*":
            expected_version = (
                self._unescape_cpe_component(
                    criteria_version
                )
            )

            if not self._version_equal(
                observed_version,
                expected_version,
            ):
                return False

        return self._version_range_matches(
            observed_version,
            match,
        )

    @staticmethod
    def _cpe_component_matches(
        expected: str,
        actual: str,
    ) -> bool:
        """
        Compare non-version CPE components conservatively.
        """

        expected = (
            NVDClient._unescape_cpe_component(
                expected
            ).lower()
        )

        actual = (
            NVDClient._unescape_cpe_component(
                actual
            ).lower()
        )

        if expected == "*":
            return True

        if expected == "-":
            return actual == "-"

        return expected == actual

    @staticmethod
    def _parse_cpe23(
        cpe: str,
    ) -> list[str] | None:
        """
        Parse a CPE 2.3 formatted string.

        CPE 2.3 formatted strings contain 13 colon-separated fields:

            cpe:2.3:
                part:
                vendor:
                product:
                version:
                update:
                edition:
                language:
                sw_edition:
                target_sw:
                target_hw:
                other
        """

        parts = str(
            cpe or ""
        ).strip().split(
            ":"
        )

        if (
            len(parts)
            != _CPE_23_FIELD_COUNT
        ):
            return None

        if (
            parts[0].lower()
            != "cpe"
            or parts[1] != "2.3"
        ):
            return None

        return parts

    @staticmethod
    def _unescape_cpe_component(
        value: str,
    ) -> str:
        """
        Remove CPE formatted-string escaping conservatively.
        """

        text = str(
            value or ""
        )

        result: list[str] = []

        index = 0

        while index < len(text):
            character = text[
                index
            ]

            if (
                character == "\\"
                and index + 1 < len(text)
            ):
                index += 1
                result.append(
                    text[index]
                )
            else:
                result.append(
                    character
                )

            index += 1

        return "".join(
            result
        )

    @classmethod
    def _version_range_matches(
        cls,
        version: str,
        match: dict[str, Any],
    ) -> bool:
        """
        Evaluate NVD CPE Match Criteria version bounds.
        """

        start_including = match.get(
            "versionStartIncluding"
        )

        start_excluding = match.get(
            "versionStartExcluding"
        )

        end_including = match.get(
            "versionEndIncluding"
        )

        end_excluding = match.get(
            "versionEndExcluding"
        )

        if (
            start_including is not None
            and str(start_including).strip()
        ):
            if (
                cls._version_compare(
                    version,
                    str(start_including),
                )
                < 0
            ):
                return False

        if (
            start_excluding is not None
            and str(start_excluding).strip()
        ):
            if (
                cls._version_compare(
                    version,
                    str(start_excluding),
                )
                <= 0
            ):
                return False

        if (
            end_including is not None
            and str(end_including).strip()
        ):
            if (
                cls._version_compare(
                    version,
                    str(end_including),
                )
                > 0
            ):
                return False

        if (
            end_excluding is not None
            and str(end_excluding).strip()
        ):
            if (
                cls._version_compare(
                    version,
                    str(end_excluding),
                )
                >= 0
            ):
                return False

        return True

    @staticmethod
    def _version_equal(
        left: str,
        right: str,
    ) -> bool:
        return (
            NVDClient._version_compare(
                left,
                right,
            )
            == 0
        )

    @staticmethod
    def _version_compare(
        left: str,
        right: str,
    ) -> int:
        """
        Conservative natural version comparison.

        Numeric components compare numerically. Alphabetic components compare
        case-insensitively. This is intentionally dependency-free and is used
        only for vulnerability applicability correlation.
        """

        def tokenize(
            value: str,
        ) -> list[
            tuple[int, Any]
        ]:
            tokens = re.findall(
                r"[0-9]+|[A-Za-z]+",
                str(value).lower(),
            )

            result: list[
                tuple[int, Any]
            ] = []

            for token in tokens:
                if token.isdigit():
                    result.append(
                        (
                            1,
                            int(token),
                        )
                    )
                else:
                    result.append(
                        (
                            0,
                            token,
                        )
                    )

            return result

        first = tokenize(
            left
        )

        second = tokenize(
            right
        )

        for left_token, right_token in zip(
            first,
            second,
        ):
            if left_token == right_token:
                continue

            if (
                left_token[0]
                != right_token[0]
            ):
                return (
                    -1
                    if left_token[0]
                    < right_token[0]
                    else 1
                )

            return (
                -1
                if left_token[1]
                < right_token[1]
                else 1
            )

        if len(first) == len(second):
            return 0

        return (
            -1
            if len(first) < len(second)
            else 1
        )

    @staticmethod
    def _cpe_name_from_record(
        cpe: dict[str, Any],
    ) -> str:
        """
        Extract a CPE name from an NVD CPE record.

        NVD 2.0 CPE responses use:

            cpe.cpeName

        Older/alternate representations are accepted for compatibility.
        """

        value = (
            cpe.get(
                "cpeName"
            )
            or cpe.get(
                "criteria"
            )
            or cpe.get(
                "cpe23Uri"
            )
            or ""
        )

        if isinstance(
            value,
            list,
        ):
            if not value:
                return ""

            first = value[0]

            if isinstance(
                first,
                dict,
            ):
                value = (
                    first.get(
                        "cpeName"
                    )
                    or first.get(
                        "cpe23Uri"
                    )
                    or ""
                )
            else:
                value = first

        return (
            str(value).strip()
            if value
            else ""
        )

    @staticmethod
    def _virtual_match_cpe(
        cpe: str,
    ) -> str:
        """
        Convert an exact CPE name into an NVD virtualMatchString.

        Only the version field is replaced with ANY (`*`).
        """

        parts = NVDClient._parse_cpe23(
            cpe
        )

        if parts is None:
            return ""

        parts[
            _CPE_VERSION_INDEX
        ] = "*"

        return ":".join(
            parts
        )

    ###########################################################################
    # Backward-Compatible CVE Lookup
    ###########################################################################

    def cves_for_cpe(
        self,
        cpe: str,
        *,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        """
        Return CVEs associated with a supplied CPE name.

        This method remains for compatibility with the existing intelligence
        engine and tests.

        New product/version correlation should use cves_for_software().
        """

        cpe = str(
            cpe
        ).strip()

        if not cpe:
            return []

        requested_limit = min(
            _positive_int(
                limit,
                DEFAULT_PAGE_SIZE,
            ),
            MAX_CVE_PAGE_SIZE,
        )

        vulnerabilities: list[
            dict[str, Any]
        ] = []

        start_index = 0

        while len(vulnerabilities) < requested_limit:
            remaining = (
                requested_limit
                - len(vulnerabilities)
            )

            page_size = min(
                remaining,
                MAX_CVE_PAGE_SIZE,
            )

            payload = self._get_json(
                CVE_ENDPOINT,
                {
                    "cpeName": cpe,
                    "startIndex": start_index,
                    "resultsPerPage": page_size,
                },
            )

            page = payload.get(
                "vulnerabilities",
                [],
            )

            if not isinstance(
                page,
                list,
            ):
                break

            if not page:
                break

            processed = 0

            for item in page:
                processed += 1

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                vulnerabilities.append(
                    _copy(item)
                )

                if (
                    len(vulnerabilities)
                    >= requested_limit
                ):
                    break

            if processed == 0:
                break

            start_index += processed

            total_results = (
                self._total_results(
                    payload
                )
            )

            if (
                total_results is not None
                and start_index >= total_results
            ):
                break

            if len(page) < page_size:
                break

        return vulnerabilities

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

        Network access remains explicitly opt-in.
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

        for attempt in range(
            MAX_RETRIES + 1
        ):
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

    @staticmethod
    def _retry_delay(
        error: HTTPError,
        attempt: int,
    ) -> float:
        """
        Calculate a bounded retry delay for NVD rate limiting.
        """

        retry_after = (
            error.headers.get(
                "Retry-After"
            )
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

    @staticmethod
    def _total_results(
        payload: dict[str, Any],
    ) -> int | None:
        """
        Extract NVD's total result count.
        """

        value = payload.get(
            "totalResults"
        )

        try:
            total = int(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return None

        if total < 0:
            return None

        return total

    @staticmethod
    def _is_formatted_cpe_23(
        value: str,
    ) -> bool:
        """
        Return True when value is a valid CPE 2.3 formatted structure.
        """

        text = str(
            value or ""
        ).strip()

        if not text:
            return False

        parts = text.split(
            ":"
        )

        return (
            len(parts)
            == _CPE_23_FIELD_COUNT
            and parts[0].lower()
            == "cpe"
            and parts[1] == "2.3"
        )

    @staticmethod
    def _candidate_version_matches(
        cpe: str,
        version: str,
    ) -> bool:
        """
        Perform a conservative CPE candidate version check.

        `*` means ANY and therefore remains a candidate.

        `-` means NOT APPLICABLE. It is not treated as a wildcard.
        """

        parts = str(
            cpe or ""
        ).strip().split(
            ":"
        )

        if (
            len(parts)
            != _CPE_23_FIELD_COUNT
        ):
            return False

        if (
            parts[0].lower()
            != "cpe"
            or parts[1] != "2.3"
        ):
            return False

        cpe_version = parts[
            _CPE_VERSION_INDEX
        ]

        if cpe_version == "*":
            return True

        if cpe_version == "-":
            return False

        normalized_cpe_version = (
            NVDClient._unescape_cpe_component(
                cpe_version
            ).lower()
        )

        normalized_version = (
            str(version)
            .strip()
            .lower()
        )

        return (
            normalized_cpe_version
            == normalized_version
        )

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
