"""
ScopeForgeX Cookie Security Analyzer
=====================================

ScopeForgeX-native analyzer for HTTP cookie security attributes.

The analyzer consumes HTTP response cookie evidence collected by
enumeration capabilities and produces normalized security findings.

It does not execute an external security tool.

Analyzed attributes
-------------------
- Secure
- HttpOnly
- SameSite
- Domain
- Path

Finding types
-------------
- INSECURE_COOKIE
- MISSING_HTTPONLY
- MISSING_SECURE
- WEAK_SAMESITE

Design Principles
-----------------
- Native ScopeForgeX analysis.
- No external executable dependency.
- Structured findings.
- Preserve source evidence.
- Deterministic analysis.
- Standard-library only.
- Compatible with the canonical finding model.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


###############################################################################
# Constants
###############################################################################


VALID_SAMESITE_VALUES = {
    "strict",
    "lax",
    "none",
}


###############################################################################
# Finding
###############################################################################


@dataclass(slots=True)
class CookieFinding:
    """
    Normalized finding produced by the cookie security analyzer.
    """

    finding_type: str

    title: str

    severity: str

    confidence: str

    target: str

    description: str

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    source_tool: str = "scopeforgex"

    detection_method: str = (
        "Cookie Security Analyzer"
    )

    remediation: str = ""

    category: str = (
        "cookie_security"
    )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the finding into a stable dictionary.
        """

        return {
            "finding_type": self.finding_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target,
            "category": self.category,
            "description": self.description,
            "evidence": dict(self.evidence),
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "remediation": self.remediation,
        }


###############################################################################
# Analyzer
###############################################################################


class CookieSecurityAnalyzer:
    """
    Analyze HTTP cookie security attributes.

    Expected input
    ---------------

    A mapping containing a target and cookies.

    Supported cookie representations include:

        {
            "target": "https://example.com",
            "cookies": [
                {
                    "name": "session",
                    "secure": True,
                    "httponly": True,
                    "samesite": "Lax",
                    "domain": "example.com",
                    "path": "/",
                }
            ],
        }

    Boolean attributes are matched case-insensitively when supplied as
    strings.

    The analyzer also accepts a mapping of cookie names to cookie metadata.
    """

    name = "cookie_security"

    description = (
        "Analyze HTTP cookies for missing or weak security attributes."
    )

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[CookieFinding]:
        """
        Analyze cookie security evidence.

        Returns:
            A list of normalized CookieFinding objects.
        """

        target = str(
            evidence.get(
                "target",
                "",
            )
        ).strip()

        cookies = evidence.get(
            "cookies",
            [],
        )

        normalized = self._normalize_cookies(
            cookies
        )

        findings: list[CookieFinding] = []

        for cookie in normalized:

            findings.extend(
                self._analyze_cookie(
                    target,
                    cookie,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Cookie Normalization
    # ------------------------------------------------------------------

    @classmethod
    def _normalize_cookies(
        cls,
        cookies: Any,
    ) -> list[dict[str, Any]]:
        """
        Normalize supported cookie representations.
        """

        if isinstance(
            cookies,
            Mapping,
        ):

            normalized: list[dict[str, Any]] = []

            for name, value in cookies.items():

                if isinstance(
                    value,
                    Mapping,
                ):

                    cookie = dict(
                        value
                    )

                    cookie.setdefault(
                        "name",
                        str(name),
                    )

                else:

                    cookie = {
                        "name": str(name),
                        "value": value,
                    }

                normalized.append(
                    cls._normalize_cookie(
                        cookie
                    )
                )

            return normalized

        if isinstance(
            cookies,
            (list, tuple),
        ):

            normalized = []

            for item in cookies:

                if isinstance(
                    item,
                    Mapping,
                ):

                    normalized.append(
                        cls._normalize_cookie(
                            item
                        )
                    )

                elif isinstance(
                    item,
                    str,
                ):

                    normalized.append(
                        cls._parse_set_cookie(
                            item
                        )
                    )

            return normalized

        return []

    @staticmethod
    def _normalize_cookie(
        cookie: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Normalize a structured cookie object.
        """

        normalized = {
            str(key).strip().lower(): value
            for key, value in cookie.items()
            if str(key).strip()
        }

        if "httponly" not in normalized:

            normalized["httponly"] = (
                normalized.get(
                    "http_only",
                    False,
                )
            )

        if "secure" not in normalized:

            normalized["secure"] = False

        if "samesite" not in normalized:

            normalized["samesite"] = (
                normalized.get(
                    "same_site",
                    None,
                )
            )

        return normalized

    @staticmethod
    def _parse_set_cookie(
        value: str,
    ) -> dict[str, Any]:
        """
        Parse a Set-Cookie style string into structured attributes.

        This parser intentionally focuses on security attributes rather than
        attempting to implement the complete cookie specification.
        """

        parts = [
            part.strip()
            for part in value.split(";")
            if part.strip()
        ]

        if not parts:

            return {}

        first = parts[0]

        if "=" in first:

            name, cookie_value = first.split(
                "=",
                1,
            )

        else:

            name = first
            cookie_value = ""

        cookie: dict[str, Any] = {
            "name": name.strip(),
            "value": cookie_value.strip(),
            "secure": False,
            "httponly": False,
            "samesite": None,
        }

        for attribute in parts[1:]:

            if "=" in attribute:

                key, attr_value = attribute.split(
                    "=",
                    1,
                )

                key = key.strip().lower()
                attr_value = attr_value.strip()

                if key == "samesite":

                    cookie["samesite"] = (
                        attr_value
                    )

                elif key == "domain":

                    cookie["domain"] = (
                        attr_value
                    )

                elif key == "path":

                    cookie["path"] = (
                        attr_value
                    )

            else:

                key = attribute.strip().lower()

                if key == "secure":

                    cookie["secure"] = True

                elif key == "httponly":

                    cookie["httponly"] = True

        return cookie

    # ------------------------------------------------------------------
    # Cookie Analysis
    # ------------------------------------------------------------------

    def _analyze_cookie(
        self,
        target: str,
        cookie: Mapping[str, Any],
    ) -> list[CookieFinding]:
        """
        Analyze one cookie.
        """

        name = str(
            cookie.get(
                "name",
                "unnamed",
            )
        ).strip()

        findings: list[CookieFinding] = []

        secure = self._as_bool(
            cookie.get(
                "secure",
                False,
            )
        )

        httponly = self._as_bool(
            cookie.get(
                "httponly",
                False,
            )
        )

        samesite = cookie.get(
            "samesite"
        )

        if isinstance(
            samesite,
            str,
        ):

            samesite = (
                samesite.strip().lower()
            )

        #######################################################################
        # Secure
        #######################################################################

        if not secure:

            findings.append(
                CookieFinding(
                    finding_type="MISSING_SECURE",
                    title=(
                        f"Cookie '{name}' Missing Secure Attribute"
                    ),
                    severity="medium",
                    confidence="high",
                    target=target,
                    description=(
                        f"The cookie '{name}' is not marked Secure. "
                        "It may therefore be transmitted over an "
                        "unencrypted HTTP connection."
                    ),
                    evidence={
                        "cookie": name,
                        "secure": False,
                        "httponly": httponly,
                        "samesite": samesite,
                        "domain": cookie.get(
                            "domain"
                        ),
                        "path": cookie.get(
                            "path"
                        ),
                    },
                    remediation=(
                        "Set the Secure attribute on cookies that "
                        "contain session or other sensitive information."
                    ),
                )
            )

        #######################################################################
        # HttpOnly
        #######################################################################

        if not httponly:

            findings.append(
                CookieFinding(
                    finding_type="MISSING_HTTPONLY",
                    title=(
                        f"Cookie '{name}' Missing HttpOnly Attribute"
                    ),
                    severity="medium",
                    confidence="high",
                    target=target,
                    description=(
                        f"The cookie '{name}' is not marked HttpOnly. "
                        "Client-side JavaScript may therefore be able "
                        "to access the cookie."
                    ),
                    evidence={
                        "cookie": name,
                        "secure": secure,
                        "httponly": False,
                        "samesite": samesite,
                        "domain": cookie.get(
                            "domain"
                        ),
                        "path": cookie.get(
                            "path"
                        ),
                    },
                    remediation=(
                        "Set HttpOnly on cookies that do not need "
                        "to be accessed by client-side JavaScript, "
                        "especially authentication and session cookies."
                    ),
                )
            )

        #######################################################################
        # SameSite
        #######################################################################

        if samesite is None or samesite == "":

            findings.append(
                CookieFinding(
                    finding_type="WEAK_SAMESITE",
                    title=(
                        f"Cookie '{name}' Missing SameSite Attribute"
                    ),
                    severity="low",
                    confidence="high",
                    target=target,
                    description=(
                        f"The cookie '{name}' does not explicitly "
                        "define a SameSite attribute."
                    ),
                    evidence={
                        "cookie": name,
                        "samesite": None,
                        "secure": secure,
                        "httponly": httponly,
                    },
                    remediation=(
                        "Set an explicit SameSite policy such as "
                        "Lax or Strict according to the application's "
                        "cross-site requirements."
                    ),
                )
            )

        elif samesite not in VALID_SAMESITE_VALUES:

            findings.append(
                CookieFinding(
                    finding_type="WEAK_SAMESITE",
                    title=(
                        f"Cookie '{name}' Has Invalid SameSite Attribute"
                    ),
                    severity="low",
                    confidence="high",
                    target=target,
                    description=(
                        f"The cookie '{name}' specifies an unrecognized "
                        "SameSite value."
                    ),
                    evidence={
                        "cookie": name,
                        "samesite": samesite,
                        "valid_values": sorted(
                            VALID_SAMESITE_VALUES
                        ),
                    },
                    remediation=(
                        "Use a valid SameSite value: Strict, Lax or None."
                    ),
                )
            )

        elif samesite == "none" and not secure:

            findings.append(
                CookieFinding(
                    finding_type="INSECURE_COOKIE",
                    title=(
                        f"Cookie '{name}' Uses SameSite=None Without Secure"
                    ),
                    severity="medium",
                    confidence="high",
                    target=target,
                    description=(
                        f"The cookie '{name}' uses SameSite=None "
                        "without the Secure attribute."
                    ),
                    evidence={
                        "cookie": name,
                        "samesite": "None",
                        "secure": False,
                        "httponly": httponly,
                    },
                    remediation=(
                        "Cookies using SameSite=None should also use "
                        "the Secure attribute."
                    ),
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _as_bool(
        value: Any,
    ) -> bool:
        """
        Convert common boolean representations into bool.
        """

        if isinstance(
            value,
            bool,
        ):
            return value

        if value is None:
            return False

        if isinstance(
            value,
            str,
        ):

            return value.strip().lower() in {
                "true",
                "yes",
                "1",
                "on",
            }

        return bool(
            value
        )


###############################################################################
# Convenience Function
###############################################################################


def analyze_cookie_security(
    evidence: Mapping[str, Any],
) -> list[CookieFinding]:
    """
    Analyze cookie security using the default analyzer.
    """

    analyzer = CookieSecurityAnalyzer()

    return analyzer.analyze(
        evidence
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "VALID_SAMESITE_VALUES",
    "CookieFinding",
    "CookieSecurityAnalyzer",
    "analyze_cookie_security",
]
