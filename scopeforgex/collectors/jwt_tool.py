"""
ScopeForgeX JWT Tool Collector
==============================

Collector adapter for jwt_tool.

jwt_tool is used by ScopeForgeX for authorized JSON Web Token security
assessment and validation.

Responsibilities
----------------

- Build deterministic jwt_tool commands.
- Support JWT inspection and attack/validation modes.
- Preserve raw stdout and stderr.
- Extract JWT security observations from jwt_tool output.
- Preserve token-related evidence without unnecessarily exposing secrets.
- Preserve algorithm, claim, attack mode and validation information when
  available.
- Maintain source-tool traceability.
- Produce normalized observations for the universal Finding pipeline.

The collector does not:

- Decide whether exploitation is authorized.
- Perform cross-tool correlation.
- Perform final deduplication.
- Perform final risk classification.
- Replace raw tool evidence with parsed data.

Architecture
------------

Authorized Target / JWT
        |
        v
JWT Tool Collector
        |
        v
Tool Executor
        |
        v
jwt_tool
        |
        +--> Raw Output
        |
        +--> Parsed Observations
                    |
                    v
             Finding Normalizer
                    |
                    v
             Correlation / Risk
                    |
                    v
                  Report

v1.0.0
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Mapping
from urllib.parse import urlparse

from scopeforgex.collectors.base import BaseCollector, CollectorObservation


###############################################################################
# Constants
###############################################################################


DEFAULT_CONFIDENCE = "Medium"

JWT_CATEGORY = "jwt_security"

JWT_CWE = "CWE-347"

JWT_FINDING_MARKERS = (
    "vulnerable",
    "vulnerability",
    "success",
    "successful",
    "accepted",
    "forged",
    "unsigned",
    "none",
    "algorithm",
    "alg",
    "weak",
    "cracked",
    "bypass",
    "tamper",
    "signature",
    "kid",
    "jku",
    "x5u",
    "claim",
)


###############################################################################
# Collector
###############################################################################


class JwtToolCollector(BaseCollector):
    """
    Collect JWT security observations from jwt_tool.

    The parser is deliberately conservative. Informational output such as
    banners, menus and normal token decoding is not automatically converted
    into a vulnerability unless the output contains recognizable security
    assessment evidence.
    """

    name = "jwt_tool"

    description = (
        "Assess JSON Web Token security and extract normalized JWT security "
        "observations from jwt_tool."
    )

    category = "validation"

    binary = "jwt_tool"

    ###########################################################################
    # Command Construction
    ###########################################################################

    def parse(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[CollectorObservation]:
        context = dict(ctx or {})

        target = str(
            context.get("target", "") or ""
        ).strip()

        options = dict(
            context.get(
                "tool_options",
                context.get("options", {}),
            ) or {}
        )

        command = [
            str(value)
            for value in (
                context.get("command", []) or []
            )
        ]

        parsed = self.parse_result(
            target=target,
            result=execution_result,
            command=command,
            options=options,
        )

        raw_observations = (
            parsed.get("observations", [])
            if isinstance(parsed, Mapping)
            else []
        )

        return self._coerce_canonical_observations(
            raw_observations,
            target=target,
        )

    @staticmethod
    def _coerce_canonical_observations(
        observations: Any,
        *,
        target: str,
    ) -> list[CollectorObservation]:
        result: list[CollectorObservation] = []

        for item in observations or []:
            data = (
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
            )

            if not isinstance(data, Mapping):
                continue

            data = dict(data)

            result.append(
                CollectorObservation(
                    observation_type=str(
                        data.get(
                            "observation_type",
                            data.get(
                                "category",
                                data.get(
                                    "type",
                                    "jwt_security",
                                ),
                            ),
                        )
                    ),
                    value=data.get("value"),
                    title=str(data.get("title", "")),
                    description=str(
                        data.get("description", "")
                    ),
                    impact=str(data.get("impact", "")),
                    remediation=str(
                        data.get("remediation", "")
                    ),
                    severity=str(
                        data.get(
                            "severity",
                            "Informational",
                        )
                    ),
                    confidence=str(
                        data.get(
                            "confidence",
                            "Informational",
                        )
                    ),
                    target=data.get(
                        "target",
                        target,
                    ),
                    host=data.get("host"),
                    port=data.get("port"),
                    url=data.get("url"),
                    parameter=data.get(
                        "parameter"
                    ),
                    evidence=data.get(
                        "evidence"
                    ),
                    source_tool=str(
                        data.get(
                            "source_tool",
                            "jwt_tool",
                        )
                    ),
                    detection_method=str(
                        data.get(
                            "detection_method",
                            "",
                        )
                    ),
                    cwe=data.get("cwe"),
                    cve=data.get("cve"),
                    references=list(
                        data.get(
                            "references",
                            [],
                        )
                        or []
                    ),
                    metadata=dict(
                        data.get(
                            "metadata",
                            {},
                        )
                        or {}
                    ),
                )
            )

        return result

    def build_command(
        self,
        target: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> list[str]:
        """
        Build a deterministic jwt_tool command.

        Supported options include:

        - token
        - url
        - request
        - cookie
        - exploit
        - tamper
        - algorithm
        - decode
        - verify
        - crack
        - wordlist
        - jwks
        - signing_key
        - header
        - headers
        - mode
        - timeout
        - proxy
        - output
        - verbose
        - additional_args

        The collector does not attempt to infer attack modes from arbitrary
        text. Explicit options are translated directly into command-line
        arguments.
        """

        options = dict(options or {})

        command = [self.binary]

        #######################################################################
        # JWT / Target
        #######################################################################

        request_target = (
            options.get("token")
            or options.get("url")
            or target
        )

        if request_target:
            normalized_target = str(request_target).strip()

            if not normalized_target:
                raise ValueError(
                    "jwt_tool target cannot be empty."
                )

            command.append(normalized_target)

        elif options.get("request"):
            request = str(options["request"]).strip()

            if not request:
                raise ValueError(
                    "jwt_tool request cannot be empty."
                )

            command.extend(
                [
                    "-r",
                    request,
                ]
            )

        else:
            raise ValueError(
                "jwt_tool requires a JWT token, URL, or request file."
            )

        #######################################################################
        # Request / Cookie
        #######################################################################

        cookie = options.get("cookie")

        if cookie:
            command.extend(
                [
                    "-rc",
                    str(cookie),
                ]
            )

        header = options.get("header")
        headers = options.get("headers")

        header_values: list[str] = []

        if header:
            if isinstance(header, (list, tuple)):
                header_values.extend(
                    str(value)
                    for value in header
                )
            else:
                header_values.append(str(header))

        if headers:
            if isinstance(headers, (list, tuple)):
                header_values.extend(
                    str(value)
                    for value in headers
                )
            else:
                header_values.append(str(headers))

        for value in header_values:
            if value.strip():
                command.extend(
                    [
                        "-rh",
                        value,
                    ]
                )

        #######################################################################
        # Analysis / Mode
        #######################################################################

        mode = options.get("mode")

        if mode:
            command.extend(
                [
                    "-M",
                    str(mode),
                ]
            )

        decode = options.get("decode")

        if decode:
            command.append("-d")

        verify = options.get("verify")

        if verify:
            command.append("-V")

        #######################################################################
        # Exploitation / Tampering
        #######################################################################

        exploit = options.get("exploit")

        if exploit:
            if isinstance(exploit, bool):
                if exploit:
                    command.append("-X")
            else:
                command.extend(
                    [
                        "-X",
                        str(exploit),
                    ]
                )

        tamper = options.get("tamper")

        if tamper:
            command.extend(
                [
                    "-T",
                    str(tamper),
                ]
            )

        algorithm = options.get("algorithm")

        if algorithm:
            command.extend(
                [
                    "-I",
                    str(algorithm),
                ]
            )

        #######################################################################
        # Key / Signature Testing
        #######################################################################

        signing_key = options.get("signing_key")

        if signing_key:
            command.extend(
                [
                    "-pk",
                    str(signing_key),
                ]
            )

        jwks = options.get("jwks")

        if jwks:
            command.extend(
                [
                    "-jwks",
                    str(jwks),
                ]
            )

        crack = options.get("crack")

        if crack:
            if isinstance(crack, bool):
                if crack:
                    command.append("-C")
            else:
                command.extend(
                    [
                        "-C",
                        str(crack),
                    ]
                )

        wordlist = options.get("wordlist")

        if wordlist:
            command.extend(
                [
                    "-p",
                    str(wordlist),
                ]
            )

        #######################################################################
        # Runtime
        #######################################################################

        timeout = options.get("timeout")

        if timeout is not None:
            timeout_value = self._integer_option(
                timeout,
                "timeout",
                minimum=1,
            )

            command.extend(
                [
                    "--timeout",
                    str(timeout_value),
                ]
            )

        proxy = options.get("proxy")

        if proxy:
            command.extend(
                [
                    "--proxy",
                    str(proxy),
                ]
            )

        #######################################################################
        # Output
        #######################################################################

        output = options.get("output")

        if output:
            command.extend(
                [
                    "-o",
                    str(output),
                ]
            )

        if options.get("verbose", False):
            command.append("-v")

        #######################################################################
        # Additional Arguments
        #######################################################################

        additional_args = options.get(
            "additional_args",
            [],
        )

        if additional_args is None:
            additional_args = []

        if not isinstance(
            additional_args,
            (list, tuple),
        ):
            raise TypeError(
                "jwt_tool additional_args must be a list or tuple."
            )

        command.extend(
            str(argument)
            for argument in additional_args
            if str(argument).strip()
        )

        return command

    ###########################################################################
    # Collection
    ###########################################################################

    def collect(
        self,
        target: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute jwt_tool and return normalized collector evidence.
        """

        options = dict(options or {})

        command = self.build_command(
            target,
            options,
        )

        result = self.execute(command)

        effective_target = (
            target
            or options.get("token")
            or options.get("url")
            or ""
        )

        return self.parse_result(
            target=str(effective_target),
            result=result,
            command=command,
            options=options,
        )

    ###########################################################################
    # Result Parsing
    ###########################################################################

    def parse_result(
        self,
        target: str,
        result: Any,
        command: list[str] | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Parse jwt_tool stdout/stderr into normalized observations.

        Raw stdout and stderr are always retained.
        """

        stdout = self._result_value(
            result,
            "stdout",
        ) or ""

        stderr = self._result_value(
            result,
            "stderr",
        ) or ""

        returncode = self._result_value(
            result,
            "returncode",
        )

        if returncode is None:
            returncode = self._result_value(
                result,
                "return_code",
            )

        combined = "\n".join(
            part
            for part in (
                str(stdout),
                str(stderr),
            )
            if part
        )

        observations = self._parse_output(
            combined,
            target,
        )

        return {
            "collector": self.name,
            "category": self.category,
            "target": str(target).strip(),
            "success": self._result_success(result),
            "observations": observations,
            "observation_count": len(observations),
            "raw": {
                "stdout": str(stdout),
                "stderr": str(stderr),
            },
            "execution": {
                "returncode": returncode,
            },
            "command": list(command or []),
            "options": dict(options or {}),
        }

    ###########################################################################
    # Output Parsing
    ###########################################################################

    @classmethod
    def _parse_output(
        cls,
        output: str,
        target: str,
    ) -> list[dict[str, Any]]:
        """
        Parse jwt_tool output into JWT security observations.

        The parser recognizes:

        - explicit vulnerability/success messages
        - algorithm weaknesses
        - signature bypass indicators
        - claim tampering
        - key/JWK related issues
        - weak secret findings

        Pure token decoding is not treated as a vulnerability.
        """

        text = str(output)

        if not text.strip():
            return []

        observations: list[dict[str, Any]] = []

        lines = text.splitlines()

        for line in lines:
            normalized = line.strip()

            if not normalized:
                continue

            if not cls._looks_like_finding(normalized):
                continue

            observation = cls._parse_finding_line(
                normalized,
                target,
            )

            if observation is not None:
                observations.append(observation)

        # Some jwt_tool modes produce structured JSON output. Attempt to
        # recover security-relevant objects without treating arbitrary JSON
        # token claims as findings.
        for record in cls._iter_json_records(text):
            observation = cls._parse_mapping_record(
                record,
                target,
            )

            if observation is not None:
                observations.append(observation)

        unique: list[dict[str, Any]] = []
        fingerprints: set[str] = set()

        for observation in observations:
            fingerprint = cls._observation_fingerprint(
                observation
            )

            if fingerprint in fingerprints:
                continue

            fingerprints.add(fingerprint)
            unique.append(observation)

        return unique

    @classmethod
    def _parse_finding_line(
        cls,
        line: str,
        target: str,
    ) -> dict[str, Any] | None:
        """
        Parse one jwt_tool output line.
        """

        lower = line.lower()

        issue = cls._classify_issue(line)

        if issue is None:
            return None

        algorithm = cls._extract_algorithm(line)
        claim = cls._extract_claim(line)
        attack = cls._extract_attack(line)
        evidence = cls._safe_evidence(line)

        confidence = (
            "High"
            if any(
                marker in lower
                for marker in (
                    "verified",
                    "successful",
                    "success",
                    "forged",
                    "accepted",
                    "vulnerable",
                )
            )
            else DEFAULT_CONFIDENCE
        )

        title = cls._issue_title(issue)

        description = cls._issue_description(
            issue,
            algorithm=algorithm,
            claim=claim,
            attack=attack,
        )

        return {
            "type": "vulnerability",
            "category": JWT_CATEGORY,
            "title": title,
            "target": str(target).strip(),
            "host": cls._extract_host(target),
            "port": cls._extract_port(target),
            "url": (
                target
                if cls._looks_like_url(target)
                else None
            ),
            "parameter": None,
            "severity": cls._issue_severity(issue),
            "confidence": confidence,
            "description": description,
            "evidence": evidence,
            "source_tool": "jwt_tool",
            "detection_method": (
                "JSON Web Token Security Assessment"
            ),
            "cwe": cls._issue_cwe(issue),
            "cve": None,
            "references": [
                "https://cwe.mitre.org/data/definitions/347.html",
            ],
            "impact": cls._issue_impact(issue),
            "remediation": cls._issue_remediation(issue),
            "metadata": {
                "issue_type": issue,
                "algorithm": algorithm,
                "claim": claim,
                "attack": attack,
                "jwt_tool_line": line,
            },
        }

    @classmethod
    def _parse_mapping_record(
        cls,
        record: Mapping[str, Any],
        target: str,
    ) -> dict[str, Any] | None:
        """
        Parse a structured jwt_tool record when it contains explicit
        security-related information.
        """

        text = json.dumps(
            record,
            ensure_ascii=False,
        )

        if not cls._looks_like_finding(text):
            return None

        issue = cls._classify_issue(text)

        if issue is None:
            return None

        algorithm = cls._extract_algorithm(text)
        claim = cls._extract_claim(text)
        attack = cls._extract_attack(text)

        return {
            "type": "vulnerability",
            "category": JWT_CATEGORY,
            "title": cls._issue_title(issue),
            "target": str(target).strip(),
            "host": cls._extract_host(target),
            "port": cls._extract_port(target),
            "url": (
                target
                if cls._looks_like_url(target)
                else None
            ),
            "parameter": None,
            "severity": cls._issue_severity(issue),
            "confidence": "High",
            "description": cls._issue_description(
                issue,
                algorithm=algorithm,
                claim=claim,
                attack=attack,
            ),
            "evidence": {
                "structured_record": record,
            },
            "source_tool": "jwt_tool",
            "detection_method": (
                "JSON Web Token Security Assessment"
            ),
            "cwe": cls._issue_cwe(issue),
            "cve": None,
            "references": [
                "https://cwe.mitre.org/data/definitions/347.html",
            ],
            "impact": cls._issue_impact(issue),
            "remediation": cls._issue_remediation(issue),
            "metadata": {
                "issue_type": issue,
                "algorithm": algorithm,
                "claim": claim,
                "attack": attack,
            },
        }

    ###########################################################################
    # JSON Parsing
    ###########################################################################

    @staticmethod
    def _iter_json_records(
        output: str,
    ) -> list[dict[str, Any]]:
        """
        Extract JSON objects from newline-delimited or standalone JSON output.
        """

        records: list[dict[str, Any]] = []

        for line in output.splitlines():
            stripped = line.strip()

            if not (
                stripped.startswith("{")
                and stripped.endswith("}")
            ):
                continue

            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                continue

            if isinstance(value, dict):
                records.append(value)

        return records

    ###########################################################################
    # Detection
    ###########################################################################

    @staticmethod
    def _looks_like_finding(
        line: str,
    ) -> bool:
        """
        Determine whether text contains security-relevant JWT evidence.

        Generic algorithm/claim display is not sufficient by itself. The
        parser requires an accompanying weakness, attack, success, bypass or
        vulnerability indicator.
        """

        normalized = line.lower()

        strong_markers = (
            "vulnerable",
            "vulnerability",
            "success",
            "successful",
            "accepted",
            "forged",
            "weak secret",
            "signature bypass",
            "algorithm confusion",
            "none algorithm",
            "key confusion",
            "claim tamper",
            "tamper successful",
            "bypass successful",
            "cracked",
        )

        if any(
            marker in normalized
            for marker in strong_markers
        ):
            return True

        attack_markers = (
            "alg none",
            "algorithm none",
            "rsa/hmac",
            "hmac/rsa",
            "jwk",
            "jku",
            "x5u",
            "kid",
        )

        security_context = (
            "attack",
            "exploit",
            "inject",
            "bypass",
            "tamper",
            "manipulat",
            "forge",
            "test",
        )

        return (
            any(
                marker in normalized
                for marker in attack_markers
            )
            and any(
                marker in normalized
                for marker in security_context
            )
        )

    @staticmethod
    def _classify_issue(
        line: str,
    ) -> str | None:
        """
        Classify a security issue from jwt_tool text.
        """

        normalized = line.lower()

        if (
            "algorithm confusion" in normalized
            or "rsa/hmac" in normalized
            or "hmac/rsa" in normalized
        ):
            return "algorithm_confusion"

        if (
            "alg none" in normalized
            or "algorithm none" in normalized
            or "unsigned" in normalized
        ):
            return "none_algorithm"

        if (
            "weak secret" in normalized
            or "secret cracked" in normalized
            or "cracked" in normalized
        ):
            return "weak_signing_secret"

        if (
            "signature bypass" in normalized
            or "bypass successful" in normalized
        ):
            return "signature_bypass"

        if (
            "jwk" in normalized
            or "jku" in normalized
            or "x5u" in normalized
        ):
            return "jwk_key_injection"

        if "kid" in normalized and any(
            marker in normalized
            for marker in (
                "inject",
                "traversal",
                "manipulat",
                "bypass",
            )
        ):
            return "kid_manipulation"

        if (
            "claim tamper" in normalized
            or "tamper successful" in normalized
            or "claim manipulation" in normalized
        ):
            return "claim_tampering"

        if (
            "forged" in normalized
            or "token accepted" in normalized
            or "successfully forged" in normalized
        ):
            return "forged_token"

        if (
            "vulnerable" in normalized
            or "vulnerability" in normalized
        ):
            return "jwt_security_issue"

        return None

    ###########################################################################
    # Extraction Helpers
    ###########################################################################

    @staticmethod
    def _extract_algorithm(
        line: str,
    ) -> str | None:
        """
        Extract a JWT signing algorithm when present.
        """

        patterns = (
            r"\balg(?:orithm)?\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)",
            r"\b(?:using|with)\s+([A-Za-z0-9_-]+)\s+algorithm\b",
        )

        for pattern in patterns:
            match = re.search(
                pattern,
                line,
                re.IGNORECASE,
            )

            if match:
                return match.group(1).strip()

        for algorithm in (
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "none",
        ):
            if re.search(
                rf"\b{re.escape(algorithm)}\b",
                line,
                re.IGNORECASE,
            ):
                return algorithm

        return None

    @staticmethod
    def _extract_claim(
        line: str,
    ) -> str | None:
        """
        Extract a likely JWT claim name.
        """

        patterns = (
            r"\bclaim\s*[:=]\s*['\"]?([A-Za-z0-9_.-]+)",
            r"\bclaim\s+['\"]([A-Za-z0-9_.-]+)['\"]",
            r"\b(?:modify|tamper|inject)\s+['\"]?([A-Za-z0-9_.-]+)",
        )

        for pattern in patterns:
            match = re.search(
                pattern,
                line,
                re.IGNORECASE,
            )

            if match:
                return match.group(1).strip()

        return None

    @staticmethod
    def _extract_attack(
        line: str,
    ) -> str | None:
        """
        Extract a likely jwt_tool attack/test identifier.
        """

        patterns = (
            r"\battack\s*[:=]\s*['\"]?([^,'\"]+)",
            r"\bmode\s*[:=]\s*['\"]?([^,'\"]+)",
            r"\btest\s*[:=]\s*['\"]?([^,'\"]+)",
        )

        for pattern in patterns:
            match = re.search(
                pattern,
                line,
                re.IGNORECASE,
            )

            if match:
                value = match.group(1).strip()

                if value:
                    return value

        return None

    @staticmethod
    def _safe_evidence(
        line: str,
    ) -> dict[str, Any]:
        """
        Preserve useful evidence while redacting complete JWTs.

        A JWT itself may contain sensitive authentication material. The raw
        execution artifact remains the authoritative evidence source, while
        normalized finding evidence avoids unnecessarily copying a complete
        token into the finding.
        """

        redacted = re.sub(
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            "<JWT_REDACTED>",
            line,
        )

        return {
            "raw_line": redacted,
        }

    ###########################################################################
    # Issue Metadata
    ###########################################################################

    @staticmethod
    def _issue_title(
        issue: str,
    ) -> str:
        titles = {
            "algorithm_confusion": (
                "JWT Algorithm Confusion"
            ),
            "none_algorithm": (
                "JWT Unsecured / None Algorithm"
            ),
            "weak_signing_secret": (
                "Weak JWT Signing Secret"
            ),
            "signature_bypass": (
                "JWT Signature Validation Bypass"
            ),
            "jwk_key_injection": (
                "JWT JWK/JWK URL Key Injection"
            ),
            "kid_manipulation": (
                "JWT Key Identifier Manipulation"
            ),
            "claim_tampering": (
                "JWT Claim Tampering"
            ),
            "forged_token": (
                "Forged JWT Accepted"
            ),
            "jwt_security_issue": (
                "JWT Security Issue"
            ),
        }

        return titles.get(
            issue,
            "JWT Security Issue",
        )

    @staticmethod
    def _issue_severity(
        issue: str,
    ) -> str:
        severities = {
            "algorithm_confusion": "High",
            "none_algorithm": "High",
            "weak_signing_secret": "High",
            "signature_bypass": "Critical",
            "jwk_key_injection": "High",
            "kid_manipulation": "High",
            "claim_tampering": "High",
            "forged_token": "Critical",
            "jwt_security_issue": "High",
        }

        return severities.get(
            issue,
            "High",
        )

    @staticmethod
    def _issue_cwe(
        issue: str,
    ) -> str:
        if issue in {
            "algorithm_confusion",
            "none_algorithm",
            "weak_signing_secret",
            "signature_bypass",
            "forged_token",
        }:
            return JWT_CWE

        if issue in {
            "claim_tampering",
            "kid_manipulation",
            "jwk_key_injection",
        }:
            return "CWE-639"

        return JWT_CWE

    @staticmethod
    def _issue_description(
        issue: str,
        algorithm: str | None,
        claim: str | None,
        attack: str | None,
    ) -> str:
        descriptions = {
            "algorithm_confusion": (
                "jwt_tool identified evidence of JWT algorithm confusion, "
                "where an implementation may accept a token under an "
                "inappropriate signing algorithm."
            ),
            "none_algorithm": (
                "jwt_tool identified evidence that an unsecured JWT "
                "algorithm may be accepted without a valid cryptographic "
                "signature."
            ),
            "weak_signing_secret": (
                "jwt_tool identified a weak or recoverable JWT signing "
                "secret, potentially allowing attacker-controlled token "
                "generation."
            ),
            "signature_bypass": (
                "jwt_tool identified evidence that JWT signature validation "
                "can be bypassed."
            ),
            "jwk_key_injection": (
                "jwt_tool identified evidence of attacker-controlled JWK "
                "or JWK URL material influencing JWT signature validation."
            ),
            "kid_manipulation": (
                "jwt_tool identified evidence that the JWT key identifier "
                "may be manipulated to influence key selection."
            ),
            "claim_tampering": (
                "jwt_tool identified evidence that JWT claims can be "
                "modified in a security-relevant manner."
            ),
            "forged_token": (
                "jwt_tool identified evidence that a forged JWT was accepted "
                "by the assessed application or validation mechanism."
            ),
            "jwt_security_issue": (
                "jwt_tool identified a security-relevant JWT condition "
                "requiring validation."
            ),
        }

        description = descriptions.get(
            issue,
            descriptions["jwt_security_issue"],
        )

        details: list[str] = []

        if algorithm:
            details.append(
                f"Observed algorithm: {algorithm}."
            )

        if claim:
            details.append(
                f"Affected claim: {claim}."
            )

        if attack:
            details.append(
                f"Assessment mode or attack: {attack}."
            )

        if details:
            return f"{description} {' '.join(details)}"

        return description

    @staticmethod
    def _issue_impact(
        issue: str,
    ) -> str:
        impacts = {
            "algorithm_confusion": (
                "Successful algorithm confusion may allow an attacker to "
                "forge authentication tokens and potentially impersonate "
                "users or obtain unauthorized privileges."
            ),
            "none_algorithm": (
                "Acceptance of unsigned tokens may allow attackers to forge "
                "authentication or authorization tokens."
            ),
            "weak_signing_secret": (
                "Recovery of a weak signing secret may allow arbitrary JWT "
                "forgery and account or privilege impersonation."
            ),
            "signature_bypass": (
                "A signature validation bypass can permit attacker-controlled "
                "tokens to be accepted as trusted authentication material."
            ),
            "jwk_key_injection": (
                "Attacker-controlled key material may allow forged tokens to "
                "pass signature validation."
            ),
            "kid_manipulation": (
                "Manipulating key selection may allow an attacker to bypass "
                "intended JWT signature validation."
            ),
            "claim_tampering": (
                "Security-sensitive claim modification may permit privilege "
                "escalation, identity impersonation or authorization bypass."
            ),
            "forged_token": (
                "Acceptance of a forged token can result in authentication "
                "bypass, account impersonation or privilege escalation."
            ),
            "jwt_security_issue": (
                "JWT weaknesses may undermine authentication, authorization "
                "or integrity protections."
            ),
        }

        return impacts.get(
            issue,
            impacts["jwt_security_issue"],
        )

    @staticmethod
    def _issue_remediation(
        issue: str,
    ) -> str:
        remediations = {
            "algorithm_confusion": (
                "Explicitly allow only the intended JWT signing algorithms, "
                "bind algorithms to the configured key type, and reject "
                "unexpected algorithm changes."
            ),
            "none_algorithm": (
                "Reject unsecured JWTs unless there is an explicit, "
                "well-justified requirement for them. Enforce signature "
                "validation for authentication tokens."
            ),
            "weak_signing_secret": (
                "Use a strong, randomly generated signing secret with "
                "sufficient entropy and rotate compromised credentials."
            ),
            "signature_bypass": (
                "Enforce strict JWT signature verification, validate the "
                "algorithm and key type, and reject malformed or unsigned "
                "tokens."
            ),
            "jwk_key_injection": (
                "Do not trust attacker-controlled key material. Restrict "
                "accepted JWK/JWK URL sources and use an explicit trusted "
                "key set."
            ),
            "kid_manipulation": (
                "Validate key identifiers against a trusted allowlist and "
                "ensure key lookup cannot be redirected to attacker-controlled "
                "resources."
            ),
            "claim_tampering": (
                "Cryptographically validate all security-sensitive claims "
                "and enforce server-side authorization independently of "
                "untrusted token claims."
            ),
            "forged_token": (
                "Fix the underlying JWT validation weakness, invalidate "
                "affected tokens, rotate compromised signing material and "
                "review authentication logs for abuse."
            ),
            "jwt_security_issue": (
                "Review JWT validation logic and enforce strict algorithm, "
                "signature, key and claim validation."
            ),
        }

        return remediations.get(
            issue,
            remediations["jwt_security_issue"],
        )

    ###########################################################################
    # Target Helpers
    ###########################################################################

    @staticmethod
    def _looks_like_url(
        value: str,
    ) -> bool:
        return value.startswith(
            (
                "http://",
                "https://",
            )
        )

    @staticmethod
    def _extract_host(
        value: str | None,
    ) -> str | None:
        if not value or not JwtToolCollector._looks_like_url(
            str(value)
        ):
            return None

        try:
            return urlparse(
                str(value)
            ).hostname
        except ValueError:
            return None

    @staticmethod
    def _extract_port(
        value: str | None,
    ) -> int | None:
        if not value or not JwtToolCollector._looks_like_url(
            str(value)
        ):
            return None

        try:
            parsed = urlparse(
                str(value)
            )

            if parsed.port is not None:
                return parsed.port

            if parsed.scheme.lower() == "http":
                return 80

            if parsed.scheme.lower() == "https":
                return 443

        except ValueError:
            return None

        return None

    ###########################################################################
    # Generic Helpers
    ###########################################################################

    @staticmethod
    def _observation_fingerprint(
        observation: Mapping[str, Any],
    ) -> str:
        """
        Build a local parser fingerprint.

        Cross-tool deduplication remains the responsibility of the universal
        finding engine.
        """

        metadata = observation.get(
            "metadata",
            {},
        )

        if not isinstance(
            metadata,
            Mapping,
        ):
            metadata = {}

        components = (
            str(
                observation.get(
                    "category",
                    "",
                )
            ),
            str(
                observation.get(
                    "title",
                    "",
                )
            ),
            str(
                observation.get(
                    "target",
                    "",
                )
            ),
            str(
                metadata.get(
                    "algorithm",
                    "",
                )
            ),
            str(
                metadata.get(
                    "claim",
                    "",
                )
            ),
        )

        return "|".join(
            component.strip().lower()
            for component in components
        )

    @staticmethod
    def _integer_option(
        value: Any,
        name: str,
        minimum: int,
        maximum: int | None = None,
    ) -> int:
        """
        Validate an integer command-line option.
        """

        try:
            normalized = int(value)
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                f"jwt_tool {name} must be an integer."
            ) from exc

        if normalized < minimum:
            raise ValueError(
                f"jwt_tool {name} must be >= {minimum}."
            )

        if (
            maximum is not None
            and normalized > maximum
        ):
            raise ValueError(
                f"jwt_tool {name} must be <= {maximum}."
            )

        return normalized

    @staticmethod
    def _result_value(
        result: Any,
        field_name: str,
    ) -> Any:
        """
        Retrieve a result field from a mapping or object.
        """

        if isinstance(
            result,
            Mapping,
        ):
            return result.get(field_name)

        return getattr(
            result,
            field_name,
            None,
        )

    @classmethod
    def _result_success(
        cls,
        result: Any,
    ) -> bool:
        """
        Determine whether jwt_tool execution completed successfully.
        """

        explicit_success = cls._result_value(
            result,
            "success",
        )

        if isinstance(
            explicit_success,
            bool,
        ):
            return explicit_success

        returncode = cls._result_value(
            result,
            "returncode",
        )

        if returncode is None:
            returncode = cls._result_value(
                result,
                "return_code",
            )

        if returncode is None:
            return True

        try:
            return int(returncode) == 0
        except (
            TypeError,
            ValueError,
        ):
            return False


__all__ = [
    "JwtToolCollector",
]
