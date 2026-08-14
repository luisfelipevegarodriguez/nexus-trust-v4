from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class EvidenceError(Exception):
    """Expected fail-closed validation error."""


@dataclass(frozen=True)
class Observation:
    url: str
    http_status: int
    content_sha256: str
    expected_sha256: str
    bytes: int
    fetched_at_ns: int
    primary_host: bool
    immutable_reference: bool
    hash_match: bool
    verified: bool
    reason: str


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise EvidenceError("REDIRECT_FORBIDDEN")


class ZeroTrustEvidenceCompiler:
    VERSION = "4.5.0-zero-trust"
    # Only sources whose URL can itself carry an immutable Git commit reference
    # are accepted as primary evidence by this compiler.
    ALLOWED_PRIMARY_HOSTS = frozenset({
        "github.com",
        "raw.githubusercontent.com",
    })
    GITHUB_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
    SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
    SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
    MAX_BYTES = 2_000_000
    MAX_URL_LENGTH = 4096
    MAX_CLAIMS = 1000
    DEFAULT_TIMEOUT = 10.0

    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("TIMEOUT_MUST_BE_POSITIVE")
        self.timeout = float(timeout)
        self.tls = ssl.create_default_context()
        self.opener = build_opener(
            _NoRedirectHandler(),
            HTTPSHandler(context=self.tls),
        )

    @classmethod
    def _parse_and_validate_url(cls, url: str) -> Tuple[str, bool]:
        """Parse once with urlsplit and reject ambiguous/mutable references."""
        if not isinstance(url, str) or not url:
            raise EvidenceError("SOURCE_URL_REQUIRED")
        if len(url) > cls.MAX_URL_LENGTH:
            raise EvidenceError("SOURCE_URL_TOO_LONG")
        if any(ord(ch) < 0x20 for ch in url):
            raise EvidenceError("SOURCE_URL_CONTROL_CHARACTER")

        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise EvidenceError("URL_PARSE_ERROR") from exc

        # urlsplit normalizes the scheme/hostname casing, but never trust
        # netloc text directly. Reject userinfo, non-HTTPS, and non-default ports.
        if parsed.scheme != "https":
            raise EvidenceError("SOURCE_URL_MUST_BE_HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise EvidenceError("URL_USERINFO_FORBIDDEN")
        if port not in (None, 443):
            raise EvidenceError("URL_PORT_FORBIDDEN")
        if not parsed.netloc or not parsed.hostname:
            raise EvidenceError("SOURCE_HOST_REQUIRED")
        if parsed.query or parsed.fragment:
            raise EvidenceError("URL_QUERY_OR_FRAGMENT_FORBIDDEN")

        try:
            parsed.hostname.encode("ascii")
        except UnicodeEncodeError as exc:
            raise EvidenceError("SOURCE_HOST_NON_ASCII_FORBIDDEN") from exc

        host = parsed.hostname.lower()
        if host.endswith(".") or host not in cls.ALLOWED_PRIMARY_HOSTS:
            raise EvidenceError("SOURCE_HOST_NOT_IN_TRUST_ANCHORS")

        raw_path = parsed.path
        if "\\" in raw_path or "//" in raw_path:
            raise EvidenceError("AMBIGUOUS_PATH_REJECTED")
        parts = raw_path.split("/")[1:] if raw_path.startswith("/") else raw_path.split("/")
        if not parts or any(not part for part in parts):
            raise EvidenceError("INVALID_PATH_STRUCTURE")
        if any(part in {".", ".."} for part in parts):
            raise EvidenceError("PATH_TRAVERSAL_SEGMENT_REJECTED")
        if any("%" in part for part in parts):
            raise EvidenceError("PERCENT_ENCODED_PATH_REJECTED")

        immutable = False
        if host == "github.com":
            immutable = (
                len(parts) >= 5
                and cls.SAFE_SEGMENT_RE.fullmatch(parts[0]) is not None
                and cls.SAFE_SEGMENT_RE.fullmatch(parts[1]) is not None
                and parts[2] == "blob"
                and bool(cls.GITHUB_SHA_RE.fullmatch(parts[3]))
            )
        elif host == "raw.githubusercontent.com":
            immutable = (
                len(parts) >= 4
                and cls.SAFE_SEGMENT_RE.fullmatch(parts[0]) is not None
                and cls.SAFE_SEGMENT_RE.fullmatch(parts[1]) is not None
                and bool(cls.GITHUB_SHA_RE.fullmatch(parts[2]))
            )

        return host, immutable

    @staticmethod
    def _assert_public_dns(host: str) -> None:
        """Reject obvious SSRF destinations before the HTTP connection."""
        try:
            infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise EvidenceError("DNS_RESOLUTION_FAILED") from exc

        if not infos:
            raise EvidenceError("DNS_NO_ADDRESSES")

        for info in infos:
            address = info[4][0]
            try:
                parsed_ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise EvidenceError("DNS_INVALID_ADDRESS") from exc
            if not parsed_ip.is_global:
                raise EvidenceError("DNS_NON_GLOBAL_ADDRESS_REJECTED")

    def fetch_primary(self, url: str, expected_sha256: str) -> Observation:
        host, immutable_reference = self._parse_and_validate_url(url)
        if not isinstance(expected_sha256, str) or not self.SHA256_RE.fullmatch(expected_sha256):
            raise EvidenceError("EXPECTED_SHA256_REQUIRED")
        if not immutable_reference:
            raise EvidenceError("IMMUTABLE_SOURCE_REFERENCE_REQUIRED")

        self._assert_public_dns(host)
        fetched_at_ns = time.time_ns()
        request = Request(
            url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": f"OmegaEvidenceCompiler/{self.VERSION}",
            },
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                status = int(response.status)
                data = response.read(self.MAX_BYTES + 1)
        except EvidenceError:
            raise
        except Exception as exc:
            return Observation(
                url=url,
                http_status=0,
                content_sha256="",
                expected_sha256=expected_sha256,
                bytes=0,
                fetched_at_ns=fetched_at_ns,
                primary_host=host in self.ALLOWED_PRIMARY_HOSTS,
                immutable_reference=immutable_reference,
                hash_match=False,
                verified=False,
                reason=f"FETCH_ERROR:{type(exc).__name__}",
            )

        if len(data) > self.MAX_BYTES:
            return Observation(
                url=url,
                http_status=status,
                content_sha256="",
                expected_sha256=expected_sha256,
                bytes=len(data),
                fetched_at_ns=fetched_at_ns,
                primary_host=host in self.ALLOWED_PRIMARY_HOSTS,
                immutable_reference=immutable_reference,
                hash_match=False,
                verified=False,
                reason="SOURCE_TOO_LARGE",
            )

        digest = hashlib.sha256(data).hexdigest()
        hash_match = hmac.compare_digest(digest.lower(), expected_sha256.lower())
        verified = (
            200 <= status < 300
            and host in self.ALLOWED_PRIMARY_HOSTS
            and immutable_reference
            and hash_match
        )
        return Observation(
            url=url,
            http_status=status,
            content_sha256=digest,
            expected_sha256=expected_sha256,
            bytes=len(data),
            fetched_at_ns=fetched_at_ns,
            primary_host=host in self.ALLOWED_PRIMARY_HOSTS,
            immutable_reference=immutable_reference,
            hash_match=hash_match,
            verified=verified,
            reason=(
                "DIRECT_PRIMARY_FETCH_HASH_MATCH"
                if verified
                else "CONTENT_OR_RESPONSE_NOT_VERIFIED"
            ),
        )

    def compile(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(manifest, dict):
            raise EvidenceError("MANIFEST_MUST_BE_OBJECT")
        artifact_id = manifest.get("artifact_id")
        claims = manifest.get("atomic_claims")
        if not isinstance(artifact_id, str) or not artifact_id:
            raise EvidenceError("ARTIFACT_ID_REQUIRED")
        if not isinstance(claims, list) or not claims:
            raise EvidenceError("ATOMIC_CLAIMS_REQUIRED")
        if len(claims) > self.MAX_CLAIMS:
            raise EvidenceError("TOO_MANY_CLAIMS")

        observations: List[Observation] = []
        verified = 0
        for claim in claims:
            if not isinstance(claim, dict):
                raise EvidenceError("INVALID_CLAIM")
            url = claim.get("evidence_url")
            expected_sha256 = claim.get("expected_sha256")
            if not isinstance(url, str):
                raise EvidenceError("CLAIM_EVIDENCE_URL_REQUIRED")
            if not isinstance(expected_sha256, str):
                raise EvidenceError("CLAIM_EXPECTED_SHA256_REQUIRED")
            try:
                observation = self.fetch_primary(url, expected_sha256)
            except EvidenceError as exc:
                observation = Observation(
                    url=url,
                    http_status=0,
                    content_sha256="",
                    expected_sha256=expected_sha256,
                    bytes=0,
                    fetched_at_ns=time.time_ns(),
                    primary_host=False,
                    immutable_reference=False,
                    hash_match=False,
                    verified=False,
                    reason=str(exc),
                )
            observations.append(observation)
            verified += int(observation.verified)

        density = verified / len(claims)
        return {
            "artifact_id": artifact_id,
            "compiler_version": self.VERSION,
            "observations": [asdict(item) for item in observations],
            "metrics": {
                "independent_evidence_density": round(density, 4),
                "verified_claims": verified,
                "total_claims": len(claims),
            },
            "gate_states": {
                "TECHNICAL_STATUS": "STATIC_VERIFIED" if observations else "NOT_EXECUTED",
                "EXECUTION_STATUS": "EXECUTED_IN_SESSION",
                "VALUE_STATUS": "UNKNOWN",
                "ECONOMIC_STATUS": "UNKNOWN",
                "ADVANTAGE_STATUS": "UNVERIFIED",
            },
            # Candidate means evidence was actually observed, not that CI,
            # runtime, deployment, or production have been verified.
            "final_classification": "CANDIDATE" if density >= 0.90 else "RESEARCH",
            "omega_verified": False,
            "production_confirmed": False,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", help="Path to a JSON manifest")
    args = parser.parse_args()
    with open(args.manifest, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    print(json.dumps(ZeroTrustEvidenceCompiler().compile(manifest), indent=2))
