from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import time
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class EvidenceError(Exception):
    pass


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
    VERSION = "4.2.1-zero-trust-pinned"
    ALLOWED_PRIMARY_HOSTS = frozenset({
        "github.com",
        "raw.githubusercontent.com",
        "modelcontextprotocol.io",
        "registry.modelcontextprotocol.io",
    })
    GITHUB_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
    MAX_BYTES = 2_000_000

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.tls = ssl.create_default_context()
        self.opener = build_opener(
            _NoRedirectHandler(),
            HTTPSHandler(context=self.tls),
        )

    def _parse_and_validate_url(self, url: str) -> tuple[str, bool]:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise EvidenceError("SOURCE_URL_MUST_BE_HTTPS")
        host = parsed.hostname.lower().rstrip(".")
        if host not in self.ALLOWED_PRIMARY_HOSTS:
            raise EvidenceError("SOURCE_HOST_NOT_IN_TRUST_ANCHORS")

        immutable = False
        if host in {"github.com", "raw.githubusercontent.com"}:
            parts = [p for p in parsed.path.split("/") if p]
            if host == "github.com":
                immutable = (
                    len(parts) >= 5
                    and parts[2] in {"blob", "tree"}
                    and bool(self.GITHUB_SHA_RE.fullmatch(parts[3]))
                )
            else:
                immutable = len(parts) >= 3 and bool(self.GITHUB_SHA_RE.fullmatch(parts[2]))
        return host, immutable

    def fetch_primary(self, url: str, expected_sha256: str) -> Observation:
        host, immutable_reference = self._parse_and_validate_url(url)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256 or ""):
            raise EvidenceError("EXPECTED_SHA256_REQUIRED")
        if not immutable_reference:
            raise EvidenceError("IMMUTABLE_SOURCE_REFERENCE_REQUIRED")

        fetched_at_ns = time.time_ns()
        request = Request(url, headers={"User-Agent": "OmegaEvidenceCompiler/4.2"})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                status = int(response.status)
                data = response.read(self.MAX_BYTES + 1)
        except EvidenceError:
            raise
        except Exception as exc:
            return Observation(
                url, 0, "", expected_sha256, 0, fetched_at_ns,
                host in self.ALLOWED_PRIMARY_HOSTS, immutable_reference,
                False, False, type(exc).__name__
            )

        if len(data) > self.MAX_BYTES:
            return Observation(
                url, status, "", expected_sha256, len(data), fetched_at_ns,
                True, immutable_reference, False, False, "SOURCE_TOO_LARGE"
            )

        digest = hashlib.sha256(data).hexdigest()
        hash_match = digest.lower() == expected_sha256.lower()
        verified = (
            200 <= status < 300
            and host in self.ALLOWED_PRIMARY_HOSTS
            and immutable_reference
            and hash_match
        )
        reason = "DIRECT_PRIMARY_FETCH_HASH_MATCH" if verified else "HASH_MISMATCH"
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
            reason=reason,
        )

    def compile(self, manifest: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(manifest, dict):
            raise EvidenceError("MANIFEST_MUST_BE_OBJECT")
        artifact_id = manifest.get("artifact_id")
        claims = manifest.get("atomic_claims")
        if not isinstance(artifact_id, str) or not artifact_id:
            raise EvidenceError("ARTIFACT_ID_REQUIRED")
        if not isinstance(claims, list) or not claims:
            raise EvidenceError("ATOMIC_CLAIMS_REQUIRED")

        observations: list[Observation] = []
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
            observation = self.fetch_primary(url, expected_sha256)
            observations.append(observation)
            if observation.verified:
                verified += 1

        density = verified / len(claims)
        return {
            "artifact_id": artifact_id,
            "compiler_version": self.VERSION,
            "observations": [asdict(item) for item in observations],
            "metrics": {"independent_evidence_density": round(density, 4)},
            "gate_states": {
                "TECHNICAL_STATUS": "STATIC_VERIFIED" if observations else "NOT_EXECUTED",
                "EXECUTION_STATUS": "EXECUTED_IN_SESSION",
                "VALUE_STATUS": "UNKNOWN",
                "ECONOMIC_STATUS": "UNKNOWN",
                "ADVANTAGE_STATUS": "UNVERIFIED",
            },
            "final_classification": "OMEGA_CANDIDATE" if density >= 0.90 else "RESEARCH",
            "omega_verified": False,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", help="Path to a JSON manifest")
    args = parser.parse_args()
    with open(args.manifest, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    print(json.dumps(ZeroTrustEvidenceCompiler().compile(manifest), indent=2))
