from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import time
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class EvidenceError(Exception):
    pass


@dataclass(frozen=True)
class Observation:
    url: str
    http_status: int
    content_sha256: str
    bytes: int
    fetched_at_ns: int
    primary_host: bool
    verified: bool
    reason: str


class ZeroTrustEvidenceCompiler:
    VERSION = "4.1.0-zero-trust"
    ALLOWED_PRIMARY_HOSTS = frozenset({
        "github.com",
        "raw.githubusercontent.com",
        "modelcontextprotocol.io",
        "registry.modelcontextprotocol.io",
    })
    MAX_BYTES = 2_000_000

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.tls = ssl.create_default_context()

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise EvidenceError("SOURCE_URL_MUST_BE_HTTPS")
        host = parsed.hostname.lower().rstrip(".")
        if host not in self.ALLOWED_PRIMARY_HOSTS:
            raise EvidenceError("SOURCE_HOST_NOT_IN_TRUST_ANCHORS")

    def fetch_primary(self, url: str) -> Observation:
        self._validate_url(url)
        fetched_at_ns = time.time_ns()
        request = Request(url, headers={"User-Agent": "OmegaEvidenceCompiler/4.1"})
        try:
            with urlopen(request, timeout=self.timeout, context=self.tls) as response:
                status = int(response.status)
                data = response.read(self.MAX_BYTES + 1)
        except Exception as exc:
            return Observation(url, 0, "", 0, fetched_at_ns, False, False, type(exc).__name__)
        if len(data) > self.MAX_BYTES:
            return Observation(url, status, "", len(data), fetched_at_ns, True, False, "SOURCE_TOO_LARGE")
        digest = hashlib.sha256(data).hexdigest()
        host = urlparse(url).hostname.lower().rstrip(".")
        return Observation(
            url=url,
            http_status=status,
            content_sha256=digest,
            bytes=len(data),
            fetched_at_ns=fetched_at_ns,
            primary_host=host in self.ALLOWED_PRIMARY_HOSTS,
            verified=200 <= status < 300,
            reason="DIRECT_PRIMARY_FETCH",
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
            if not isinstance(url, str):
                raise EvidenceError("CLAIM_EVIDENCE_URL_REQUIRED")
            observation = self.fetch_primary(url)
            observations.append(observation)
            if observation.verified and observation.primary_host:
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
