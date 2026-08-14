import hashlib
import ssl
import unittest
from unittest.mock import patch

from omega_compiler import EvidenceError, ZeroTrustEvidenceCompiler


SHA = "0123456789abcdef0123456789abcdef01234567"
GOOD_URL = "https://github.com/modelcontextprotocol/servers/" f"blob/{SHA}/README.md"
GOOD_DIGEST = hashlib.sha256(b"primary evidence").hexdigest()


class FakeResponse:
    def __init__(self, body=b"primary evidence", status=200):
        self.body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.body[:limit]


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.compiler = ZeroTrustEvidenceCompiler()

    def test_manifest_status_is_ignored(self):
        manifest = {
            "artifact_id": "TEST",
            "atomic_claims": [
                {"status": "VERIFIED", "evidence_url": GOOD_URL, "expected_sha256": GOOD_DIGEST},
                {"status": "VERIFIED", "evidence_url": GOOD_URL, "expected_sha256": "0" * 64},
            ],
        }
        with patch.object(self.compiler.opener, "open", return_value=FakeResponse()):
            result = self.compiler.compile(manifest)
        self.assertEqual(result["metrics"]["independent_evidence_density"], 0.5)
        self.assertEqual(result["gate_states"]["VALUE_STATUS"], "UNKNOWN")
        self.assertFalse(result["omega_verified"])

    def test_root_github_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.fetch_primary("https://github.com", GOOD_DIGEST)

    def test_http_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.fetch_primary(GOOD_URL.replace("https://", "http://"), GOOD_DIGEST)

    def test_mutable_reference_is_rejected(self):
        mutable = "https://github.com/modelcontextprotocol/servers/blob/main/README.md"
        with self.assertRaises(EvidenceError):
            self.compiler.fetch_primary(mutable, GOOD_DIGEST)

    def test_bad_sha_lengths_and_charset_are_rejected(self):
        for bad_sha in (SHA[:-1], SHA + "0", "g" * 40):
            url = "https://github.com/modelcontextprotocol/servers/" f"blob/{bad_sha}/README.md"
            with self.assertRaises(EvidenceError):
                self.compiler.fetch_primary(url, GOOD_DIGEST)

    def test_userinfo_is_rejected(self):
        url = "https://user:pass@github.com/modelcontextprotocol/servers/" f"blob/{SHA}/README.md"
        with self.assertRaises(EvidenceError):
            self.compiler.fetch_primary(url, GOOD_DIGEST)

    def test_non_default_port_is_rejected(self):
        url = "https://github.com:8443/modelcontextprotocol/servers/" f"blob/{SHA}/README.md"
        with self.assertRaises(EvidenceError):
            self.compiler.fetch_primary(url, GOOD_DIGEST)

    def test_query_and_fragment_are_rejected(self):
        for suffix in ("?download=1", "#section"):
            with self.assertRaises(EvidenceError):
                self.compiler.fetch_primary(GOOD_URL + suffix, GOOD_DIGEST)

    def test_untrusted_host_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.fetch_primary("https://example.com/evidence", GOOD_DIGEST)

    def test_expected_hash_must_be_sha256(self):
        for bad_hash in ("", "not-a-sha256", "0" * 63, "g" * 64):
            with self.assertRaises(EvidenceError):
                self.compiler.fetch_primary(GOOD_URL, bad_hash)

    def test_redirect_is_fail_closed(self):
        with patch.object(self.compiler.opener, "open", side_effect=EvidenceError("REDIRECT_FORBIDDEN")):
            with self.assertRaises(EvidenceError):
                self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)

    def test_hash_mismatch_is_not_verified(self):
        with patch.object(self.compiler.opener, "open", return_value=FakeResponse(b"different")):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)
        self.assertFalse(result.hash_match)

    def test_empty_content_is_not_verified_for_nonempty_expected_hash(self):
        with patch.object(self.compiler.opener, "open", return_value=FakeResponse(b"")):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)

    def test_response_size_is_bounded(self):
        with patch.object(self.compiler.opener, "open", return_value=FakeResponse(b"x" * (self.compiler.MAX_BYTES + 1))):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)
        self.assertEqual(result.reason, "SOURCE_TOO_LARGE")

    def test_timeout_is_unverified(self):
        with patch.object(self.compiler.opener, "open", side_effect=TimeoutError("timed out")):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)
        self.assertIn("TimeoutError", result.reason)

    def test_invalid_certificate_is_unverified(self):
        with patch.object(self.compiler.opener, "open", side_effect=ssl.SSLCertVerificationError("bad cert")):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)

    def test_manifest_without_claims_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile({"artifact_id": "TEST", "atomic_claims": []})

    def test_manifest_missing_artifact_id_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile({"atomic_claims": [{"evidence_url": GOOD_URL, "expected_sha256": GOOD_DIGEST}]})

    def test_malformed_claim_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile({"artifact_id": "TEST", "atomic_claims": ["bad"]})

    def test_ci_metadata_cannot_promote_value(self):
        manifest = {
            "artifact_id": "TEST",
            "atomic_claims": [{"status": "VERIFIED", "evidence_url": GOOD_URL, "expected_sha256": GOOD_DIGEST, "ci": {"status": "PASSED"}}],
        }
        with patch.object(self.compiler.opener, "open", return_value=FakeResponse()):
            result = self.compiler.compile(manifest)
        self.assertEqual(result["gate_states"]["VALUE_STATUS"], "UNKNOWN")
        self.assertFalse(result["production_confirmed"])

    def test_raw_github_sha_pinning(self):
        raw_url = "https://raw.githubusercontent.com/modelcontextprotocol/servers/" f"{SHA}/README.md"
        with patch.object(self.compiler.opener, "open", return_value=FakeResponse()):
            result = self.compiler.fetch_primary(raw_url, GOOD_DIGEST)
        self.assertTrue(result.verified)

    def test_mcp_docs_are_not_implicitly_immutable(self):
        with self.assertRaises(EvidenceError):
            self.compiler.fetch_primary("https://modelcontextprotocol.io/specification", GOOD_DIGEST)

    def test_omega_and_production_are_always_false(self):
        manifest = {"artifact_id": "TEST", "atomic_claims": [{"status": "VERIFIED", "evidence_url": GOOD_URL, "expected_sha256": GOOD_DIGEST}]}
        with patch.object(self.compiler.opener, "open", return_value=FakeResponse()):
            result = self.compiler.compile(manifest)
        self.assertFalse(result["omega_verified"])
        self.assertFalse(result["production_confirmed"])


if __name__ == "__main__":
    unittest.main()
