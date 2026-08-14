import hashlib
import unittest
from unittest.mock import patch

from omega_compiler import ZeroTrustEvidenceCompiler


GOOD_URL = "https://github.com/modelcontextprotocol/servers/blob/0123456789abcdef0123456789abcdef01234567/README.md"
GOOD_DIGEST = hashlib.sha256(b"primary evidence").hexdigest()


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return b"primary evidence"


class CompilerTests(unittest.TestCase):
    def test_manifest_status_is_ignored_and_hash_pinning_controls_verification(self):
        compiler = ZeroTrustEvidenceCompiler()
        manifest = {
            "artifact_id": "TEST",
            "atomic_claims": [
                {
                    "id": "good",
                    "status": "VERIFIED",
                    "evidence_url": GOOD_URL,
                    "expected_sha256": GOOD_DIGEST,
                },
                {
                    "id": "bad",
                    "status": "VERIFIED",
                    "evidence_url": GOOD_URL,
                    "expected_sha256": "0" * 64,
                },
            ],
        }
        with patch.object(compiler.opener, "open", return_value=FakeResponse()):
            result = compiler.compile(manifest)
        self.assertEqual(result["metrics"]["independent_evidence_density"], 0.5)
        self.assertEqual(result["gate_states"]["VALUE_STATUS"], "UNKNOWN")
        self.assertFalse(result["omega_verified"])

    def test_non_https_is_rejected_without_network_access(self):
        compiler = ZeroTrustEvidenceCompiler()
        with self.assertRaises(Exception):
            compiler.fetch_primary(
                "http://github.com/modelcontextprotocol/servers/blob/0123456789abcdef0123456789abcdef01234567/README.md",
                GOOD_DIGEST,
            )

    def test_untrusted_host_is_rejected_without_network_access(self):
        compiler = ZeroTrustEvidenceCompiler()
        with self.assertRaises(Exception):
            compiler.fetch_primary("https://example.com/evidence", GOOD_DIGEST)

    def test_mutable_github_reference_is_rejected(self):
        compiler = ZeroTrustEvidenceCompiler()
        mutable = "https://github.com/modelcontextprotocol/servers/blob/main/README.md"
        with self.assertRaises(Exception):
            compiler.fetch_primary(mutable, GOOD_DIGEST)

    def test_expected_hash_is_required(self):
        compiler = ZeroTrustEvidenceCompiler()
        with self.assertRaises(Exception):
            compiler.fetch_primary(GOOD_URL, "not-a-sha256")


if __name__ == "__main__":
    unittest.main()
