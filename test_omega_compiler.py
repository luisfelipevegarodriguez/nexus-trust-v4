import unittest
from unittest.mock import patch

from omega_compiler import ZeroTrustEvidenceCompiler


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return b"primary evidence"


class CompilerTests(unittest.TestCase):
    def test_manifest_status_is_ignored_and_primary_fetch_controls_verification(self):
        compiler = ZeroTrustEvidenceCompiler()
        manifest = {
            "artifact_id": "TEST",
            "atomic_claims": [
                {"id": "good", "status": "VERIFIED", "evidence_url": "https://github.com/modelcontextprotocol/servers"},
                {"id": "bad", "status": "VERIFIED", "evidence_url": "https://example.com/fake"},
            ],
        }
        with patch("omega_compiler.urlopen", return_value=FakeResponse()):
            result = compiler.compile(manifest)
        self.assertEqual(result["metrics"]["independent_evidence_density"], 0.5)
        self.assertEqual(result["gate_states"]["VALUE_STATUS"], "UNKNOWN")
        self.assertFalse(result["omega_verified"])

    def test_non_https_is_rejected_without_network_access(self):
        compiler = ZeroTrustEvidenceCompiler()
        with self.assertRaises(Exception):
            compiler.fetch_primary("http://github.com/modelcontextprotocol/servers")

    def test_untrusted_host_is_rejected_without_network_access(self):
        compiler = ZeroTrustEvidenceCompiler()
        with self.assertRaises(Exception):
            compiler.fetch_primary("https://example.com/evidence")


if __name__ == "__main__":
    unittest.main()
