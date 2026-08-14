import hashlib
import socket
import unittest
from unittest import mock
from unittest.mock import patch

from omega_compiler import EvidenceError, ZeroTrustEvidenceCompiler


SHA = "0123456789abcdef0123456789abcdef01234567"
GOOD_URL = "https://github.com/modelcontextprotocol/servers/" f"blob/{SHA}/README.md"
RAW_URL = "https://raw.githubusercontent.com/modelcontextprotocol/servers/" f"{SHA}/README.md"
GOOD_DIGEST = hashlib.sha256(b"primary evidence").hexdigest()


class FakeResponse:
    def __init__(self, body=b"primary evidence", status=200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.body[:limit]


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.compiler = ZeroTrustEvidenceCompiler()
        self.dns_patch = patch.object(self.compiler, "_assert_public_dns", return_value="93.184.216.34")
        self.dns_patch.start()
        self.addCleanup(self.dns_patch.stop)

    def assert_rejected(self, url, digest=GOOD_DIGEST):
        with self.assertRaises(EvidenceError):
            self.compiler.fetch_primary(url, digest)

    def fake_open(self, body=b"primary evidence", status=200, headers=None):
        opener = mock.Mock()
        opener.open.return_value = FakeResponse(body, status, headers)
        return patch.object(self.compiler, "_build_opener", return_value=opener)

    def test_manifest_status_is_ignored(self):
        manifest = {
            "artifact_id": "TEST",
            "atomic_claims": [
                {"status": "VERIFIED", "evidence_url": GOOD_URL, "expected_sha256": GOOD_DIGEST},
                {"status": "VERIFIED", "evidence_url": GOOD_URL, "expected_sha256": "0" * 64},
            ],
        }
        with self.fake_open():
            result = self.compiler.compile(manifest)
        self.assertEqual(result["metrics"]["independent_evidence_density"], 0.5)
        self.assertEqual(result["gate_states"]["VALUE_STATUS"], "UNKNOWN")
        self.assertEqual(result["gate_states"]["TECHNICAL_STATUS"], "STATIC_INPUT_VALIDATED")
        self.assertEqual(result["final_classification"], "RESEARCH")
        self.assertFalse(result["omega_verified"])
        self.assertFalse(result["production_confirmed"])

    def test_root_github_is_rejected(self):
        self.assert_rejected("https://github.com")

    def test_http_is_rejected(self):
        self.assert_rejected(GOOD_URL.replace("https://", "http://"))

    def test_mutable_references_are_rejected(self):
        for ref in ("main", "master", "develop", "HEAD", "refs/heads/main", "refs/tags/v1.0.0"):
            self.assert_rejected("https://github.com/modelcontextprotocol/servers/blob/" f"{ref}/README.md")

    def test_sha_lengths_and_charset_are_rejected(self):
        for bad_sha in (SHA[:-1], SHA + "0", "g" * 40, "G" * 40):
            self.assert_rejected("https://github.com/modelcontextprotocol/servers/blob/" f"{bad_sha}/README.md")

    def test_userinfo_is_rejected(self):
        self.assert_rejected("https://user:pass@github.com/modelcontextprotocol/servers/" f"blob/{SHA}/README.md")

    def test_non_default_port_is_rejected(self):
        self.assert_rejected("https://github.com:8443/modelcontextprotocol/servers/" f"blob/{SHA}/README.md")

    def test_malformed_port_is_rejected_without_raw_exception(self):
        self.assert_rejected("https://github.com:not-a-port/modelcontextprotocol/servers/" f"blob/{SHA}/README.md")

    def test_query_and_fragment_are_rejected(self):
        for suffix in ("?download=1", "#section"):
            self.assert_rejected(GOOD_URL + suffix)

    def test_untrusted_host_is_rejected(self):
        self.assert_rejected("https://example.com/evidence")

    def test_trailing_dot_host_is_rejected(self):
        self.assert_rejected(GOOD_URL.replace("github.com", "github.com."))

    def test_non_ascii_host_is_rejected(self):
        self.assert_rejected(GOOD_URL.replace("github.com", "gïthub.com"))

    def test_double_slash_path_is_rejected(self):
        self.assert_rejected(GOOD_URL.replace("servers/", "servers//"))

    def test_backslash_path_is_rejected(self):
        self.assert_rejected(GOOD_URL.replace("servers/", "servers\\"))

    def test_dot_segments_are_rejected(self):
        self.assert_rejected(GOOD_URL.replace("servers/", "servers/../servers/"))

    def test_percent_encoded_path_is_rejected(self):
        self.assert_rejected(GOOD_URL.replace("modelcontextprotocol", "%6dodelcontextprotocol"))

    def test_long_url_is_rejected(self):
        self.assert_rejected(GOOD_URL + ("x" * 5000))

    def test_control_character_is_rejected(self):
        self.assert_rejected(GOOD_URL + "\n")

    def test_expected_hash_must_be_sha256(self):
        for bad_hash in ("", "not-a-sha256", "0" * 63, "g" * 64):
            self.assert_rejected(GOOD_URL, bad_hash)

    def test_redirect_is_fail_closed(self):
        opener = mock.Mock()
        opener.open.side_effect = EvidenceError("REDIRECT_FORBIDDEN")
        with patch.object(self.compiler, "_build_opener", return_value=opener):
            with self.assertRaises(EvidenceError):
                self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)

    def test_hash_mismatch_is_not_verified(self):
        with self.fake_open(body=b"different"):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)
        self.assertFalse(result.hash_match)

    def test_empty_content_is_not_verified_for_nonempty_expected_hash(self):
        with self.fake_open(body=b""):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)

    def test_response_size_is_bounded(self):
        body = b"x" * (self.compiler.MAX_BYTES + 1)
        with self.fake_open(body=body):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)
        self.assertEqual(result.reason, "SOURCE_TOO_LARGE")

    def test_declared_content_length_is_bounded_before_read(self):
        headers = {"Content-Length": str(self.compiler.MAX_BYTES + 1)}
        with self.fake_open(headers=headers):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)
        self.assertEqual(result.reason, "SOURCE_TOO_LARGE")

    def test_invalid_content_length_is_fail_closed(self):
        headers = {"Content-Length": "not-an-integer"}
        with self.fake_open(headers=headers):
            with self.assertRaises(EvidenceError) as ctx:
                self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertEqual(str(ctx.exception), "INVALID_CONTENT_LENGTH")

    def test_timeout_or_network_error_is_not_verified(self):
        opener = mock.Mock()
        opener.open.side_effect = TimeoutError("timeout")
        with patch.object(self.compiler, "_build_opener", return_value=opener):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)
        self.assertTrue(result.reason.startswith("FETCH_ERROR:"))

    def test_raw_github_pinned_reference_is_accepted(self):
        with self.fake_open():
            result = self.compiler.fetch_primary(RAW_URL, GOOD_DIGEST)
        self.assertTrue(result.verified)
        self.assertTrue(result.immutable_reference)

    def test_mcp_hosts_are_not_primary_evidence_without_immutable_reference(self):
        for host in ("https://modelcontextprotocol.io/evidence", "https://registry.modelcontextprotocol.io/evidence"):
            self.assert_rejected(host)

    def test_dns_private_address_is_rejected(self):
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("omega_compiler.socket.getaddrinfo", return_value=private):
            with self.assertRaises(EvidenceError) as ctx:
                self.compiler._assert_public_dns("github.com")
        self.assertEqual(str(ctx.exception), "DNS_NON_GLOBAL_ADDRESS_REJECTED")

    def test_dns_resolution_failure_is_rejected(self):
        with patch("omega_compiler.socket.getaddrinfo", side_effect=OSError("resolver failure")):
            with self.assertRaises(EvidenceError) as ctx:
                self.compiler._assert_public_dns("github.com")
        self.assertEqual(str(ctx.exception), "DNS_RESOLUTION_FAILED")

    def test_dns_returns_pinned_global_address(self):
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with patch("omega_compiler.socket.getaddrinfo", return_value=public):
            self.assertEqual(self.compiler._assert_public_dns("github.com"), "93.184.216.34")

    def test_mixed_dns_answers_fail_closed(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ]
        with patch("omega_compiler.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(EvidenceError):
                self.compiler._assert_public_dns("github.com")

    def test_proxy_handler_is_explicitly_disabled(self):
        with patch("omega_compiler.build_opener", return_value=mock.Mock()) as build:
            self.compiler._build_opener("93.184.216.34")
        handlers = build.call_args.args
        self.assertTrue(any(handler.__class__.__name__ == "ProxyHandler" and handler.proxies == {} for handler in handlers))

    def test_missing_manifest_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile({})

    def test_non_object_manifest_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile([])

    def test_empty_claims_are_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile({"artifact_id": "A", "atomic_claims": []})

    def test_malformed_claim_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile({"artifact_id": "A", "atomic_claims": ["not-a-claim"]})

    def test_claim_missing_url_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile({"artifact_id": "A", "atomic_claims": [{"expected_sha256": GOOD_DIGEST}]})

    def test_claim_missing_hash_is_rejected(self):
        with self.assertRaises(EvidenceError):
            self.compiler.compile({"artifact_id": "A", "atomic_claims": [{"evidence_url": GOOD_URL}]})

    def test_claim_count_is_bounded(self):
        claims = [{"evidence_url": GOOD_URL, "expected_sha256": GOOD_DIGEST}] * (self.compiler.MAX_CLAIMS + 1)
        with self.assertRaises(EvidenceError):
            self.compiler.compile({"artifact_id": "A", "atomic_claims": claims})

    def test_network_observation_controls_verification(self):
        manifest = {
            "artifact_id": "A",
            "atomic_claims": [{"status": "VERIFIED", "evidence_url": GOOD_URL, "expected_sha256": "0" * 64}],
        }
        with self.fake_open():
            result = self.compiler.compile(manifest)
        self.assertEqual(result["metrics"]["verified_claims"], 0)
        self.assertEqual(result["final_classification"], "RESEARCH")

    def test_successful_observation_never_promotes_global_state(self):
        manifest = {
            "artifact_id": "A",
            "atomic_claims": [{"status": "UNTRUSTED", "evidence_url": GOOD_URL, "expected_sha256": GOOD_DIGEST}],
        }
        with self.fake_open():
            result = self.compiler.compile(manifest)
        self.assertEqual(result["metrics"]["verified_claims"], 1)
        self.assertEqual(result["final_classification"], "RESEARCH")
        self.assertEqual(result["gate_states"]["TECHNICAL_STATUS"], "STATIC_INPUT_VALIDATED")
        self.assertFalse(result["omega_verified"])

    def test_non_200_response_is_not_verified(self):
        with self.fake_open(status=500):
            result = self.compiler.fetch_primary(GOOD_URL, GOOD_DIGEST)
        self.assertFalse(result.verified)

    def test_https_context_is_created_by_default(self):
        self.assertIsNotNone(self.compiler.tls)
        self.assertTrue(self.compiler.tls.check_hostname)

    def test_invalid_timeout_is_rejected(self):
        for value in (0, -1, True):
            with self.assertRaises(ValueError):
                ZeroTrustEvidenceCompiler(timeout=value)

    def test_scheme_normalization_does_not_bypass_host_or_sha_checks(self):
        url = GOOD_URL.replace("https://", "HTTPS://")
        with self.fake_open():
            result = self.compiler.fetch_primary(url, GOOD_DIGEST)
        self.assertTrue(result.verified)

    def test_case_insensitive_host_does_not_bypass_anchor(self):
        with self.fake_open():
            result = self.compiler.fetch_primary(GOOD_URL.replace("github.com", "GITHUB.COM"), GOOD_DIGEST)
        self.assertTrue(result.verified)


if __name__ == "__main__":
    unittest.main()
