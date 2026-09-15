import ipaddress
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.ssrf import (
    URLValidationError,
    is_ip_blocked,
    parse_and_validate_scheme,
    validate_resolved_ips,
)


class TestSchemeValidation(unittest.TestCase):
    def test_https_is_accepted(self):
        target = parse_and_validate_scheme("https://example.com/path")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.hostname, "example.com")

    def test_http_is_accepted(self):
        target = parse_and_validate_scheme("http://example.com")
        self.assertEqual(target.scheme, "http")

    def test_file_scheme_is_rejected(self):
        with self.assertRaises(URLValidationError):
            parse_and_validate_scheme("file:///etc/passwd")

    def test_ftp_scheme_is_rejected(self):
        with self.assertRaises(URLValidationError):
            parse_and_validate_scheme("ftp://example.com")

    def test_gopher_scheme_is_rejected(self):
        with self.assertRaises(URLValidationError):
            parse_and_validate_scheme("gopher://example.com")

    def test_empty_url_is_rejected(self):
        with self.assertRaises(URLValidationError):
            parse_and_validate_scheme("")

    def test_no_hostname_is_rejected(self):
        with self.assertRaises(URLValidationError):
            parse_and_validate_scheme("https:///path-only")

    def test_literal_private_ip_is_rejected_before_dns(self):
        with self.assertRaises(URLValidationError):
            parse_and_validate_scheme("http://127.0.0.1/")

    def test_literal_metadata_ip_is_rejected(self):
        """169.254.169.254 : IP de métadonnées cloud (AWS/GCP)."""
        with self.assertRaises(URLValidationError):
            parse_and_validate_scheme("http://169.254.169.254/latest/meta-data/")

    def test_literal_public_ip_is_accepted(self):
        target = parse_and_validate_scheme("http://93.184.216.34/")
        self.assertEqual(target.hostname, "93.184.216.34")


class TestIsIPBlocked(unittest.TestCase):
    def test_rfc1918_10_blocked(self):
        self.assertTrue(is_ip_blocked(ipaddress.ip_address("10.1.2.3")))

    def test_rfc1918_172_blocked(self):
        self.assertTrue(is_ip_blocked(ipaddress.ip_address("172.20.0.5")))

    def test_rfc1918_192_blocked(self):
        self.assertTrue(is_ip_blocked(ipaddress.ip_address("192.168.1.1")))

    def test_loopback_blocked(self):
        self.assertTrue(is_ip_blocked(ipaddress.ip_address("127.0.0.1")))

    def test_link_local_blocked(self):
        self.assertTrue(is_ip_blocked(ipaddress.ip_address("169.254.1.1")))

    def test_ipv6_loopback_blocked(self):
        self.assertTrue(is_ip_blocked(ipaddress.ip_address("::1")))

    def test_ipv6_link_local_blocked(self):
        self.assertTrue(is_ip_blocked(ipaddress.ip_address("fe80::1")))

    def test_ipv4_mapped_ipv6_private_is_blocked(self):
        self.assertTrue(is_ip_blocked(ipaddress.ip_address("::ffff:10.0.0.1")))

    def test_public_ip_not_blocked(self):
        self.assertFalse(is_ip_blocked(ipaddress.ip_address("8.8.8.8")))

    def test_public_ipv6_not_blocked(self):
        self.assertFalse(is_ip_blocked(ipaddress.ip_address("2606:4700:4700::1111")))


class TestValidateResolvedIPs(unittest.TestCase):
    def test_empty_list_is_rejected(self):
        with self.assertRaises(URLValidationError):
            validate_resolved_ips([])

    def test_all_public_ips_pass(self):
        validate_resolved_ips([ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("1.1.1.1")])

    def test_one_private_ip_among_public_is_rejected(self):
        """Cas DNS multi-réponses : une seule IP privée suffit à rejeter,
        pour éviter un contournement round-robin."""
        with self.assertRaises(URLValidationError):
            validate_resolved_ips(
                [ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("10.0.0.1")]
            )


class TestResolveHostnameMocked(unittest.TestCase):
    """La résolution DNS réelle n'est pas testée ici (réseau indisponible
    dans cet environnement) — seul l'appelant (ensure_url_is_safe) est
    vérifié avec une résolution mockée, pour couvrir l'orchestration."""

    @patch("security.ssrf.resolve_hostname")
    def test_ensure_url_is_safe_rejects_when_resolution_is_private(self, mock_resolve):
        from security.ssrf import ensure_url_is_safe

        mock_resolve.return_value = [ipaddress.ip_address("10.0.0.5")]
        with self.assertRaises(URLValidationError):
            ensure_url_is_safe("http://internal.example.com/")

    @patch("security.ssrf.resolve_hostname")
    def test_ensure_url_is_safe_accepts_public_resolution(self, mock_resolve):
        from security.ssrf import ensure_url_is_safe

        mock_resolve.return_value = [ipaddress.ip_address("93.184.216.34")]
        target = ensure_url_is_safe("https://example.com/")
        self.assertEqual(target.hostname, "example.com")


if __name__ == "__main__":
    unittest.main()
