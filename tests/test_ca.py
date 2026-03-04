"""
Tests for Certificate Authority (ca.py)
TC-CA-001 to TC-CA-008
"""

import pytest
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


class TestCAGeneration:
    """TC-CA-001: CA generates valid self-signed root certificate."""

    def test_ca_cert_is_self_signed(self, ca):
        cert = ca.ca_cert
        assert cert.subject == cert.issuer, "Root CA must be self-signed"

    def test_ca_cert_key_usage(self, ca):
        cert = ca.ca_cert
        ku   = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign, "CA must be able to sign certificates"
        assert ku.crl_sign,      "CA must be able to sign CRLs"

    def test_ca_cert_basic_constraints(self, ca):
        cert = ca.ca_cert
        bc   = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True, "Root CA BasicConstraints.ca must be True"

    def test_ca_cert_validity_period(self, ca):
        cert = ca.ca_cert
        now  = datetime.datetime.now(datetime.timezone.utc)
        assert cert.not_valid_before_utc < now < cert.not_valid_after_utc

    def test_ca_cert_pem_export(self, ca):
        pem = ca.get_ca_cert_pem()
        assert pem.startswith("-----BEGIN CERTIFICATE-----")
        assert "-----END CERTIFICATE-----" in pem


class TestCertificateIssuance:
    """TC-CA-002: CA issues valid user certificates."""

    def test_alice_cert_issued(self, alice, ca):
        cert = alice["cert"]
        cn   = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert cn == "alice"

    def test_cert_signed_by_ca(self, alice, ca):
        from cryptography.hazmat.primitives.asymmetric import padding
        cert = alice["cert"]
        # Should not raise
        ca.ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

    def test_cert_key_usage_digital_signature(self, alice):
        cert = alice["cert"]
        ku   = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.digital_signature

    def test_cert_key_usage_key_encipherment(self, alice):
        cert = alice["cert"]
        ku   = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_encipherment

    def test_serial_numbers_unique(self, alice, bob, carol):
        serials = {alice["cert"].serial_number, bob["cert"].serial_number, carol["cert"].serial_number}
        assert len(serials) == 3, "All certificate serials must be unique"

    def test_cert_not_ca(self, alice):
        cert = alice["cert"]
        bc   = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is False


class TestCertificateValidation:
    """TC-CA-003: verify_certificate checks chain, expiry, and CRL."""

    def test_valid_cert_passes(self, ca, alice):
        result = ca.verify_certificate(alice["cert"])
        assert result["chain_valid"]
        assert result["not_expired"]
        assert result["not_revoked"]
        assert result["valid"]

    def test_self_signed_user_cert_fails_chain(self, ca, km):
        """A cert not signed by our CA must fail chain check."""
        priv, pub = km.generate_keypair()
        # Sign the cert with its own key (not CA)
        from cryptography.x509.oid import NameOID
        import datetime as dt
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue")])
        now  = dt.datetime.now(dt.timezone.utc)
        fake_cert = (
            x509.CertificateBuilder()
            .subject_name(subj).issuer_name(subj)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(priv, __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256())
        )
        result = ca.verify_certificate(fake_cert)
        assert not result["chain_valid"]
        assert not result["valid"]


class TestCRL:
    """TC-CA-004: CRL revocation and checking."""

    def test_publish_crl(self, ca):
        crl = ca.publish_crl()
        assert crl is not None

    def test_crl_file_exists(self, ca):
        assert Path(ca.crl_path).exists()

    def test_unrevoked_cert_not_in_crl(self, ca, alice):
        assert not ca.is_revoked(alice["cert"].serial_number)

    def test_revoke_and_check(self, ca, carol):
        serial = carol["cert"].serial_number
        ca.revoke_certificate(serial)
        assert ca.is_revoked(serial)

    def test_revoked_cert_fails_validation(self, ca, carol):
        result = ca.verify_certificate(carol["cert"])
        assert not result["not_revoked"]
        assert not result["valid"]
