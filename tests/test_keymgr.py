"""
Tests for Key Manager (keymgr.py)
TC-KM-001 to TC-KM-007
"""

import pytest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


class TestKeyGeneration:
    """TC-KM-001: RSA-2048 key pairs are correctly generated."""

    def test_generates_rsa_key(self, km):
        priv, pub = km.generate_keypair()
        assert isinstance(priv, rsa.RSAPrivateKey)
        assert isinstance(pub, rsa.RSAPublicKey)

    def test_key_size_is_2048(self, km):
        priv, _ = km.generate_keypair()
        assert priv.key_size == 2048

    def test_public_exponent_is_65537(self, km):
        priv, _ = km.generate_keypair()
        assert priv.public_key().public_numbers().e == 65537

    def test_each_keypair_is_unique(self, km):
        priv1, _ = km.generate_keypair()
        priv2, _ = km.generate_keypair()
        n1 = priv1.private_numbers().p
        n2 = priv2.private_numbers().p
        assert n1 != n2, "Each key pair must be cryptographically unique"


class TestPKCS12:
    """TC-KM-002 to TC-KM-006: PKCS#12 keystore operations."""

    def test_pkcs12_file_created(self, km, alice):
        p12_path = km.get_p12_path("alice")
        assert Path(p12_path).exists()

    def test_pkcs12_loads_correctly(self, km, alice):
        p12_path = km.get_p12_path("alice")
        priv, cert, _ = km.load_from_pkcs12(p12_path, alice["passphrase"])
        assert priv is not None
        assert cert is not None

    def test_loaded_cert_matches_original(self, km, alice):
        p12_path = km.get_p12_path("alice")
        _, cert, _ = km.load_from_pkcs12(p12_path, alice["passphrase"])
        assert cert.serial_number == alice["cert"].serial_number

    def test_wrong_passphrase_raises(self, km, alice):
        """TC-KM-005: Wrong passphrase must be rejected."""
        p12_path = km.get_p12_path("alice")
        with pytest.raises(ValueError, match="Failed to load PKCS#12"):
            km.load_from_pkcs12(p12_path, b"WrongPassword!")

    def test_empty_passphrase_raises(self, km, alice):
        p12_path = km.get_p12_path("alice")
        with pytest.raises((ValueError, Exception)):
            km.load_from_pkcs12(p12_path, b"")

    def test_p12_exists_check(self, km, bob):
        # Ensure fixtures for alice and bob have been created so their
        # PKCS#12 keystores exist.
        assert km.p12_exists("alice")
        assert km.p12_exists("bob")
        assert not km.p12_exists("nonexistent_user_xyz")


class TestPEMExport:
    """TC-KM-007: PEM export functions."""

    def test_export_public_key_pem(self, km, alice):
        _, pub = km.generate_keypair()
        pem = km.export_public_key_pem(pub)
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_export_cert_pem(self, km, alice):
        pem = km.export_cert_pem(alice["cert"])
        assert pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_load_cert_from_pem_roundtrip(self, km, alice):
        pem  = km.export_cert_pem(alice["cert"])
        cert = km.load_cert_from_pem(pem)
        assert cert.serial_number == alice["cert"].serial_number
