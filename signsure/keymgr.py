"""
SignSure Key Manager Module
============================
Handles RSA-2048 key pair generation, PKCS#12 keystore management,
and secure key storage/retrieval with passphrase protection.
"""

import os
import logging
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger(__name__)


class KeyManager:
    """
    Manages RSA key pairs and PKCS#12 keystores for SignSure users.

    Private keys are NEVER stored in plaintext.
    All private key material is protected inside PKCS#12 (.p12) files
    encrypted with a user-chosen passphrase via PBKDF2-SHA256.
    """

    def __init__(self, keys_dir: str):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)

    # ── KEY GENERATION ─────────────────────────────────────────────────────

    def generate_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate an RSA-2048 key pair.

        Uses public_exponent=65537 (Fermat prime F4) as recommended by
        NIST SP 800-131A. Key size 2048 bits provides ≥112 bits of security.

        Returns:
            (private_key, public_key) tuple
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        logger.info("Generated RSA-2048 key pair")
        return private_key, private_key.public_key()

    # ── PKCS#12 KEYSTORE ──────────────────────────────────────────────────

    def save_to_pkcs12(
        self,
        username: str,
        private_key: rsa.RSAPrivateKey,
        cert: x509.Certificate,
        passphrase: bytes,
        ca_cert: Optional[x509.Certificate] = None,
    ) -> str:
        """
        Bundle private key + certificate into an encrypted PKCS#12 file.

        The PKCS#12 container is encrypted using AES-256-CBC with a key
        derived from the passphrase. The MAC uses HMAC-SHA256.

        Args:
            username:    Used as the keystore filename and friendly name.
            private_key: RSA private key to store.
            cert:        User's X.509 certificate.
            passphrase:  Bytes passphrase to protect the keystore.
            ca_cert:     Optional CA certificate to include in the chain.

        Returns:
            Path to the saved .p12 file.
        """
        cas = [ca_cert] if ca_cert else []

        p12_data = pkcs12.serialize_key_and_certificates(
            name=username.encode(),
            key=private_key,
            cert=cert,
            cas=cas,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )

        p12_path = self.keys_dir / f"{username}.p12"
        with open(p12_path, "wb") as f:
            f.write(p12_data)

        logger.info("PKCS#12 keystore saved: %s", p12_path)
        return str(p12_path)

    def load_from_pkcs12(
        self,
        p12_path: str,
        passphrase: bytes,
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, list]:
        """
        Load private key and certificate from a PKCS#12 file.

        Args:
            p12_path:   Path to the .p12 file.
            passphrase: Passphrase used during save.

        Returns:
            (private_key, certificate, additional_certs) tuple.

        Raises:
            ValueError: If passphrase is wrong or file is corrupt.
        """
        with open(p12_path, "rb") as f:
            p12_data = f.read()

        try:
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                p12_data, passphrase
            )
        except Exception as exc:
            raise ValueError(
                "Failed to load PKCS#12 keystore. Wrong passphrase or corrupted file."
            ) from exc

        logger.info("PKCS#12 keystore loaded: %s", p12_path)
        return private_key, cert, additional_certs or []

    # ── PUBLIC KEY EXPORT ──────────────────────────────────────────────────

    def export_public_key_pem(self, public_key: rsa.RSAPublicKey) -> str:
        """Export a public key in PEM format (safe to share)."""
        return public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def export_cert_pem(self, cert: x509.Certificate) -> str:
        """Export an X.509 certificate in PEM format."""
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def load_cert_from_pem(self, pem_data: str) -> x509.Certificate:
        """Load an X.509 certificate from PEM string."""
        return x509.load_pem_x509_certificate(pem_data.encode())

    def load_public_key_from_pem(self, pem_data: str) -> rsa.RSAPublicKey:
        """Load a public key from PEM string."""
        return serialization.load_pem_public_key(pem_data.encode())

    def get_p12_path(self, username: str) -> str:
        """Get the expected PKCS#12 path for a username."""
        return str(self.keys_dir / f"{username}.p12")

    def p12_exists(self, username: str) -> bool:
        """Check if a PKCS#12 keystore exists for the given username."""
        return (self.keys_dir / f"{username}.p12").exists()
