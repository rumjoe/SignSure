"""
SignSure Hybrid Encryption Module
====================================
Implements hybrid encryption: AES-256-GCM for bulk data,
RSA-OAEP for session key wrapping.

Encryption output format (binary):
  [4 bytes: enc_key_len] [enc_session_key] [12 bytes: IV] [ciphertext+GCM_tag]
"""

import os
import struct
import logging
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keymgr import KeyManager

logger = logging.getLogger(__name__)


class EncryptionService:
    """
    Hybrid AES-256-GCM + RSA-OAEP encryption/decryption service.

    Why hybrid?
    - RSA-2048 with OAEP can only wrap ~190 bytes — unsuitable for large files.
    - AES-256-GCM is fast and provides authenticated encryption (AEAD).
    - Session key is ephemeral and discarded after each session.

    Security properties:
    - Confidentiality: AES-256 (key space 2^256)
    - Integrity:       GCM authentication tag (128-bit) detects ANY tampering
    - Key security:    RSA-OAEP (immune to Bleichenbacher attacks)
    - IV uniqueness:   os.urandom(12) per encryption (never reused)
    """

    ENC_EXTENSION = ".enc"
    IV_SIZE        = 12   # 96-bit IV for GCM
    KEY_SIZE       = 32   # 256-bit AES key
    GCM_TAG_SIZE   = 16   # 128-bit GCM authentication tag (appended by AESGCM)

    def __init__(self, key_manager: KeyManager, encrypted_dir: str):
        self.key_manager   = key_manager
        self.encrypted_dir = Path(encrypted_dir)
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)

    # ── ENCRYPTION ─────────────────────────────────────────────────────────

    def encrypt_file(
        self,
        file_path: str,
        recipient_cert_pem: str,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Encrypt a file for a specific recipient.

        Args:
            file_path:         Path to plaintext file.
            recipient_cert_pem: Recipient's X.509 certificate in PEM format.
            output_path:       Optional path for encrypted output.

        Returns:
            Path to the encrypted .enc file.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # 1 — Load recipient's public key from certificate
        recipient_cert = x509.load_pem_x509_certificate(recipient_cert_pem.encode())
        recipient_pub  = recipient_cert.public_key()

        # 2 — Generate random 256-bit AES session key (ephemeral)
        session_key = os.urandom(self.KEY_SIZE)

        # 3 — Generate random 96-bit IV (never reuse with same key)
        iv = os.urandom(self.IV_SIZE)

        # 4 — Read plaintext
        with open(file_path, "rb") as f:
            plaintext = f.read()

        # 5 — Encrypt with AES-256-GCM (includes 128-bit authentication tag)
        aesgcm     = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        # ciphertext = [encrypted data] + [16-byte GCM tag]

        # 6 — Wrap session key with RSA-OAEP (recipient's public key)
        enc_session_key = recipient_pub.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 7 — Serialize: [4B key_len][enc_key][12B IV][ciphertext+tag]
        out_path = output_path or self.encrypted_dir / f"{file_path.name}{self.ENC_EXTENSION}"
        with open(out_path, "wb") as f:
            key_len_bytes = struct.pack(">I", len(enc_session_key))
            f.write(key_len_bytes)
            f.write(enc_session_key)
            f.write(iv)
            f.write(ciphertext)

        # Zero out session key from memory
        session_key = b"\x00" * self.KEY_SIZE

        logger.info("File encrypted: %s → %s", file_path, out_path)
        return str(out_path)

    # ── DECRYPTION ─────────────────────────────────────────────────────────

    def decrypt_file(
        self,
        enc_path: str,
        username: str,
        passphrase: bytes,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Decrypt an encrypted file using the recipient's private key.

        Args:
            enc_path:    Path to the .enc file.
            username:    Recipient's username (for PKCS#12 lookup).
            passphrase:  Keystore passphrase.
            output_path: Optional path for decrypted output.

        Returns:
            Path to the decrypted file.

        Raises:
            ValueError: If GCM authentication fails (tamper detection).
            ValueError: If RSA decryption fails (wrong private key).
        """
        enc_path = Path(enc_path)

        # Load recipient's private key
        p12_path    = self.key_manager.get_p12_path(username)
        private_key, cert, _ = self.key_manager.load_from_pkcs12(p12_path, passphrase)

        # Parse encrypted file
        with open(enc_path, "rb") as f:
            raw = f.read()

        offset = 0

        # Read encrypted session key length
        key_len = struct.unpack(">I", raw[offset:offset+4])[0]
        offset += 4

        enc_session_key = raw[offset:offset+key_len]
        offset += key_len

        iv = raw[offset:offset+self.IV_SIZE]
        offset += self.IV_SIZE

        ciphertext = raw[offset:]  # includes GCM tag

        # Decrypt session key with RSA-OAEP
        try:
            session_key = private_key.decrypt(
                enc_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise ValueError(
                "RSA-OAEP decryption failed — wrong private key or corrupted file."
            ) from exc

        # Decrypt and authenticate with AES-256-GCM
        aesgcm = AESGCM(session_key)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except Exception as exc:
            raise ValueError(
                "AES-GCM authentication tag mismatch — ciphertext was TAMPERED."
            ) from exc

        # Determine output path
        original_name = enc_path.stem  # remove .enc
        out_path = output_path or self.encrypted_dir / f"decrypted_{original_name}"
        with open(out_path, "wb") as f:
            f.write(plaintext)

        # Zero session key
        session_key = b"\x00" * self.KEY_SIZE

        logger.info("File decrypted: %s → %s", enc_path, out_path)
        return str(out_path)

    # ── ENCRYPT STRING ──────────────────────────────────────────────────────

    def encrypt_message(self, message: str, recipient_cert_pem: str) -> bytes:
        """Encrypt a short message string. Returns raw bytes bundle."""
        recipient_cert = x509.load_pem_x509_certificate(recipient_cert_pem.encode())
        recipient_pub  = recipient_cert.public_key()

        session_key = os.urandom(self.KEY_SIZE)
        iv          = os.urandom(self.IV_SIZE)
        plaintext   = message.encode("utf-8")

        aesgcm     = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        enc_session_key = recipient_pub.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        key_len_bytes = struct.pack(">I", len(enc_session_key))
        return key_len_bytes + enc_session_key + iv + ciphertext

    def decrypt_message(self, bundle: bytes, username: str, passphrase: bytes) -> str:
        """Decrypt a message bundle produced by encrypt_message."""
        p12_path    = self.key_manager.get_p12_path(username)
        private_key, _, _ = self.key_manager.load_from_pkcs12(p12_path, passphrase)

        offset  = 0
        key_len = struct.unpack(">I", bundle[offset:offset+4])[0]
        offset += 4

        enc_session_key = bundle[offset:offset+key_len]
        offset += key_len
        iv              = bundle[offset:offset+self.IV_SIZE]
        offset += self.IV_SIZE
        ciphertext      = bundle[offset:]

        try:
            session_key = private_key.decrypt(
                enc_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise ValueError("RSA-OAEP decryption failed.") from exc

        aesgcm = AESGCM(session_key)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except Exception as exc:
            raise ValueError("AES-GCM authentication failed — tampered data.") from exc

        return plaintext.decode("utf-8")
