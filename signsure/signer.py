"""
SignSure Digital Signature Module
===================================
Implements RSA-PSS digital signatures over SHA-256 document hashes.
Creates detached .sig files (JSON bundles) alongside signed documents.
"""

import os
import json
import base64
import hashlib
import datetime
import logging
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .keymgr import KeyManager

logger = logging.getLogger(__name__)


class SignatureService:
    """
    Signs documents using RSA-PSS with SHA-256.

    The signature bundle (.sig file) contains:
      - SHA-256 digest of the document
      - RSA-PSS signature over the digest
      - Signer's X.509 certificate (for verification without external lookup)
      - ISO-8601 timestamp (replay attack prevention)
      - Certificate serial number
    """

    SIG_EXTENSION = ".sig"
    PSS_SALT_LENGTH = 32  # bytes — equals SHA-256 digest length

    def __init__(self, key_manager: KeyManager, sigs_dir: str):
        self.key_manager = key_manager
        self.sigs_dir    = Path(sigs_dir)
        self.sigs_dir.mkdir(parents=True, exist_ok=True)

    # ── PUBLIC API ─────────────────────────────────────────────────────────

    def sign_file(
        self,
        file_path: str,
        username: str,
        passphrase: bytes,
        output_sig_path: Optional[str] = None,
    ) -> dict:
        """
        Sign a file and produce a detached .sig bundle.

        Steps:
          1. Load private key + cert from PKCS#12 keystore
          2. Compute SHA-256 digest of the file
          3. Sign with RSA-PSS (salt=32 bytes, MGF1-SHA256)
          4. Build JSON bundle with sig, cert, timestamp, serial
          5. Save .sig file to sigs_dir

        Args:
            file_path:       Path to the file to sign.
            username:        Name matching the PKCS#12 keystore.
            passphrase:      Keystore passphrase.
            output_sig_path: Optional override for .sig file location.

        Returns:
            dict with signature bundle details.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        p12_path = self.key_manager.get_p12_path(username)
        private_key, cert, _ = self.key_manager.load_from_pkcs12(
            p12_path, passphrase
        )

        # Step 1: Hash the file
        doc_hash = self._hash_file(str(file_path))

        # Step 2: Build the signed payload
        # Replay prevention: signature covers hash + timestamp + serial
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        serial    = cert.serial_number

        payload = self._build_payload(doc_hash, timestamp, serial)

        # Step 3: Sign with RSA-PSS
        raw_signature = self._sign_payload(payload, private_key)

        # Step 4: Build the bundle
        cert_pem = self.key_manager.export_cert_pem(cert)
        bundle   = self._create_bundle(
            raw_signature, cert_pem, doc_hash, timestamp, serial, file_path.name
        )

        # Step 5: Save .sig file
        # Use a per-user signature filename to avoid overwriting when multiple
        # users sign the same document. Format: <filename>.<username>.sig
        default_name = f"{file_path.name}.{username}{self.SIG_EXTENSION}"
        sig_path = output_sig_path or self.sigs_dir / default_name
        with open(sig_path, "w") as f:
            json.dump(bundle, f, indent=2)

        logger.info("File signed: %s → %s", file_path, sig_path)
        return {
            "sig_path": str(sig_path),
            "document_hash": doc_hash,
            "signer": username,
            "serial": serial,
            "timestamp": timestamp,
        }

    # ── HELPERS ────────────────────────────────────────────────────────────

    def _hash_file(self, file_path: str) -> str:
        """Compute SHA-256 hash of a file, returned as hex string."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _build_payload(self, doc_hash: str, timestamp: str, serial: int) -> bytes:
        """
        Build the byte payload that is actually signed.

        Signing covers: SHA256(doc_hash || timestamp || serial_str)
        This binds the signature to a specific document AND time,
        preventing replay attacks.
        """
        combined = f"{doc_hash}:{timestamp}:{serial}".encode("utf-8")
        return hashlib.sha256(combined).digest()

    def _sign_payload(self, payload: bytes, private_key) -> bytes:
        """
        Sign with RSA-PSS (Probabilistic Signature Scheme).

        PSS is provably secure under the RSA assumption (EUF-CMA security).
        Salt length = 32 bytes (SHA-256 output length) as recommended by RFC 8017.
        """
        return private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=self.PSS_SALT_LENGTH,
            ),
            hashes.SHA256(),
        )

    def _create_bundle(
        self,
        raw_signature: bytes,
        cert_pem: str,
        doc_hash: str,
        timestamp: str,
        serial: int,
        filename: str,
    ) -> dict:
        """Assemble the JSON signature bundle."""
        return {
            "signsure_version": "1.0",
            "document_name":    filename,
            "document_hash_sha256": doc_hash,
            "timestamp":        timestamp,
            "signer_serial":    serial,
            "signature":        base64.b64encode(raw_signature).decode("ascii"),
            "certificate_pem":  cert_pem,
            "algorithm":        "RSA-PSS-SHA256",
            "pss_salt_length":  self.PSS_SALT_LENGTH,
        }

    def load_sig_bundle(self, sig_path: str) -> dict:
        """Load and parse a .sig JSON bundle."""
        with open(sig_path) as f:
            return json.load(f)
