"""
SignSure Signature Verification Module
=========================================
Verifies RSA-PSS signatures from .sig bundles.
Performs: certificate chain validation, CRL check, hash match, signature math.
"""

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
from cryptography.exceptions import InvalidSignature

from .ca import CertificateAuthority

logger = logging.getLogger(__name__)


class VerificationResult:
    """Structured result of a signature verification attempt."""

    def __init__(self):
        self.valid          = False
        self.signer_name    = ""
        self.signer_serial  = 0
        self.signed_at      = ""
        self.document_name  = ""
        self.hash_match     = False
        self.chain_valid    = False
        self.not_revoked    = False
        self.not_expired    = False
        self.sig_math_valid = False
        self.errors         = []
        # Additional diagnostic fields (useful for UI debugging)
        self.cert_issuer    = ""
        self.ca_issuer      = ""

    def to_dict(self) -> dict:
        return {
            "valid":          self.valid,
            "signer_name":    self.signer_name,
            "signer_serial":  self.signer_serial,
            "signed_at":      self.signed_at,
            "document_name":  self.document_name,
            "hash_match":     self.hash_match,
            "chain_valid":    self.chain_valid,
            "not_revoked":    self.not_revoked,
            "not_expired":    self.not_expired,
            "sig_math_valid": self.sig_math_valid,
            "errors":         self.errors,
            "cert_issuer":    self.cert_issuer,
            "ca_issuer":      self.ca_issuer,
        }

    def __str__(self):
        status = "✅ VALID" if self.valid else "❌ INVALID"
        return (
            f"{status} — Signer: {self.signer_name} | "
            f"Signed: {self.signed_at} | "
            f"Errors: {', '.join(self.errors) or 'None'}"
        )


class VerificationService:
    """
    Verifies document signatures produced by SignatureService.

    Verification pipeline:
      1. Load and parse .sig bundle
      2. Extract embedded X.509 certificate
      3. Verify certificate chain (CA signature)
      4. Check certificate expiry
      5. Check certificate against CRL (revocation)
      6. Recompute document SHA-256 hash and compare
      7. Verify RSA-PSS signature mathematics
    """

    PSS_SALT_LENGTH = 32

    def __init__(self, ca: CertificateAuthority):
        self.ca = ca

    # ── PUBLIC API ─────────────────────────────────────────────────────────

    def verify_file(self, file_path: str, sig_path: str) -> VerificationResult:
        """
        Full verification pipeline for a signed file.

        Args:
            file_path: Path to the original document.
            sig_path:  Path to the corresponding .sig file.

        Returns:
            VerificationResult with detailed status.
        """
        result = VerificationResult()

        # ── Load bundle ──────────────────────────────────────────────
        try:
            with open(sig_path) as f:
                bundle = json.load(f)
        except Exception as e:
            result.errors.append(f"Cannot read .sig file: {e}")
            return result

        result.document_name = bundle.get("document_name", "")
        result.signed_at     = bundle.get("timestamp", "")
        result.signer_serial = bundle.get("signer_serial", 0)

        # ── Extract certificate ──────────────────────────────────────
        try:
            cert = x509.load_pem_x509_certificate(
                bundle["certificate_pem"].encode()
            )
        except Exception as e:
            result.errors.append(f"Invalid certificate in bundle: {e}")
            return result

        result.signer_name = self._extract_cn(cert)
        # record certificate issuer for diagnostics
        try:
            result.cert_issuer = cert.issuer.rfc4514_string()
        except Exception:
            result.cert_issuer = ""

        logger.debug("Verifier: loaded bundle for document=%s signer_serial=%s",
                 result.document_name, result.signer_serial)

        # ── Step 3: Certificate chain ────────────────────────────────
        cert_status = self.ca.verify_certificate(cert)
        result.chain_valid   = cert_status["chain_valid"]
        result.not_expired   = cert_status["not_expired"]
        result.not_revoked   = cert_status["not_revoked"]

        # record server CA subject for diagnostics (if available)
        try:
            result.ca_issuer = self.ca.ca_cert.subject.rfc4514_string()
        except Exception:
            result.ca_issuer = ""

        logger.debug("Certificate status: %s", cert_status)

        if not result.chain_valid:
            result.errors.append("Certificate chain validation failed — untrusted issuer")
        if not result.not_expired:
            result.errors.append("Certificate has expired")
        if not result.not_revoked:
            result.errors.append("Certificate has been REVOKED")

        if not (result.chain_valid and result.not_expired and result.not_revoked):
            return result

        # ── Step 6: Document hash ────────────────────────────────────
        try:
            computed_hash = self._hash_file(file_path)
            stored_hash   = bundle.get("document_hash_sha256", "")
            result.hash_match = (computed_hash == stored_hash)
            logger.debug(
                "Hash compare — computed=%s stored=%s match=%s",
                computed_hash, stored_hash, result.hash_match,
            )
        except FileNotFoundError:
            result.errors.append(f"Document file not found: {file_path}")
            return result

        if not result.hash_match:
            result.errors.append(
                "Document hash mismatch — file has been TAMPERED after signing"
            )
            return result

        # ── Step 7: RSA-PSS signature math ───────────────────────────
        try:
            raw_sig = base64.b64decode(bundle["signature"])
            payload = self._build_payload(
                stored_hash,
                bundle["timestamp"],
                bundle["signer_serial"],
            )

            logger.debug(
                "Verifying signature — sig_len=%d payload_hash=%s",
                len(raw_sig), hashlib.sha256(payload).hexdigest(),
            )

            cert.public_key().verify(
                raw_sig,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=self.PSS_SALT_LENGTH,
                ),
                hashes.SHA256(),
            )
            result.sig_math_valid = True
        except InvalidSignature:
            result.errors.append("RSA-PSS signature is cryptographically INVALID")
            return result
        except Exception as e:
            logger.exception("Signature verification raised unexpected error")
            result.errors.append(f"Signature verification error: {e}")
            return result

        result.valid = True
        logger.info("Verification PASSED: %s signed by %s", file_path, result.signer_name)
        return result

    def verify_bundle_only(self, bundle: dict) -> dict:
        """Verify a sig bundle dict (without file — checks cert + sig structure)."""
        result = {"cert_valid": False, "bundle_well_formed": False, "errors": []}

        required = ["document_hash_sha256", "timestamp", "signer_serial",
                    "signature", "certificate_pem", "algorithm"]
        missing = [k for k in required if k not in bundle]
        if missing:
            result["errors"].append(f"Missing fields: {missing}")
            return result

        result["bundle_well_formed"] = True

        try:
            cert = x509.load_pem_x509_certificate(bundle["certificate_pem"].encode())
            cert_status = self.ca.verify_certificate(cert)
            result["cert_valid"] = cert_status["valid"]
            if not cert_status["chain_valid"]:
                result["errors"].append("Certificate chain invalid")
            if not cert_status["not_expired"]:
                result["errors"].append("Certificate expired")
            if not cert_status["not_revoked"]:
                result["errors"].append("Certificate revoked")
        except Exception as e:
            result["errors"].append(f"Certificate parsing failed: {e}")

        return result

    # ── HELPERS ────────────────────────────────────────────────────────────

    def _hash_file(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _build_payload(self, doc_hash: str, timestamp: str, serial: int) -> bytes:
        """Must match signer.py exactly."""
        combined = f"{doc_hash}:{timestamp}:{serial}".encode("utf-8")
        return hashlib.sha256(combined).digest()

    def _extract_cn(self, cert: x509.Certificate) -> str:
        """Extract Common Name from certificate subject."""
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                return attr.value
        return "Unknown"
