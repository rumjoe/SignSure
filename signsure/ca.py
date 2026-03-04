"""
SignSure Certificate Authority Module
======================================
Implements a two-tier PKI: Root CA + user (leaf) certificates.
Handles X.509 certificate issuance, CRL management, and revocation.
"""

import os
import json
import datetime
import logging
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


class CertificateAuthority:
    """
    Root Certificate Authority for SignSure PKI.

    Generates and signs X.509 v3 certificates, manages a CRL,
    and performs certificate chain validation.
    """

    CA_CERT_FILENAME = "ca_cert.pem"
    CA_KEY_FILENAME  = "ca_key.pem"
    CRL_FILENAME     = "ca.crl"
    SERIAL_FILENAME  = "serial.json"

    def __init__(self, ca_dir: str, passphrase: Optional[bytes] = None):
        self.ca_dir    = Path(ca_dir)
        self.passphrase = passphrase
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        self._ca_key:  Optional[rsa.RSAPrivateKey] = None
        self._ca_cert: Optional[x509.Certificate]  = None

        self._serial_file = self.ca_dir / self.SERIAL_FILENAME
        self._crl_path    = self.ca_dir / self.CRL_FILENAME
        self._cert_path   = self.ca_dir / self.CA_CERT_FILENAME
        self._key_path    = self.ca_dir / self.CA_KEY_FILENAME

    # ── INITIALISATION ─────────────────────────────────────────────────────

    def generate_ca(
        self,
        common_name: str = "SignSure-RootCA",
        org: str = "SignSure PKI",
        country: str = "NP",
        validity_days: int = 3650,
        force: bool = False,
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Generate root CA key pair and self-signed certificate.
        
        Args:
            common_name: CA common name (CN)
            org: Organization name
            country: Country code
            validity_days: Certificate validity in days
            force: If True, overwrite existing CA (WARNING: invalidates all signatures)
            
        Raises:
            RuntimeError: If CA already exists and force=False
        """
        # Prevent accidental CA regeneration
        if self._cert_path.exists() and not force:
            raise RuntimeError(
                f"CA already exists at {self._cert_path}. "
                "Use force=True to overwrite (WARNING: this will invalidate all existing signatures!). "
                "To use the existing CA, call load_ca() instead."
            )
        
        logger.info("Generating Root CA: %s", common_name)

        # RSA-2048 key — NIST SP 800-131A minimum
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Persist to disk
        self._save_key(private_key, self._key_path)
        self._save_cert(cert, self._cert_path)
        self._init_serial()

        self._ca_key  = private_key
        self._ca_cert = cert

        logger.info("Root CA generated — serial %s", cert.serial_number)
        return private_key, cert

    def load_ca(self) -> None:
        """Load an existing CA from disk."""
        if not self._cert_path.exists() or not self._key_path.exists():
            raise FileNotFoundError(
                "CA files not found. Run generate_ca() first."
            )

        with open(self._key_path, "rb") as f:
            self._ca_key = serialization.load_pem_private_key(
                f.read(), password=self.passphrase
            )

        with open(self._cert_path, "rb") as f:
            self._ca_cert = x509.load_pem_x509_certificate(f.read())

        # Sanity check: ensure the loaded certificate is actually a CA cert.
        try:
            bc = self._ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                raise RuntimeError("Loaded certificate is not a CA (BasicConstraints CA=False)")
        except x509.ExtensionNotFound:
            raise RuntimeError("Loaded CA certificate lacks BasicConstraints extension")

        logger.info("CA loaded: %s", self._ca_cert.subject.rfc4514_string())

    # ── CERTIFICATE ISSUANCE ───────────────────────────────────────────────

    def issue_certificate(
        self,
        username: str,
        public_key: rsa.RSAPublicKey,
        email: Optional[str] = None,
        org: str = "SignSure PKI",
        country: str = "NP",
        validity_days: int = 365,
    ) -> x509.Certificate:
        """Issue and sign an X.509 v3 user certificate."""
        self._ensure_loaded()
        serial = self._next_serial()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36"),  # documentSigning
                ]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._ca_key.public_key()
                ),
                critical=False,
            )
        )

        if email:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(email)]),
                critical=False,
            )

        cert = builder.sign(self._ca_key, hashes.SHA256())
        logger.info("Issued certificate for %s (serial %s)", username, serial)
        return cert

    # ── REVOCATION ─────────────────────────────────────────────────────────

    def revoke_certificate(
        self,
        serial: int,
        reason: x509.ReasonFlags = x509.ReasonFlags.unspecified,
    ) -> None:
        """Add a certificate serial number to the CRL."""
        self._ensure_loaded()

        revoked_certs = self._load_revoked_certs()
        revoked_certs[str(serial)] = {
            "revocation_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "reason": reason.name,
        }
        self._save_revoked_certs(revoked_certs)
        self.publish_crl()
        logger.warning("Certificate serial %s revoked (%s)", serial, reason.name)

    def publish_crl(self) -> x509.CertificateRevocationList:
        """Build, sign, and write the CRL to disk."""
        self._ensure_loaded()

        now       = datetime.datetime.now(datetime.timezone.utc)
        next_upd  = now + datetime.timedelta(days=7)
        revoked   = self._load_revoked_certs()

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._ca_cert.subject)
            .last_update(now)
            .next_update(next_upd)
        )

        for serial_str, info in revoked.items():
            rev_date = datetime.datetime.fromisoformat(info["revocation_date"])
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(serial_str))
                .revocation_date(rev_date)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(self._ca_key, hashes.SHA256())

        with open(self._crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.DER))

        logger.info("CRL published (%d revoked entries)", len(revoked))
        return crl

    # ── VALIDATION ─────────────────────────────────────────────────────────

    def verify_certificate(self, cert: x509.Certificate) -> dict:
        """
        Validate a certificate: chain, expiry, and CRL.
        Returns a dict with status fields.
        """
        self._ensure_loaded()
        result = {
            "chain_valid": False,
            "not_expired": False,
            "not_revoked": False,
            "valid": False,
            "subject": cert.subject.rfc4514_string(),
            "serial": cert.serial_number,
        }

        # 1 — Chain: verify CA signature
        try:
            self._ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            result["chain_valid"] = True
        except InvalidSignature:
            return result

        # 2 — Expiry
        now = datetime.datetime.now(datetime.timezone.utc)
        if cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            result["not_expired"] = True
        else:
            return result

        # 3 — CRL check
        if self._crl_path.exists():
            with open(self._crl_path, "rb") as f:
                crl = x509.load_der_x509_crl(f.read())
            revoked_entry = crl.get_revoked_certificate_by_serial_number(
                cert.serial_number
            )
            result["not_revoked"] = revoked_entry is None
        else:
            result["not_revoked"] = True  # No CRL yet = not revoked

        result["valid"] = all([
            result["chain_valid"],
            result["not_expired"],
            result["not_revoked"],
        ])
        return result

    def is_revoked(self, serial: int) -> bool:
        """Quick check: is the given serial in the CRL?"""
        if not self._crl_path.exists():
            return False
        with open(self._crl_path, "rb") as f:
            crl = x509.load_der_x509_crl(f.read())
        return crl.get_revoked_certificate_by_serial_number(serial) is not None

    # ── PROPERTIES ─────────────────────────────────────────────────────────

    @property
    def ca_cert(self) -> x509.Certificate:
        self._ensure_loaded()
        return self._ca_cert

    @property
    def ca_cert_path(self) -> str:
        return str(self._cert_path)

    @property
    def crl_path(self) -> str:
        return str(self._crl_path)

    def get_ca_cert_pem(self) -> str:
        self._ensure_loaded()
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # ── HELPERS ────────────────────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        if self._ca_cert is None or self._ca_key is None:
            if self._cert_path.exists():
                self.load_ca()
            else:
                raise RuntimeError("CA not initialised. Call generate_ca() or load_ca().")

    def _save_key(self, key: rsa.RSAPrivateKey, path: Path) -> None:
        enc = (
            serialization.BestAvailableEncryption(self.passphrase)
            if self.passphrase
            else serialization.NoEncryption()
        )
        with open(path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8, enc))

    def _save_cert(self, cert: x509.Certificate, path: Path) -> None:
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def _init_serial(self) -> None:
        with open(self._serial_file, "w") as f:
            json.dump({"next": 1000}, f)

    def _next_serial(self) -> int:
        data = {"next": 1000}
        if self._serial_file.exists():
            with open(self._serial_file) as f:
                data = json.load(f)
        serial = data["next"]
        data["next"] += 1
        with open(self._serial_file, "w") as f:
            json.dump(data, f)
        return serial

    def _revocation_file(self) -> Path:
        return self.ca_dir / "revoked.json"

    def _load_revoked_certs(self) -> dict:
        p = self._revocation_file()
        if p.exists():
            with open(p) as f:
                return json.load(f)
        return {}

    def _save_revoked_certs(self, data: dict) -> None:
        with open(self._revocation_file(), "w") as f:
            json.dump(data, f, indent=2)
