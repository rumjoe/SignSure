"""
SignSure Test Configuration & Shared Fixtures
==============================================
Provides reusable pytest fixtures for all test modules.
"""

import os
import sys
import pytest
import tempfile
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from signsure.ca          import CertificateAuthority
from signsure.keymgr      import KeyManager
from signsure.signer      import SignatureService
from signsure.verifier    import VerificationService
from signsure.encryption  import EncryptionService


@pytest.fixture(scope="session")
def tmp_data():
    """Create a temporary data directory tree for the test session."""
    with tempfile.TemporaryDirectory(prefix="signsure_test_") as d:
        root = Path(d)
        for sub in ["ca", "keys", "signatures", "encrypted", "uploads"]:
            (root / sub).mkdir()
        yield root


@pytest.fixture(scope="session")
def ca(tmp_data):
    """Initialise a Root CA for testing."""
    authority = CertificateAuthority(ca_dir=str(tmp_data / "ca"))
    authority.generate_ca(common_name="TestCA", org="SignSure Tests", country="NP")
    return authority


@pytest.fixture(scope="session")
def km(tmp_data):
    """Shared KeyManager instance."""
    return KeyManager(keys_dir=str(tmp_data / "keys"))


@pytest.fixture(scope="session")
def sig_svc(km, tmp_data):
    """Shared SignatureService."""
    return SignatureService(km, sigs_dir=str(tmp_data / "signatures"))


@pytest.fixture(scope="session")
def ver_svc(ca):
    """Shared VerificationService."""
    return VerificationService(ca)


@pytest.fixture(scope="session")
def enc_svc(km, tmp_data):
    """Shared EncryptionService."""
    return EncryptionService(km, encrypted_dir=str(tmp_data / "encrypted"))


@pytest.fixture(scope="session")
def alice(ca, km):
    """Register Alice as a PKI user."""
    passphrase = b"AliceSecure123!"
    private_key, public_key = km.generate_keypair()
    cert = ca.issue_certificate("alice", public_key, email="alice@test.com")
    km.save_to_pkcs12("alice", private_key, cert, passphrase, ca_cert=ca.ca_cert)
    # Export cert PEM
    cert_pem_path = Path(km.keys_dir) / "alice_cert.pem"
    with open(cert_pem_path, "w") as f:
        f.write(km.export_cert_pem(cert))
    return {"username": "alice", "passphrase": passphrase, "cert": cert}


@pytest.fixture(scope="session")
def bob(ca, km):
    """Register Bob as a PKI user."""
    passphrase = b"BobSecure456!"
    private_key, public_key = km.generate_keypair()
    cert = ca.issue_certificate("bob", public_key, email="bob@test.com")
    km.save_to_pkcs12("bob", private_key, cert, passphrase, ca_cert=ca.ca_cert)
    cert_pem_path = Path(km.keys_dir) / "bob_cert.pem"
    with open(cert_pem_path, "w") as f:
        f.write(km.export_cert_pem(cert))
    return {"username": "bob", "passphrase": passphrase, "cert": cert}


@pytest.fixture(scope="session")
def carol(ca, km):
    """Register Carol (will be revoked in revocation tests)."""
    passphrase = b"CarolRevoke789!"
    private_key, public_key = km.generate_keypair()
    cert = ca.issue_certificate("carol", public_key)
    km.save_to_pkcs12("carol", private_key, cert, passphrase, ca_cert=ca.ca_cert)
    cert_pem_path = Path(km.keys_dir) / "carol_cert.pem"
    with open(cert_pem_path, "w") as f:
        f.write(km.export_cert_pem(cert))
    return {"username": "carol", "passphrase": passphrase, "cert": cert}


@pytest.fixture
def sample_text_file(tmp_path):
    """A simple text file for signing tests."""
    p = tmp_path / "contract.txt"
    p.write_text(
        "This is a test legal contract.\n"
        "Party A agrees to the terms.\n"
        "Party B agrees to the terms.\n"
        "Signed on 2026-02-23.\n"
    )
    return p


@pytest.fixture
def sample_pdf_like_file(tmp_path):
    """A binary file simulating a PDF for encryption tests."""
    p = tmp_path / "report.pdf"
    p.write_bytes(b"%PDF-1.4 SignSure test document content " + b"\x00\xff" * 100)
    return p
