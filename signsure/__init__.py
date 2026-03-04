"""
SignSure — Open-Source Document Signing & Verification System
==============================================================
A PKI-based cryptographic tool providing:
  • RSA-PSS digital signatures (SHA-256)
  • X.509 certificate management
  • AES-256-GCM hybrid encryption
  • Certificate Revocation List (CRL)
  • PKCS#12 secure key storage

MIT License | https://github.com/your-username/signsure
"""

__version__ = "1.0.0"
__author__  = "SignSure Contributors"
__license__ = "MIT"

from .ca          import CertificateAuthority
from .keymgr      import KeyManager
from .signer      import SignatureService
from .verifier    import VerificationService, VerificationResult
from .encryption  import EncryptionService
from .utils       import setup_logging

__all__ = [
    "CertificateAuthority",
    "KeyManager",
    "SignatureService",
    "VerificationService",
    "VerificationResult",
    "EncryptionService",
    "setup_logging",
]
