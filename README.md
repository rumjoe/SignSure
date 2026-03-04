# SignSure — Open-Source PKI Document Security Platform

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org)
[![Tests](https://github.com/your-username/signsure/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/signsure/actions)

> **ST6051CEM Practical Cryptography Coursework** — Softwarica College / Coventry University

SignSure is a fully open-source PKI-based document signing and verification system implementing RSA-PSS digital signatures, AES-256-GCM hybrid encryption, X.509 certificate management, and certificate revocation.

---

## ✨ Features

| Feature | Algorithm | Standard |
|---------|-----------|----------|
| Digital Signatures | RSA-PSS + SHA-256 | RFC 8017 §8.1 |
| Hybrid Encryption | AES-256-GCM + RSA-OAEP | NIST SP 800-38D |
| Certificates | X.509 v3 | RFC 5280 |
| Key Storage | PKCS#12 (.p12) | RFC 7292 |
| Revocation | CRL (X.509) | RFC 5280 §5 |
| Key Derivation | PBKDF2-HMAC-SHA256 | RFC 8018 |

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/signsure.git
cd signsure

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## 🖥️ Web Interface (Recommended)

```bash
python run.py
# Open http://127.0.0.1:5000 in your browser
```

The web interface provides a modern dark-themed UI for all operations:
- Initialise the Root CA
- Register users (generates RSA-2048 keys + X.509 cert)
- Sign and download `.sig` files
- Verify signatures with detailed status
- Encrypt files (hybrid AES-256-GCM)
- Decrypt files
- Revoke certificates and update CRL

---

## ⚡ Quick Start (API)

```python
from signsure import CertificateAuthority, KeyManager, SignatureService, VerificationService

# 1 — Initialise CA
ca = CertificateAuthority("./data/ca")
ca.generate_ca("MyCA", org="My Org", country="NP")

# 2 — Register a user
km   = KeyManager("./data/keys")
priv, pub = km.generate_keypair()
cert = ca.issue_certificate("alice", pub, email="alice@example.com")
km.save_to_pkcs12("alice", priv, cert, b"StrongPassphrase!", ca_cert=ca.ca_cert)

# 3 — Sign a document
sig_svc = SignatureService(km, "./data/signatures")
result  = sig_svc.sign_file("document.pdf", "alice", b"StrongPassphrase!")
print("Signature saved:", result["sig_path"])

# 4 — Verify the signature
ver    = VerificationService(ca)
status = ver.verify_file("document.pdf", result["sig_path"])
print("Valid:", status.valid, "| Signer:", status.signer_name)
```

---

## 🧪 Running Tests

```bash
# Run all tests with coverage report
pytest tests/ -v --cov=signsure --cov-report=term-missing

# Run specific test categories
pytest tests/test_ca.py         -v    # CA tests
pytest tests/test_signer.py     -v    # Signing tests
pytest tests/test_verifier.py   -v    # Verification tests
pytest tests/test_encryption.py -v    # Encryption tests
pytest tests/test_attacks.py    -v    # Attack simulation tests
```

---

## 📁 Project Structure

```
signsure/
├── signsure/           # Core cryptographic library
│   ├── ca.py           # Certificate Authority
│   ├── keymgr.py       # PKCS#12 Key Manager
│   ├── signer.py       # RSA-PSS Digital Signatures
│   ├── verifier.py     # Signature Verification
│   ├── encryption.py   # Hybrid AES-GCM + RSA-OAEP
│   └── utils.py        # Utilities
├── app/                # Flask Web Application
│   ├── routes.py       # API endpoints
│   └── templates/      # HTML UI
├── tests/              # Full test suite (45+ test cases)
│   ├── conftest.py     # Shared fixtures
│   ├── test_ca.py      # CA tests
│   ├── test_keymgr.py  # Key manager tests
│   ├── test_signer.py  # Signing tests
│   ├── test_verifier.py# Verification tests
│   ├── test_encryption.py # Encryption tests
│   └── test_attacks.py # Attack simulation tests
├── examples/           # Real-world use case demos
│   ├── usecase1_legal_signing.py
│   ├── usecase2_transcript_auth.py
│   └── usecase3_medical_records.py
├── run.py              # Web server entry point
└── requirements.txt
```

---

## 🛡️ Attacks Prevented

| Attack | Countermeasure |
|--------|---------------|
| Signature Forgery | RSA-PSS: EUF-CMA secure, infeasible without 2048-bit private key |
| Document Tampering | SHA-256 binding: any change invalidates the signature |
| Replay Attack | Signature covers SHA256(doc_hash \|\| timestamp \|\| serial) |
| MITM | X.509 certificate chain validates signer identity via CA |
| Private Key Theft | PKCS#12 + PBKDF2 (600k iterations) — brute-force impractical |
| Ciphertext Tamper | AES-GCM 128-bit authentication tag detects any modification |
| IV Reuse | os.urandom(12) — cryptographically random IV per encryption |
| Padding Oracle | RSA-OAEP + RSA-PSS — immune to Bleichenbacher-style attacks |
| Revoked Cert Use | CRL checked on every verification |

---

## 🏗️ Extending SignSure

### Adding a new file type
The system is format-agnostic. Any file can be signed and verified.

### Integrating as a library
```python
from signsure import SignatureService, VerificationService
# Use directly in your own application
```

### Adding OCSP support
Extend `VerificationService.verify_file()` to call an OCSP endpoint instead of (or in addition to) the local CRL.

---

## 📖 Use Cases

1. **Legal Contract Signing** — Parties sign contracts; non-repudiation is provable
2. **Academic Transcript Authentication** — University signs; employers verify without contacting university
3. **Medical Record Exchange** — Doctor signs + encrypts; clinic verifies authenticity and decrypts securely

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions welcome!

---

## 📚 References

- NIST SP 800-131A — Key Sizes
- RFC 8017 — RSA Cryptography (PKCS#1 v2.2)
- RFC 5280 — X.509 Certificate Profile
- NIST SP 800-38D — AES-GCM
- [Python cryptography docs](https://cryptography.io/en/latest/)
