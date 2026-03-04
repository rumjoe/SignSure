"""
Tests for Signature Verification Service (verifier.py)
TC-VER-001 to TC-VER-010
"""

import json
import base64
import pytest
from pathlib import Path


class TestValidVerification:
    """TC-VER-001 to TC-VER-003: Valid signatures pass all checks."""

    def test_valid_signature_passes(self, sig_svc, ver_svc, alice, tmp_path):
        """TC-VER-001: Happy path — valid sig verifies correctly."""
        doc = tmp_path / "valid_test.txt"
        doc.write_text("Valid document content for verification test.")

        res    = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])
        result = ver_svc.verify_file(str(doc), res["sig_path"])

        assert result.valid,          "Valid signature must pass"
        assert result.chain_valid,    "Certificate chain must be valid"
        assert result.not_expired,    "Certificate must not be expired"
        assert result.not_revoked,    "Certificate must not be revoked"
        assert result.hash_match,     "Document hash must match"
        assert result.sig_math_valid, "RSA-PSS math must be valid"
        assert result.signer_name == "alice"

    def test_verify_returns_correct_signer(self, sig_svc, ver_svc, bob, tmp_path):
        """TC-VER-002: Verifier correctly identifies the signer."""
        doc = tmp_path / "bob_signed.txt"
        doc.write_text("Bob signed this document.")
        res    = sig_svc.sign_file(str(doc), bob["username"], bob["passphrase"])
        result = ver_svc.verify_file(str(doc), res["sig_path"])
        assert result.signer_name == "bob"

    def test_result_contains_timestamp(self, sig_svc, ver_svc, alice, tmp_path):
        """TC-VER-003: VerificationResult includes signing timestamp."""
        doc = tmp_path / "ts_verify_test.txt"
        doc.write_text("Timestamp verification test.")
        res    = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])
        result = ver_svc.verify_file(str(doc), res["sig_path"])
        assert result.signed_at, "signed_at must be present"
        assert "T" in result.signed_at


class TestTamperDetection:
    """TC-VER-004 to TC-VER-006: Tampered documents are rejected."""

    def test_tampered_document_fails(self, sig_svc, ver_svc, alice, tmp_path):
        """TC-VER-004: Any byte change in document invalidates signature."""
        doc = tmp_path / "tamper_test.txt"
        doc.write_text("Original content — do not change.")
        res = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        # Tamper with the document
        doc.write_text("Original content — has been CHANGED!")
        result = ver_svc.verify_file(str(doc), res["sig_path"])

        assert not result.valid
        assert not result.hash_match
        assert any("tamper" in e.lower() or "mismatch" in e.lower() for e in result.errors)

    def test_tampered_sig_file_fails(self, sig_svc, ver_svc, alice, tmp_path):
        """TC-VER-005: Modified .sig bundle fails verification."""
        doc = tmp_path / "sig_tamper_test.txt"
        doc.write_text("Document with tampered signature file.")
        res = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        # Corrupt the base64 signature
        with open(res["sig_path"]) as f:
            bundle = json.load(f)
        bundle["signature"] = base64.b64encode(b"FORGED" * 50).decode()
        with open(res["sig_path"], "w") as f:
            json.dump(bundle, f)

        result = ver_svc.verify_file(str(doc), res["sig_path"])
        assert not result.valid
        assert not result.sig_math_valid

    def test_wrong_document_wrong_sig_fails(self, sig_svc, ver_svc, alice, tmp_path):
        """TC-VER-006: Sig for doc A doesn't validate doc B."""
        doc_a = tmp_path / "doc_a.txt"
        doc_b = tmp_path / "doc_b.txt"
        doc_a.write_text("Document A content.")
        doc_b.write_text("Document B content — completely different.")

        res_a = sig_svc.sign_file(str(doc_a), alice["username"], alice["passphrase"])

        # Try to verify doc_b with doc_a's signature
        result = ver_svc.verify_file(str(doc_b), res_a["sig_path"])
        assert not result.valid
        assert not result.hash_match


class TestCertificateChecks:
    """TC-VER-007 to TC-VER-009: Certificate-level checks."""

    def test_wrong_user_cert_fails(self, sig_svc, ver_svc, alice, bob, tmp_path):
        """TC-VER-007: Alice's sig cannot be verified as Bob's."""
        doc = tmp_path / "cross_verify_test.txt"
        doc.write_text("Cross-user verification test content.")
        res_alice = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        # Modify the bundle to contain Bob's certificate
        with open(res_alice["sig_path"]) as f:
            bundle = json.load(f)

        from cryptography import x509
        from signsure.keymgr import KeyManager
        bob_cert_path = Path(ver_svc.ca.ca_dir).parent / "keys" / "bob_cert.pem"
        if bob_cert_path.exists():
            with open(bob_cert_path) as f:
                bundle["certificate_pem"] = f.read()
            with open(res_alice["sig_path"], "w") as f:
                json.dump(bundle, f)

            result = ver_svc.verify_file(str(doc), res_alice["sig_path"])
            assert not result.valid

    def test_revoked_cert_fails_verify(self, sig_svc, ver_svc, ca, carol, tmp_path):
        """TC-VER-008: Signature from revoked certificate is rejected."""
        doc = tmp_path / "revoked_test.txt"
        doc.write_text("Document signed by Carol (who will be revoked).")
        res = sig_svc.sign_file(str(doc), carol["username"], carol["passphrase"])

        # Carol's cert is already revoked in test_ca.py
        result = ver_svc.verify_file(str(doc), res["sig_path"])
        assert not result.valid
        assert not result.not_revoked

    def test_missing_doc_file_handled(self, sig_svc, ver_svc, alice, tmp_path):
        """TC-VER-009: Missing document file is handled gracefully."""
        doc = tmp_path / "to_be_deleted.txt"
        doc.write_text("Will be deleted before verify.")
        res = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        doc.unlink()  # Delete the file

        result = ver_svc.verify_file(str(doc), res["sig_path"])
        assert not result.valid
        assert any("not found" in e.lower() for e in result.errors)


class TestMultiUserVerification:
    """TC-VER-010: Multiple users can sign same doc independently."""

    def test_alice_and_bob_both_valid(self, sig_svc, ver_svc, alice, bob, tmp_path):
        doc = tmp_path / "multi_sign.txt"
        doc.write_text("Both Alice and Bob need to sign this.")

        res_a = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])
        res_b = sig_svc.sign_file(str(doc), bob["username"],   bob["passphrase"])

        result_a = ver_svc.verify_file(str(doc), res_a["sig_path"])
        result_b = ver_svc.verify_file(str(doc), res_b["sig_path"])

        assert result_a.valid, "Alice's signature must be valid"
        assert result_b.valid, "Bob's signature must be valid"
        assert result_a.signer_name == "alice"
        assert result_b.signer_name == "bob"
