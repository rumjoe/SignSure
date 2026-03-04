"""
Tests for Digital Signature Service (signer.py)
TC-SIG-001 to TC-SIG-008
"""

import json
import base64
import pytest
from pathlib import Path


class TestSignatureCreation:
    """TC-SIG-001 to TC-SIG-004: Signing produces correct .sig bundles."""

    def test_sign_text_file(self, sig_svc, alice, sample_text_file):
        """TC-SIG-001: Successfully sign a text file."""
        result = sig_svc.sign_file(
            file_path=str(sample_text_file),
            username=alice["username"],
            passphrase=alice["passphrase"],
        )
        assert result["sig_path"]
        assert Path(result["sig_path"]).exists()
        assert len(result["document_hash"]) == 64  # SHA-256 hex

    def test_sig_bundle_fields(self, sig_svc, alice, sample_text_file, tmp_path):
        """TC-SIG-002: .sig bundle contains all required fields."""
        doc = tmp_path / "bundle_test.txt"
        doc.write_text("bundle test content")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        with open(result["sig_path"]) as f:
            bundle = json.load(f)

        required = ["signsure_version", "document_name", "document_hash_sha256",
                    "timestamp", "signer_serial", "signature", "certificate_pem",
                    "algorithm", "pss_salt_length"]
        for field in required:
            assert field in bundle, f"Missing field: {field}"

    def test_algorithm_is_rsa_pss(self, sig_svc, alice, tmp_path):
        """TC-SIG-003: Algorithm field must be RSA-PSS-SHA256."""
        doc = tmp_path / "algo_test.txt"
        doc.write_text("algorithm test")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])
        with open(result["sig_path"]) as f:
            bundle = json.load(f)
        assert bundle["algorithm"] == "RSA-PSS-SHA256"
        assert bundle["pss_salt_length"] == 32

    def test_signature_is_base64(self, sig_svc, alice, tmp_path):
        """TC-SIG-004: Signature is valid Base64."""
        doc = tmp_path / "b64_test.txt"
        doc.write_text("base64 test")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])
        with open(result["sig_path"]) as f:
            bundle = json.load(f)
        # Should not raise
        raw = base64.b64decode(bundle["signature"])
        assert len(raw) > 0

    def test_timestamp_in_bundle(self, sig_svc, alice, tmp_path):
        """TC-SIG-005: Timestamp is present and ISO-8601."""
        doc = tmp_path / "ts_test.txt"
        doc.write_text("timestamp test")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])
        with open(result["sig_path"]) as f:
            bundle = json.load(f)
        ts = bundle["timestamp"]
        assert "T" in ts, "Timestamp must be ISO-8601"
        assert "Z" in ts or "+" in ts, "Timestamp must include timezone"

    def test_sign_binary_file(self, sig_svc, alice, sample_pdf_like_file, tmp_path):
        """TC-SIG-006: Can sign binary (non-text) files."""
        result = sig_svc.sign_file(
            str(sample_pdf_like_file), alice["username"], alice["passphrase"]
        )
        assert Path(result["sig_path"]).exists()

    def test_nonexistent_file_raises(self, sig_svc, alice):
        """TC-SIG-007: Missing file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            sig_svc.sign_file("/tmp/ghost_file_xyz.txt", alice["username"], alice["passphrase"])

    def test_different_users_produce_different_sigs(self, sig_svc, alice, bob, tmp_path):
        """TC-SIG-008: Two users signing the same doc produce different signatures."""
        doc = tmp_path / "multiuser_test.txt"
        doc.write_text("multi-user signing test content")

        res_a = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])
        res_b = sig_svc.sign_file(str(doc), bob["username"],   bob["passphrase"])

        with open(res_a["sig_path"]) as f:
            bundle_a = json.load(f)
        with open(res_b["sig_path"]) as f:
            bundle_b = json.load(f)

        # Same document hash (same content)
        assert bundle_a["document_hash_sha256"] == bundle_b["document_hash_sha256"]

        # But different signatures (different keys)
        assert bundle_a["signature"] != bundle_b["signature"]
        assert bundle_a["signer_serial"] != bundle_b["signer_serial"]
