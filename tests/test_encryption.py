"""
Tests for Hybrid Encryption Service (encryption.py)
TC-ENC-001 to TC-ENC-009
"""

import os
import struct
import pytest
from pathlib import Path


class TestEncryptDecryptRoundtrip:
    """TC-ENC-001 to TC-ENC-003: Basic roundtrip correctness."""

    def test_encrypt_decrypt_text_file(self, enc_svc, alice, bob, tmp_path):
        """TC-ENC-001: Encrypt for Bob, Bob decrypts correctly."""
        doc = tmp_path / "secret.txt"
        original = b"This is a highly confidential message for Bob only."
        doc.write_bytes(original)

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc_path = enc_svc.encrypt_file(str(doc), bob_cert_pem)
        dec_path = enc_svc.decrypt_file(enc_path, bob["username"], bob["passphrase"])

        assert Path(dec_path).read_bytes() == original

    def test_encrypt_decrypt_binary_file(self, enc_svc, alice, bob, sample_pdf_like_file):
        """TC-ENC-002: Works on binary files."""
        original = sample_pdf_like_file.read_bytes()

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc_path = enc_svc.encrypt_file(str(sample_pdf_like_file), bob_cert_pem)
        dec_path = enc_svc.decrypt_file(enc_path, bob["username"], bob["passphrase"])

        assert Path(dec_path).read_bytes() == original

    def test_message_roundtrip(self, enc_svc, bob):
        """TC-ENC-003: encrypt_message / decrypt_message roundtrip."""
        original = "Hello Bob! This is a secret message."
        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        bundle = enc_svc.encrypt_message(original, bob_cert_pem)
        recovered = enc_svc.decrypt_message(bundle, bob["username"], bob["passphrase"])
        assert recovered == original


class TestWrongKeyRejection:
    """TC-ENC-004 to TC-ENC-005: Decryption with wrong key fails."""

    def test_alice_cannot_decrypt_bobs_message(self, enc_svc, alice, bob, tmp_path):
        """TC-ENC-004: File encrypted for Bob cannot be decrypted by Alice."""
        doc = tmp_path / "for_bob_only.txt"
        doc.write_bytes(b"Eyes of Bob only.")

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc_path = enc_svc.encrypt_file(str(doc), bob_cert_pem)

        with pytest.raises(ValueError, match="RSA-OAEP decryption failed"):
            enc_svc.decrypt_file(enc_path, alice["username"], alice["passphrase"])

    def test_wrong_passphrase_prevents_decrypt(self, enc_svc, bob, tmp_path):
        """TC-ENC-005: Wrong keystore passphrase prevents decryption."""
        doc = tmp_path / "wrong_pass_test.txt"
        doc.write_bytes(b"Secret content.")

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc_path = enc_svc.encrypt_file(str(doc), bob_cert_pem)

        with pytest.raises((ValueError, Exception)):
            enc_svc.decrypt_file(enc_path, bob["username"], b"WrongPassphrase!")


class TestTamperDetection:
    """TC-ENC-006 to TC-ENC-008: GCM tag catches ciphertext tampering."""

    def test_ciphertext_tamper_detected(self, enc_svc, bob, tmp_path):
        """TC-ENC-006: Single byte flip in ciphertext causes GCM auth failure."""
        doc = tmp_path / "tamper_enc_test.txt"
        doc.write_bytes(b"Tamper detection test content for AES-GCM.")

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc_path = enc_svc.encrypt_file(str(doc), bob_cert_pem)

        # Flip a byte in the ciphertext region
        with open(enc_path, "rb") as f:
            raw = bytearray(f.read())

        # Parse to find ciphertext offset
        key_len = struct.unpack(">I", raw[:4])[0]
        ciphertext_offset = 4 + key_len + 12  # after header+key+IV
        if ciphertext_offset + 10 < len(raw):
            raw[ciphertext_offset + 5] ^= 0xFF  # flip a byte

        tampered_path = str(enc_path) + ".tampered"
        with open(tampered_path, "wb") as f:
            f.write(raw)

        with pytest.raises(ValueError, match="tampered|GCM|authentication"):
            enc_svc.decrypt_file(tampered_path, bob["username"], bob["passphrase"])

    def test_gcm_tag_tamper_detected(self, enc_svc, bob, tmp_path):
        """TC-ENC-007: Flipping GCM authentication tag causes failure."""
        doc = tmp_path / "gcm_tag_test.txt"
        doc.write_bytes(b"GCM tag integrity test.")

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc_path = enc_svc.encrypt_file(str(doc), bob_cert_pem)

        # Flip the last 16 bytes (GCM tag)
        with open(enc_path, "rb") as f:
            raw = bytearray(f.read())
        for i in range(-16, 0):
            raw[i] ^= 0xAA

        tampered_path = str(enc_path) + ".tagflip"
        with open(tampered_path, "wb") as f:
            f.write(raw)

        with pytest.raises(ValueError):
            enc_svc.decrypt_file(tampered_path, bob["username"], bob["passphrase"])

    def test_truncated_file_rejected(self, enc_svc, bob, tmp_path):
        """TC-ENC-008: Truncated .enc file fails gracefully."""
        doc = tmp_path / "truncate_test.txt"
        doc.write_bytes(b"Truncation test content here.")

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc_path = enc_svc.encrypt_file(str(doc), bob_cert_pem)

        with open(enc_path, "rb") as f:
            data = f.read()

        truncated_path = str(enc_path) + ".trunc"
        with open(truncated_path, "wb") as f:
            f.write(data[:len(data)//2])

        with pytest.raises((ValueError, Exception)):
            enc_svc.decrypt_file(truncated_path, bob["username"], bob["passphrase"])


class TestIVUniqueness:
    """TC-ENC-009: Each encryption produces a unique IV."""

    def test_different_ivs_each_encryption(self, enc_svc, bob, tmp_path):
        """TC-ENC-009: os.urandom(12) ensures no IV reuse."""
        doc = tmp_path / "iv_test.txt"
        doc.write_bytes(b"Same content encrypted twice.")

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        ivs = []
        for i in range(5):
            enc_path = enc_svc.encrypt_file(str(doc), bob_cert_pem,
                                             output_path=str(tmp_path / f"iv_test_{i}.enc"))
            with open(enc_path, "rb") as f:
                raw = f.read()
            key_len = struct.unpack(">I", raw[:4])[0]
            iv = raw[4 + key_len: 4 + key_len + 12]
            ivs.append(iv)

        # All IVs must be unique
        assert len(set(ivs)) == 5, "Each encryption must use a unique 96-bit IV"
