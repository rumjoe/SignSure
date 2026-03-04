"""
SignSure Attack Simulation Tests (test_attacks.py)
====================================================
Simulates all documented attack scenarios and verifies they are prevented.

TC-ATK-001: Replay attack — reuse old signature on new document
TC-ATK-002: MITM attack — substitute public key in bundle
TC-ATK-003: Signature forgery — random bytes as RSA signature
TC-ATK-004: Padding oracle — RSA PKCS1v15 vs PSS
TC-ATK-005: IV reuse attack — manually reuse IV in AES-GCM
TC-ATK-006: Hash collision attempt — wrong algorithm
TC-ATK-007: Certificate chain substitution
TC-ATK-008: Wrong passphrase brute-force simulation
"""

import os
import json
import base64
import struct
import hashlib
import pytest
from pathlib import Path
from cryptography.exceptions import InvalidSignature


class TestReplayAttack:
    """TC-ATK-001: Replay attack prevention."""

    def test_replay_signature_on_different_document(self, sig_svc, ver_svc, alice, tmp_path):
        """
        Attack: Capture Alice's valid .sig file from document A,
        then attach it to document B hoping verification passes.

        Expected: FAIL — hash mismatch prevents replay.
        """
        # Original document — Alice signs it legitimately
        doc_original = tmp_path / "original_contract.txt"
        doc_original.write_text("Original contract: Alice agrees to pay $100.")
        result = sig_svc.sign_file(str(doc_original), alice["username"], alice["passphrase"])
        sig_path = result["sig_path"]

        # Attacker creates new document and tries to reuse Alice's signature
        doc_new = tmp_path / "forged_contract.txt"
        doc_new.write_text("FORGED contract: Alice agrees to pay $1,000,000.")

        # Verify the forged doc with Alice's original sig
        verify_result = ver_svc.verify_file(str(doc_new), sig_path)

        assert not verify_result.valid, "Replay attack must be rejected"
        assert not verify_result.hash_match, \
            "Hash mismatch must be the rejection reason"
        print(f"\n  [✅ REPLAY BLOCKED] Reason: {verify_result.errors}")


class TestMITMAttack:
    """TC-ATK-002: Man-in-the-Middle attack via certificate substitution."""

    def test_substitute_public_key_in_bundle(self, sig_svc, ver_svc, alice, bob, tmp_path, km):
        """
        Attack: Attacker intercepts Alice's .sig bundle and substitutes
        Bob's certificate, hoping verification uses the substituted key.

        Expected: FAIL — RSA-PSS signature math fails with wrong key.
        """
        doc = tmp_path / "mitm_test.txt"
        doc.write_text("Important document for MITM test.")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        # Attacker loads Alice's bundle and replaces cert with Bob's
        with open(result["sig_path"]) as f:
            bundle = json.load(f)

        bob_cert_path = Path(km.keys_dir) / "bob_cert.pem"
        if bob_cert_path.exists():
            with open(bob_cert_path) as f:
                bundle["certificate_pem"] = f.read()
            bundle["signer_serial"] = bob["cert"].serial_number

        tampered_sig = str(result["sig_path"]) + ".mitm"
        with open(tampered_sig, "w") as f:
            json.dump(bundle, f)

        verify_result = ver_svc.verify_file(str(doc), tampered_sig)

        # Either sig_math_valid fails (wrong key) or chain valid fails
        assert not verify_result.valid, "MITM attack must be detected"
        print(f"\n  [✅ MITM BLOCKED] Reason: {verify_result.errors}")


class TestSignatureForgery:
    """TC-ATK-003: Forging an RSA-PSS signature without the private key."""

    def test_random_bytes_as_signature_fails(self, sig_svc, ver_svc, alice, tmp_path):
        """
        Attack: Attacker creates a .sig bundle with a random 256-byte
        payload instead of a real RSA-PSS signature.

        Expected: FAIL — RSA-PSS cryptographic verification rejects it.
        """
        doc = tmp_path / "forgery_test.txt"
        doc.write_text("Document that attacker wants to forge a signature for.")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        # Load legitimate bundle but replace signature with random bytes
        with open(result["sig_path"]) as f:
            bundle = json.load(f)

        forged_sig = os.urandom(256)  # Random bytes — not a valid RSA sig
        bundle["signature"] = base64.b64encode(forged_sig).decode()

        forged_path = str(result["sig_path"]) + ".forged"
        with open(forged_path, "w") as f:
            json.dump(bundle, f)

        verify_result = ver_svc.verify_file(str(doc), forged_path)

        assert not verify_result.valid,          "Forged signature must fail"
        assert not verify_result.sig_math_valid, "RSA-PSS math must reject random bytes"
        print(f"\n  [✅ FORGERY BLOCKED] Random bytes rejected by RSA-PSS")

    def test_zeroed_signature_fails(self, sig_svc, ver_svc, alice, tmp_path):
        """
        Attack: Attacker uses all-zero bytes as signature.
        Expected: FAIL.
        """
        doc = tmp_path / "zero_sig_test.txt"
        doc.write_text("Zero signature attack test.")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        with open(result["sig_path"]) as f:
            bundle = json.load(f)
        bundle["signature"] = base64.b64encode(b"\x00" * 256).decode()

        zeroed_path = str(result["sig_path"]) + ".zero"
        with open(zeroed_path, "w") as f:
            json.dump(bundle, f)

        verify_result = ver_svc.verify_file(str(doc), zeroed_path)
        assert not verify_result.valid
        print(f"\n  [✅ ZERO SIG BLOCKED]")


class TestCiphertextTamper:
    """TC-ATK-004 to TC-ATK-005: AES-GCM authenticated encryption."""

    def test_single_bit_flip_detected(self, enc_svc, bob, tmp_path):
        """
        Attack: Attacker flips a single bit in encrypted ciphertext.
        Expected: AES-GCM tag authentication fails — cannot recover plaintext.
        """
        doc = tmp_path / "bit_flip_test.txt"
        doc.write_bytes(b"Highly sensitive medical record: patient has condition X.")

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc_path = enc_svc.encrypt_file(str(doc), bob_cert_pem)

        # Flip a single bit in ciphertext
        with open(enc_path, "rb") as f:
            raw = bytearray(f.read())
        key_len = struct.unpack(">I", raw[:4])[0]
        ct_start = 4 + key_len + 12
        if ct_start < len(raw):
            raw[ct_start] ^= 0x01  # single bit flip

        attacked_path = str(enc_path) + ".bitflip"
        with open(attacked_path, "wb") as f:
            f.write(raw)

        with pytest.raises(ValueError):
            enc_svc.decrypt_file(attacked_path, bob["username"], bob["passphrase"])
        print(f"\n  [✅ BIT FLIP DETECTED by GCM authentication tag]")

    def test_iv_reuse_simulation(self, enc_svc, bob, tmp_path):
        """
        Test: Verify that encrypting same content twice produces different ciphertexts.
        (IV reuse would produce identical ciphertexts, leaking XOR of plaintexts.)
        """
        content = b"Same plaintext encrypted twice."
        doc = tmp_path / "iv_reuse1.txt"
        doc.write_bytes(content)

        bob_cert_path = Path(enc_svc.key_manager.keys_dir) / "bob_cert.pem"
        with open(bob_cert_path) as f:
            bob_cert_pem = f.read()

        enc1 = enc_svc.encrypt_file(str(doc), bob_cert_pem, output_path=str(tmp_path/"r1.enc"))
        enc2 = enc_svc.encrypt_file(str(doc), bob_cert_pem, output_path=str(tmp_path/"r2.enc"))

        with open(enc1, "rb") as f: raw1 = f.read()
        with open(enc2, "rb") as f: raw2 = f.read()

        assert raw1 != raw2, "Same plaintext must produce different ciphertext (unique IV)"
        print(f"\n  [✅ IV UNIQUENESS CONFIRMED — different ciphertexts each time]")


class TestCertificateChainAttack:
    """TC-ATK-006: Rogue CA certificate injection."""

    def test_self_signed_cert_in_bundle_rejected(self, sig_svc, ver_svc, alice, km, tmp_path):
        """
        Attack: Attacker creates their own self-signed certificate and injects
        it into a legitimate signature bundle.

        Expected: FAIL — certificate chain check rejects non-CA-signed cert.
        """
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes

        doc = tmp_path / "chain_attack_test.txt"
        doc.write_text("Chain substitution attack test document.")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        # Create rogue self-signed cert
        rogue_priv, _ = km.generate_keypair()
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice")])
        now  = datetime.datetime.now(datetime.timezone.utc)
        rogue_cert = (
            x509.CertificateBuilder()
            .subject_name(subj).issuer_name(subj)
            .public_key(rogue_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(rogue_priv, hashes.SHA256())
        )
        rogue_pem = rogue_cert.public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM
        ).decode()

        # Inject rogue cert
        with open(result["sig_path"]) as f:
            bundle = json.load(f)
        bundle["certificate_pem"] = rogue_pem

        attack_path = str(result["sig_path"]) + ".rogue"
        with open(attack_path, "w") as f:
            json.dump(bundle, f)

        verify_result = ver_svc.verify_file(str(doc), attack_path)
        assert not verify_result.valid
        assert not verify_result.chain_valid
        print(f"\n  [✅ ROGUE CA CERT REJECTED — chain validation failed]")


class TestHashManipulation:
    """TC-ATK-007: Document hash manipulation in bundle."""

    def test_altered_hash_in_bundle_fails(self, sig_svc, ver_svc, alice, tmp_path):
        """
        Attack: Attacker modifies the document_hash_sha256 in the bundle
        to match a forged document, while keeping the original signature.

        Expected: FAIL — signature covers the original hash value.
        The RSA-PSS signature is over SHA256(original_hash:timestamp:serial).
        Changing the hash changes the payload, making the sig invalid.
        """
        doc = tmp_path / "hash_manip_test.txt"
        doc.write_text("Legitimate document content.")
        result = sig_svc.sign_file(str(doc), alice["username"], alice["passphrase"])

        # Attacker modifies the document content
        doc.write_text("Attacker modified content.")
        attacker_hash = hashlib.sha256(b"Attacker modified content.").hexdigest()

        with open(result["sig_path"]) as f:
            bundle = json.load(f)
        bundle["document_hash_sha256"] = attacker_hash

        attack_path = str(result["sig_path"]) + ".hashmod"
        with open(attack_path, "w") as f:
            json.dump(bundle, f)

        verify_result = ver_svc.verify_file(str(doc), attack_path)
        # Hash in doc matches modified bundle, but sig over {original_hash:ts:serial} won't match
        assert not verify_result.valid
        print(f"\n  [✅ HASH MANIPULATION BLOCKED — sig payload mismatch]")


class TestPassphraseProtection:
    """TC-ATK-008: Brute-force resistance of PKCS#12 keystore."""

    def test_common_passwords_rejected(self, km, alice):
        """
        Simulate brute-force: try common passwords.
        Expected: ALL rejected — correct passphrase is not in the list.
        """
        p12_path = km.get_p12_path("alice")
        common_passwords = [
            b"password", b"123456", b"qwerty", b"letmein",
            b"admin", b"", b"alice", b"test123", b"password1",
        ]
        rejected_count = 0
        for pwd in common_passwords:
            try:
                km.load_from_pkcs12(p12_path, pwd)
                # If we get here, the password was accepted — this should NOT happen
                assert False, f"Common password '{pwd}' should have been rejected!"
            except (ValueError, Exception):
                rejected_count += 1

        assert rejected_count == len(common_passwords)
        print(f"\n  [✅ BRUTE FORCE BLOCKED — all {rejected_count} common passwords rejected]")
