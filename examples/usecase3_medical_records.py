"""
SignSure Use Case 3: Secure Medical Record Exchange
=====================================================
Doctor signs + encrypts a medical record for a clinic.
Encryption ensures confidentiality; signature ensures authenticity.
Ciphertext tamper detected by AES-GCM.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import tempfile
from signsure.ca          import CertificateAuthority
from signsure.keymgr      import KeyManager
from signsure.signer      import SignatureService
from signsure.verifier    import VerificationService
from signsure.encryption  import EncryptionService

def run():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for s in ["ca","keys","signatures","encrypted"]: (root/s).mkdir()

        print("\n=== USE CASE 3: Secure Medical Record Exchange ===\n")

        ca  = CertificateAuthority(str(root/"ca"))
        km  = KeyManager(str(root/"keys"))
        ca.generate_ca("MedPKI-CA", org="Medical PKI", country="NP")

        for name, pwd in [("dr_patel", b"DrPatel#2026!"), ("city_clinic", b"Clinic#2026!")]:
            priv, pub = km.generate_keypair()
            cert = ca.issue_certificate(name, pub)
            km.save_to_pkcs12(name, priv, cert, pwd, ca_cert=ca.ca_cert)
            with open(root/"keys"/f"{name}_cert.pem","w") as f:
                f.write(km.export_cert_pem(cert))
            print(f"✅ Registered: {name}")

        # Create medical record
        record = root/"patient_record.txt"
        record.write_text(
            "CONFIDENTIAL MEDICAL RECORD\n"
            "============================\n"
            "Patient: John Doe | DOB: 1985-05-15\n"
            "Diagnosis: Type 2 Diabetes (E11.9)\n"
            "Medication: Metformin 500mg twice daily\n"
            "Referring physician: Dr. A. Patel\n"
            "Date: 2026-02-23\n"
        )
        print(f"📄 Medical record created")

        sig_svc = SignatureService(km, str(root/"signatures"))
        enc_svc = EncryptionService(km, str(root/"encrypted"))
        ver     = VerificationService(ca)

        # Step 1: Doctor signs the record
        res = sig_svc.sign_file(str(record), "dr_patel", b"DrPatel#2026!")
        print(f"\n✍️  Dr. Patel signed the record")

        # Step 2: Doctor encrypts for clinic (hybrid AES-256-GCM + RSA-OAEP)
        with open(root/"keys"/"city_clinic_cert.pem") as f:
            clinic_cert_pem = f.read()
        enc_path = enc_svc.encrypt_file(str(record), clinic_cert_pem)
        print(f"🔒 Record encrypted for City Clinic (AES-256-GCM)")

        # Step 3: Clinic decrypts
        dec_path = enc_svc.decrypt_file(enc_path, "city_clinic", b"Clinic#2026!")
        print(f"🔓 City Clinic decrypted the record")

        # Step 4: Clinic verifies doctor's signature
        result = ver.verify_file(dec_path, res["sig_path"])
        print(f"\n🔍 Clinic verifies Dr. Patel's signature: {'✅ AUTHENTIC' if result.valid else '❌ INVALID'}")
        print(f"   Signer: {result.signer_name} | Chain: {'✅' if result.chain_valid else '❌'}")

        # ATTACK: MITM modifies ciphertext in transit
        print("\n⚔️  ATTACK: Attacker intercepts encrypted file and flips a byte")
        import struct
        with open(enc_path, "rb") as f:
            raw = bytearray(f.read())
        key_len = struct.unpack(">I", raw[:4])[0]
        ct_start = 4 + key_len + 12
        if ct_start < len(raw):
            raw[ct_start] ^= 0xFF

        tampered_path = str(enc_path) + ".mitm"
        with open(tampered_path, "wb") as f:
            f.write(raw)

        try:
            enc_svc.decrypt_file(tampered_path, "city_clinic", b"Clinic#2026!")
            print("❌ ERROR: Tampered data was not detected!")
        except ValueError as e:
            print(f"✅ TAMPER DETECTED: {e}")

        print("\n=== USE CASE 3 COMPLETE ===")

if __name__ == "__main__":
    run()
