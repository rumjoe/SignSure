"""
SignSure Use Case 2: Academic Transcript Authentication
========================================================
University signs transcripts; employers verify without
contacting the university. Tampered transcripts are caught.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import tempfile
from signsure.ca       import CertificateAuthority
from signsure.keymgr   import KeyManager
from signsure.signer   import SignatureService
from signsure.verifier import VerificationService

def run():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for s in ["ca","keys","signatures"]: (root/s).mkdir()

        print("\n=== USE CASE 2: Academic Transcript Authentication ===\n")

        ca  = CertificateAuthority(str(root/"ca"))
        km  = KeyManager(str(root/"keys"))
        ca.generate_ca("UniPKI-CA", org="University PKI", country="NP")

        # Register registrar
        priv, pub = km.generate_keypair()
        cert = ca.issue_certificate("registrar", pub, email="registrar@university.edu")
        km.save_to_pkcs12("registrar", priv, cert, b"Registrar#2026!", ca_cert=ca.ca_cert)
        print("✅ University Registrar registered")

        # Create transcript
        transcript = root/"transcript_alice.txt"
        transcript.write_text(
            "ACADEMIC TRANSCRIPT\n"
            "===================\n"
            "Student: Alice Johnson | ID: 2022-CS-001\n"
            "Module: Cryptography   — A\n"
            "Module: Algorithms     — A+\n"
            "Module: Networks       — B+\n"
            "GPA: 3.92 / 4.00\n"
            "Awarded: BSc Computer Science (First Class Hons)\n"
        )
        print(f"📄 Transcript created: {transcript.name}")

        sig_svc = SignatureService(km, str(root/"signatures"))
        res = sig_svc.sign_file(str(transcript), "registrar", b"Registrar#2026!")
        print(f"✍️  Registrar signed: {Path(res['sig_path']).name}")

        ver = VerificationService(ca)

        # Employer verifies
        result = ver.verify_file(str(transcript), res["sig_path"])
        print(f"\n🏢 Employer verifies transcript: {'✅ GENUINE' if result.valid else '❌ INVALID'}")

        # ATTACK: Student modifies grades
        print("\n⚔️  ATTACK: Student changes GPA from 3.92 to 4.00 and an 'A' to 'A+'")
        transcript.write_text(
            "ACADEMIC TRANSCRIPT\n"
            "===================\n"
            "Student: Alice Johnson | ID: 2022-CS-001\n"
            "Module: Cryptography   — A+\n"
            "Module: Algorithms     — A+\n"
            "Module: Networks       — A\n"
            "GPA: 4.00 / 4.00\n"
            "Awarded: BSc Computer Science (First Class Hons)\n"
        )
        result2 = ver.verify_file(str(transcript), res["sig_path"])
        print(f"🏢 Employer re-verifies tampered transcript: {'✅ VALID' if result2.valid else '❌ TAMPERED — REJECTED'}")
        if not result2.valid:
            print(f"   Reason: {', '.join(result2.errors)}")

        print("\n=== USE CASE 2 COMPLETE ===")

if __name__ == "__main__":
    run()
