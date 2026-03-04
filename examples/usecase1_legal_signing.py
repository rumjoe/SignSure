"""
SignSure Use Case 1: Legal Contract Signing
===========================================
Demonstrates signing and verification in a legal context.
Alice (law firm) and Bob (client) both sign a contract.
A verifier confirms authenticity without contacting the signers.
"""

import sys, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import tempfile
from signsure.ca          import CertificateAuthority
from signsure.keymgr      import KeyManager
from signsure.signer      import SignatureService
from signsure.verifier    import VerificationService
from signsure.utils       import setup_logging

setup_logging()

def run():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for sub in ["ca","keys","signatures"]:
            (root/sub).mkdir()

        # 1 — Initialise CA
        print("\n=== USE CASE 1: Legal Contract Signing ===\n")
        ca  = CertificateAuthority(str(root/"ca"))
        km  = KeyManager(str(root/"keys"))
        ca.generate_ca("LegalSure-CA", org="Legal PKI", country="NP")
        print("✅ Root CA initialised")

        # 2 — Register users
        for name, pwd in [("alice_lawfirm", b"AliceLaw#2026"), ("bob_client", b"BobClient#2026")]:
            priv, pub = km.generate_keypair()
            cert = ca.issue_certificate(name, pub, email=f"{name}@example.com")
            km.save_to_pkcs12(name, priv, cert, pwd, ca_cert=ca.ca_cert)
            with open(root/"keys"/f"{name}_cert.pem","w") as f:
                f.write(km.export_cert_pem(cert))
            print(f"✅ User '{name}' registered (serial {cert.serial_number})")

        # 3 — Create contract
        contract = root/"contract.txt"
        contract.write_text(
            "LEGAL CONTRACT\n"
            "==============\n"
            "Client (Bob) agrees to pay Law Firm (Alice) $5,000 for legal services.\n"
            "Terms: Payment due within 30 days of service completion.\n"
            "Date: 2026-02-23\n"
        )
        print(f"\n📄 Contract created: {contract.name}")

        # 4 — Both parties sign
        sig_svc = SignatureService(km, str(root/"signatures"))
        res_alice = sig_svc.sign_file(str(contract), "alice_lawfirm", b"AliceLaw#2026")
        res_bob   = sig_svc.sign_file(str(contract), "bob_client",    b"BobClient#2026")
        print(f"✍️  Alice signed → {Path(res_alice['sig_path']).name}")
        print(f"✍️  Bob   signed → {Path(res_bob['sig_path']).name}")

        # 5 — Third-party verification
        ver = VerificationService(ca)
        for who, path in [("Alice", res_alice["sig_path"]), ("Bob", res_bob["sig_path"])]:
            result = ver.verify_file(str(contract), path)
            status = "✅ VALID" if result.valid else "❌ INVALID"
            print(f"\n🔍 Verifying {who}'s signature: {status}")
            print(f"   Signer: {result.signer_name} | Time: {result.signed_at}")

        # 6 — Attack: client denies signing (non-repudiation test)
        print("\n⚔️  ATTACK: Bob claims he never signed the contract.")
        result = ver.verify_file(str(contract), res_bob["sig_path"])
        if result.valid:
            print("✅ NON-REPUDIATION PROOF: Signature is mathematically valid.")
            print("   Bob's private key (only Bob has it) produced this signature.")

        print("\n=== USE CASE 1 COMPLETE ===")

if __name__ == "__main__":
    run()
