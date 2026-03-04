#!/usr/bin/env python3
"""
SignSure Debug Script - Diagnose Signature Verification Issues

This script helps debug why signature verification is failing.

Usage:
  python debug_sig.py --sig-file <path> --doc-file <path> --ca-dir <path>
  python debug_sig.py --analyze-all  # Analyze all signatures in data directory
"""

import sys
import json
import base64
import hashlib
import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from signsure.ca import CertificateAuthority
from signsure.keymgr import KeyManager
from signsure.verifier import VerificationService


def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")


def print_section(text):
    print(f"\n--- {text} ---")


def analyze_sig_file(sig_path):
    """Load and analyze a signature bundle file."""
    print_section(f"Loading signature bundle: {sig_path}")
    
    with open(sig_path) as f:
        bundle = json.load(f)
    
    print(f"SignSure Version: {bundle.get('signsure_version', 'N/A')}")
    print(f"Document Name: {bundle.get('document_name', 'N/A')}")
    print(f"Document Hash (SHA-256): {bundle.get('document_hash_sha256', 'N/A')}")
    print(f"Timestamp: {bundle.get('timestamp', 'N/A')}")
    print(f"Signer Serial: {bundle.get('signer_serial', 'N/A')}")
    print(f"Algorithm: {bundle.get('algorithm', 'N/A')}")
    print(f"PSS Salt Length: {bundle.get('pss_salt_length', 'N/A')}")
    
    # Load and analyze certificate
    cert_pem = bundle.get('certificate_pem', '')
    if cert_pem:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        print_section("Certificate Details (from signature bundle)")
        print(f"  Subject: {cert.subject.rfc4514_string()}")
        print(f"  Issuer: {cert.issuer.rfc4514_string()}")
        print(f"  Serial Number: {cert.serial_number}")
        print(f"  Not Valid Before: {cert.not_valid_before_utc}")
        print(f"  Not Valid After: {cert.not_valid_after_utc}")
        
        # Check expiry
        now = datetime.datetime.now(datetime.timezone.utc)
        is_expired = now > cert.not_valid_after_utc or now < cert.not_valid_before_utc
        print(f"  Is Expired (at {now}): {is_expired}")
        
        # Get subject CN
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                print(f"  Signer CN: {attr.value}")
                break
    
    return bundle, cert


def analyze_ca(ca_dir):
    """Analyze the CA configuration."""
    print_section(f"Analyzing CA at: {ca_dir}")
    
    ca_path = Path(ca_dir)
    ca_cert_path = ca_path / "ca_cert.pem"
    ca_key_path = ca_path / "ca_key.pem"
    crl_path = ca_path / "ca.crl"
    revoked_path = ca_path / "revoked.json"
    
    print(f"CA Cert exists: {ca_cert_path.exists()}")
    print(f"CA Key exists: {ca_key_path.exists()}")
    print(f"CRL exists: {crl_path.exists()}")
    print(f"Revoked JSON exists: {revoked_path.exists()}")
    
    if ca_cert_path.exists():
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        print_section("CA Certificate Details")
        print(f"  Subject: {ca_cert.subject.rfc4514_string()}")
        print(f"  Issuer: {ca_cert.issuer.rfc4514_string()}")
        print(f"  Serial Number: {ca_cert.serial_number}")
        print(f"  Not Valid Before: {ca_cert.not_valid_before_utc}")
        print(f"  Not Valid After: {ca_cert.not_valid_after_utc}")
        
        # Check CA cert expiry
        now = datetime.datetime.now(datetime.timezone.utc)
        is_expired = now > ca_cert.not_valid_after_utc or now < ca_cert.not_valid_before_utc
        print(f"  CA Cert Is Expired: {is_expired}")
    else:
        ca_cert = None
    
    if revoked_path.exists():
        with open(revoked_path) as f:
            revoked = json.load(f)
        print_section(f"Revoked Certificates ({len(revoked)} entries)")
        for serial, info in revoked.items():
            print(f"  Serial {serial}: revoked at {info.get('revocation_date', 'N/A')} (reason: {info.get('reason', 'N/A')})")
    
    return ca_cert


def verify_chain(ca_cert, user_cert):
    """Manually verify certificate chain."""
    print_section("Manual Chain Verification")
    
    print(f"CA Subject: {ca_cert.subject.rfc4514_string()}")
    print(f"User Cert Issuer: {user_cert.issuer.rfc4514_string()}")
    print(f"Issuer matches CA Subject: {ca_cert.subject == user_cert.issuer}")
    
    try:
        ca_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm,
        )
        print("Signature verification: SUCCESS")
        return True
    except InvalidSignature as e:
        print(f"Signature verification: FAILED - {e}")
        return False
    except Exception as e:
        print(f"Signature verification: ERROR - {type(e).__name__}: {e}")
        return False


def verify_document_hash(doc_path, expected_hash):
    """Verify document hash."""
    print_section("Document Hash Verification")
    
    sha256 = hashlib.sha256()
    with open(doc_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    computed_hash = sha256.hexdigest()
    
    print(f"Computed Hash: {computed_hash}")
    print(f"Expected Hash: {expected_hash}")
    print(f"Match: {computed_hash == expected_hash}")
    
    return computed_hash == expected_hash


def analyze_all_signatures(data_dir="./app/data"):
    """Analyze all signatures in the data directory."""
    data_path = Path(data_dir)
    sig_dir = data_path / "signatures"
    ca_dir = data_path / "ca"
    uploads_dir = data_path / "uploads"
    
    if not sig_dir.exists():
        print(f"No signatures directory found at {sig_dir}")
        return
    
    sig_files = list(sig_dir.glob("*.sig"))
    if not sig_files:
        print("No signature files found.")
        return
    
    print_header(f"Analyzing {len(sig_files)} Signature Files")
    
    # Load CA
    ca_cert_path = ca_dir / "ca_cert.pem"
    if ca_cert_path.exists():
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        print(f"\nCA Certificate: {ca_cert.subject.rfc4514_string()}")
        print(f"CA Created: {ca_cert.not_valid_before_utc}")
    else:
        print("\n[ERROR] No CA certificate found!")
        ca_cert = None
    
    results = []
    for sig_file in sig_files:
        print(f"\n{'─'*50}")
        print(f"Signature: {sig_file.name}")
        
        with open(sig_file) as f:
            bundle = json.load(f)
        
        cert_pem = bundle.get('certificate_pem', '')
        if cert_pem:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            print(f"  Signer: {cert.subject.rfc4514_string()}")
            print(f"  Cert Issuer: {cert.issuer.rfc4514_string()}")
            print(f"  Cert Serial: {cert.serial_number}")
            print(f"  Cert Created: {cert.not_valid_before_utc}")
            
            if ca_cert:
                # Check if CA matches
                issuer_match = ca_cert.subject == cert.issuer
                print(f"  Issuer matches CA: {issuer_match}")
                
                # Try signature verification
                try:
                    ca_cert.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                    chain_valid = True
                    print(f"  Chain Valid: YES")
                except InvalidSignature:
                    chain_valid = False
                    print(f"  Chain Valid: NO - CA MISMATCH!")
                
                
                results.append({
                    'sig_file': sig_file.name,
                    'signer': cert.subject.rfc4514_string(),
                    'cert_created': str(cert.not_valid_before_utc),
                    'ca_created': str(ca_cert.not_valid_before_utc),
                    'chain_valid': chain_valid,
                })
    
    # Summary
    print_header("SUMMARY")
    failed = [r for r in results if not r['chain_valid']]
    passed = [r for r in results if r['chain_valid']]
    
    print(f"Total signatures: {len(results)}")
    print(f"Valid chain: {len(passed)}")
    print(f"Invalid chain (CA mismatch): {len(failed)}")
    
    if failed:
        print("\n[ROOT CAUSE IDENTIFIED]")
        print("The following signatures were created with a DIFFERENT CA:")
        for r in failed:
            print(f"  - {r['sig_file']}: cert created {r['cert_created']}, CA created {r['ca_created']}")
        print("\nFIX: Either restore the original CA or re-sign the documents.")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Debug SignSure signature verification")
    parser.add_argument("--sig-file", help="Path to .sig file")
    parser.add_argument("--doc-file", help="Path to original document")
    parser.add_argument("--ca-dir", default="./app/data/ca", help="Path to CA directory")
    parser.add_argument("--data-dir", default="./app/data", help="Path to data directory")
    parser.add_argument("--analyze-all", action="store_true", help="Analyze all signatures")
    args = parser.parse_args()
    
    if args.analyze_all:
        analyze_all_signatures(args.data_dir)
        return
    
    if not args.sig_file or not args.doc_file:
        parser.error("--sig-file and --doc-file are required unless --analyze-all is used")
    
    print_header("SignSure Signature Debug Tool")
    
    # Analyze signature file
    bundle, user_cert = analyze_sig_file(args.sig_file)
    
    # Analyze CA
    ca_cert = analyze_ca(args.ca_dir)
    
    # Verify chain
    if ca_cert:
        chain_valid = verify_chain(ca_cert, user_cert)
    else:
        print("\n[ERROR] CA certificate not found!")
        chain_valid = False
    
    # Verify document hash
    doc_hash_match = verify_document_hash(args.doc_file, bundle.get('document_hash_sha256', ''))
    
    # Summary
    print_header("SUMMARY")
    print(f"Chain Valid: {'YES' if chain_valid else 'NO'}")
    print(f"Document Hash Match: {'YES' if doc_hash_match else 'NO'}")
    
    if not chain_valid:
        print("\n[ROOT CAUSE] Certificate chain validation failed!")
        print("This typically means:")
        print("1. The CA on the server is different from the CA that issued the certificate")
        print("2. The CA was regenerated after the certificate was issued")
        print("3. The certificate is from a different PKI instance")
    
    if not doc_hash_match:
        print("\n[WARNING] Document hash doesn't match!")
        print("The document may have been modified after signing.")


if __name__ == "__main__":
    main()
