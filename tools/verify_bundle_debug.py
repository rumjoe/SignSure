#!/usr/bin/env python3
"""Debug helper: inspect a .sig bundle and run verification using server CA.

Usage:
  python tools/verify_bundle_debug.py /path/to/document /path/to/signature.sig [data_dir]

This will print bundle fields, certificate details, server CA info and run
the `VerificationService.verify_file` call so you can see why verification
fails when uploading through the web UI.
"""

import sys
import json
import logging
from pathlib import Path

from signsure.ca import CertificateAuthority
from signsure.verifier import VerificationService


def print_bundle(bundle):
    print("--- Bundle fields ---")
    for k, v in bundle.items():
        if k == "certificate_pem":
            print("certificate_pem: (PEM omitted, length=%d)" % len(v))
        else:
            print(f"{k}: {v}")


def main():
    if len(sys.argv) < 3:
        print("Usage: verify_bundle_debug.py /path/to/doc /path/to/sig [data_dir]")
        sys.exit(2)

    doc_path = Path(sys.argv[1])
    sig_path = Path(sys.argv[2])
    data_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("app/data")

    logging.basicConfig(level=logging.DEBUG)

    if not doc_path.exists():
        print("Document not found:", doc_path)
        sys.exit(1)
    if not sig_path.exists():
        print("Signature file not found:", sig_path)
        sys.exit(1)

    with open(sig_path) as f:
        bundle = json.load(f)

    print_bundle(bundle)

    ca = CertificateAuthority(ca_dir=str(Path(data_dir) / "ca"))
    try:
        ca.load_ca()
    except Exception as e:
        print("Unable to load CA from:", Path(data_dir) / "ca", " — ", e)
        sys.exit(1)

    print("\n--- Server CA ---")
    print(ca.ca_cert.subject.rfc4514_string())
    print(ca.ca_cert.issuer.rfc4514_string())
    print("serial:", ca.ca_cert.serial_number)

    ver = VerificationService(ca)
    print("\nRunning verification...\n")
    res = ver.verify_file(str(doc_path), str(sig_path))
    print("Result:")
    print(json.dumps(res.to_dict(), indent=2))


if __name__ == "__main__":
    main()
