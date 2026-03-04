"""
SignSure Flask Routes
======================
API endpoints for the SignSure web interface.
"""

import os
import json
import traceback
from pathlib import Path
from flask import (
    Blueprint, request, jsonify, render_template,
    send_file, current_app, session
)
from werkzeug.utils import secure_filename

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from signsure.ca         import CertificateAuthority
from signsure.keymgr     import KeyManager
from signsure.signer     import SignatureService
from signsure.verifier   import VerificationService
from signsure.encryption import EncryptionService

bp = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "docx", "doc", "png", "jpg", "jpeg",
    "xlsx", "csv", "json", "xml", "md", "html"
}


def _get_services():
    """Initialise all SignSure services from the configured data directory."""
    data_dir = current_app.config["DATA_DIR"]

    ca   = CertificateAuthority(ca_dir=str(Path(data_dir) / "ca"))
    km   = KeyManager(keys_dir=str(Path(data_dir) / "keys"))
    sig  = SignatureService(km, sigs_dir=str(Path(data_dir) / "signatures"))
    enc  = EncryptionService(km, encrypted_dir=str(Path(data_dir) / "encrypted"))

    # Load CA if it exists
    ca_cert_path = Path(data_dir) / "ca" / "ca_cert.pem"
    if ca_cert_path.exists():
        ca.load_ca()
        ver = VerificationService(ca)
    else:
        ver = None

    return ca, km, sig, ver, enc


def _allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ── UI ─────────────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    return render_template("index.html")


# ── SYSTEM STATUS ───────────────────────────────────────────────────────────

@bp.route("/api/status")
def status():
    data_dir     = current_app.config["DATA_DIR"]
    ca_cert_path = Path(data_dir) / "ca" / "ca_cert.pem"
    ca_ready     = ca_cert_path.exists()

    keys_dir  = Path(data_dir) / "keys"
    users     = [f.stem for f in keys_dir.glob("*.p12")] if keys_dir.exists() else []

    sigs_dir = Path(data_dir) / "signatures"
    sigs     = [f.name for f in sigs_dir.glob("*.sig")] if sigs_dir.exists() else []

    return jsonify({
        "ca_initialised": ca_ready,
        "registered_users": users,
        "signature_count": len(sigs),
    })


# ── CA INITIALISATION ───────────────────────────────────────────────────────

@bp.route("/api/ca/init", methods=["POST"])
def init_ca():
    try:
        data    = request.get_json() or {}
        ca_name = data.get("ca_name", "SignSure-RootCA")
        org     = data.get("org", "SignSure PKI")
        country = data.get("country", "NP")
        force   = data.get("force", False)  # Allow force regeneration

        ca, *_ = _get_services()
        
        # Check if CA already exists
        ca_cert_path = Path(current_app.config["DATA_DIR"]) / "ca" / "ca_cert.pem"
        if ca_cert_path.exists() and not force:
            return jsonify({
                "success": False, 
                "error": "CA already exists. Re-initializing will invalidate all existing signatures!",
                "ca_exists": True,
                "hint": "Use force=true to regenerate (WARNING: destroys all existing signatures)"
            }), 400
        
        _, cert = ca.generate_ca(common_name=ca_name, org=org, country=country, force=force)

        return jsonify({
            "success": True,
            "message": f"Root CA '{ca_name}' initialised successfully.",
            "serial": cert.serial_number,
            "subject": cert.subject.rfc4514_string(),
            "warning": "All previous signatures are now invalid" if force else None,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/ca/cert", methods=["GET"])
def get_ca_cert():
    try:
        ca, *_ = _get_services()
        return jsonify({"cert_pem": ca.get_ca_cert_pem()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── USER REGISTRATION ───────────────────────────────────────────────────────

@bp.route("/api/users/register", methods=["POST"])
def register_user():
    try:
        data       = request.get_json() or {}
        username   = data.get("username", "").strip()
        passphrase = data.get("passphrase", "").encode()
        email      = data.get("email", "")

        if not username:
            return jsonify({"success": False, "error": "Username is required"}), 400
        if len(data.get("passphrase", "")) < 8:
            return jsonify({"success": False, "error": "Passphrase must be at least 8 characters"}), 400

        ca, km, *_ = _get_services()

        if km.p12_exists(username):
            return jsonify({"success": False, "error": f"User '{username}' already exists"}), 400

        # Generate key pair
        private_key, public_key = km.generate_keypair()

        # Issue certificate
        cert = ca.issue_certificate(
            username=username,
            public_key=public_key,
            email=email or None,
        )

        # Save PKCS#12 keystore
        p12_path = km.save_to_pkcs12(
            username=username,
            private_key=private_key,
            cert=cert,
            passphrase=passphrase,
            ca_cert=ca.ca_cert,
        )

        # Export public cert PEM for sharing
        cert_pem = km.export_cert_pem(cert)
        cert_path = Path(current_app.config["DATA_DIR"]) / "keys" / f"{username}_cert.pem"
        with open(cert_path, "w") as f:
            f.write(cert_pem)

        return jsonify({
            "success": True,
            "message": f"User '{username}' registered successfully.",
            "serial": cert.serial_number,
            "cert_pem": cert_pem,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/users/list", methods=["GET"])
def list_users():
    try:
        data_dir = current_app.config["DATA_DIR"]
        keys_dir = Path(data_dir) / "keys"
        users = []
        for p12_file in keys_dir.glob("*.p12"):
            username = p12_file.stem
            cert_path = keys_dir / f"{username}_cert.pem"
            users.append({
                "username": username,
                "has_cert": cert_path.exists(),
            })
        return jsonify({"users": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/users/<username>/cert", methods=["GET"])
def get_user_cert(username):
    try:
        data_dir  = current_app.config["DATA_DIR"]
        cert_path = Path(data_dir) / "keys" / f"{secure_filename(username)}_cert.pem"
        if not cert_path.exists():
            return jsonify({"error": "Certificate not found"}), 404
        with open(cert_path) as f:
            return jsonify({"cert_pem": f.read(), "username": username})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── SIGNING ─────────────────────────────────────────────────────────────────

@bp.route("/api/sign", methods=["POST"])
def sign_document():
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        f          = request.files["file"]
        username   = request.form.get("username", "")
        passphrase = request.form.get("passphrase", "").encode()

        if not username:
            return jsonify({"success": False, "error": "Username required"}), 400
        if not f.filename:
            return jsonify({"success": False, "error": "No file selected"}), 400
        if not _allowed(f.filename):
            return jsonify({"success": False, "error": "File type not allowed"}), 400

        filename  = secure_filename(f.filename)
        upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
        file_path = upload_dir / filename
        f.save(str(file_path))

        _, km, sig_svc, *_ = _get_services()

        result = sig_svc.sign_file(
            file_path=str(file_path),
            username=username,
            passphrase=passphrase,
        )

        # Read .sig for response
        with open(result["sig_path"]) as sf:
            sig_bundle = json.load(sf)

        return jsonify({
            "success": True,
            "message": f"Document signed successfully by {username}.",
            "document_hash": result["document_hash"],
            "timestamp": result["timestamp"],
            "serial": result["serial"],
            "sig_filename": Path(result["sig_path"]).name,
            "sig_bundle": sig_bundle,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/signatures/<sig_filename>", methods=["GET"])
def download_signature(sig_filename):
    data_dir = current_app.config["DATA_DIR"]
    sig_path = Path(data_dir) / "signatures" / secure_filename(sig_filename)
    if not sig_path.exists():
        return jsonify({"error": "Signature not found"}), 404
    try:
        # Use absolute path and set a download name to avoid issues across Flask versions
        abs_path = str(sig_path.resolve())
        return send_file(abs_path, as_attachment=True, download_name=sig_path.name)
    except Exception as e:
        # Return JSON with error details to aid debugging instead of a generic 500
        tb = traceback.format_exc()
        current_app.logger.error("Failed to send signature file: %s\n%s", e, tb)
        return jsonify({"error": str(e), "traceback": tb}), 500


@bp.route("/api/encrypted/<enc_filename>", methods=["GET"])
def download_encrypted(enc_filename):
    """Download an encrypted .enc file from the data `encrypted` folder."""
    data_dir = current_app.config["DATA_DIR"]
    enc_path = Path(data_dir) / "encrypted" / secure_filename(enc_filename)
    if not enc_path.exists():
        return jsonify({"error": "Encrypted file not found"}), 404
    try:
        abs_path = str(enc_path.resolve())
        return send_file(abs_path, as_attachment=True, download_name=enc_path.name)
    except Exception as e:
        tb = traceback.format_exc()
        current_app.logger.error("Failed to send encrypted file: %s\n%s", e, tb)
        return jsonify({"error": str(e), "traceback": tb}), 500


@bp.route("/api/decrypted/<dec_filename>", methods=["GET"])
def download_decrypted(dec_filename):
    """Download a decrypted file produced by `EncryptionService.decrypt_file`.

    Decrypted outputs are stored in the `encrypted` directory with the
    prefix `decrypted_` by default; this endpoint will look for the
    requested filename directly under the `encrypted` folder.
    """
    data_dir = current_app.config["DATA_DIR"]
    dec_path = Path(data_dir) / "encrypted" / secure_filename(dec_filename)
    if not dec_path.exists():
        return jsonify({"error": "Decrypted file not found"}), 404
    try:
        abs_path = str(dec_path.resolve())
        return send_file(abs_path, as_attachment=True, download_name=dec_path.name)
    except Exception as e:
        tb = traceback.format_exc()
        current_app.logger.error("Failed to send decrypted file: %s\n%s", e, tb)
        return jsonify({"error": str(e), "traceback": tb}), 500


# ── VERIFICATION ────────────────────────────────────────────────────────────

@bp.route("/api/verify", methods=["POST"])
def verify_document():
    try:
        if "file" not in request.files or "sig_file" not in request.files:
            return jsonify({"success": False, "error": "Both document and .sig file required"}), 400

        doc_file = request.files["file"]
        sig_file = request.files["sig_file"]

        upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
        doc_path   = upload_dir / secure_filename(doc_file.filename)
        sig_path   = upload_dir / secure_filename(sig_file.filename)

        doc_file.save(str(doc_path))
        sig_file.save(str(sig_path))

        ca, _, _, ver, _ = _get_services()
        if ver is None:
            return jsonify({"success": False, "error": "CA not initialised"}), 500

        result = ver.verify_file(str(doc_path), str(sig_path))
        result_dict = result.to_dict()
        result_dict["success"] = True

        return jsonify(result_dict)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── ENCRYPTION ──────────────────────────────────────────────────────────────

@bp.route("/api/encrypt", methods=["POST"])
def encrypt_document():
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        f                = request.files["file"]
        recipient_username = request.form.get("recipient", "")

        if not recipient_username:
            return jsonify({"success": False, "error": "Recipient username required"}), 400

        filename   = secure_filename(f.filename)
        upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
        file_path  = upload_dir / filename
        f.save(str(file_path))

        # Load recipient's cert
        data_dir   = current_app.config["DATA_DIR"]
        cert_path  = Path(data_dir) / "keys" / f"{secure_filename(recipient_username)}_cert.pem"
        if not cert_path.exists():
            return jsonify({"success": False, "error": f"No certificate for '{recipient_username}'"}), 404

        with open(cert_path) as cf:
            recipient_cert_pem = cf.read()

        _, _, _, _, enc_svc = _get_services()
        enc_path = enc_svc.encrypt_file(str(file_path), recipient_cert_pem)

        return jsonify({
            "success": True,
            "message": f"File encrypted for {recipient_username}.",
            "enc_filename": Path(enc_path).name,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/decrypt", methods=["POST"])
def decrypt_document():
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No encrypted file uploaded"}), 400

        f          = request.files["file"]
        username   = request.form.get("username", "")
        passphrase = request.form.get("passphrase", "").encode()

        if not username:
            return jsonify({"success": False, "error": "Username required"}), 400

        filename   = secure_filename(f.filename)
        upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
        enc_path   = upload_dir / filename
        f.save(str(enc_path))

        _, _, _, _, enc_svc = _get_services()
        # Write decrypted output into the uploads folder so it is colocated
        # with the uploaded file and easy to return to the client.
        base_out_name = f"decrypted_{enc_path.stem}"
        out_path = upload_dir / base_out_name

        # If a file with that name already exists, append a numeric suffix
        # to avoid races or overwrites (decrypted_<name>, decrypted_<name>_1, ...).
        if out_path.exists():
            i = 1
            while True:
                candidate = upload_dir / f"{base_out_name}_{i}"
                if not candidate.exists():
                    out_path = candidate
                    break
                i += 1

        dec_path = enc_svc.decrypt_file(str(enc_path), username, passphrase, output_path=str(out_path))

        # Ensure returned path exists (decrypt_file should have created it)
        if not Path(dec_path).exists():
            return jsonify({"success": False, "error": f"Decrypted file not found: {dec_path}"}), 500

        # Return the file and include its actual filename in a header so the
        # client can discover the server-side name for subsequent downloads.
        resp = send_file(str(dec_path), as_attachment=True, download_name=Path(dec_path).name)
        resp.headers['X-Decrypted-Filename'] = Path(dec_path).name
        return resp
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── REVOCATION ──────────────────────────────────────────────────────────────

@bp.route("/api/revoke", methods=["POST"])
def revoke_certificate():
    try:
        data   = request.get_json() or {}
        serial = data.get("serial")
        if serial is None:
            return jsonify({"success": False, "error": "Serial number required"}), 400

        ca, *_ = _get_services()
        ca.revoke_certificate(int(serial))
        return jsonify({
            "success": True,
            "message": f"Certificate serial {serial} revoked and CRL updated.",
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/crl", methods=["GET"])
def get_crl_info():
    try:
        data_dir     = current_app.config["DATA_DIR"]
        revoked_path = Path(data_dir) / "ca" / "revoked.json"
        if revoked_path.exists():
            with open(revoked_path) as f:
                revoked = json.load(f)
        else:
            revoked = {}
        return jsonify({"revoked": revoked, "count": len(revoked)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
