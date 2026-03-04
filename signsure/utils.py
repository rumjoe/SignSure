"""
SignSure Utilities Module
==========================
Logging setup, file helpers, and shared constants.
"""

import os
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timezone


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging for SignSure."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def hash_file_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of any file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(path: str) -> Path:
    """Ensure a directory exists, creating it if needed."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def human_readable_size(size_bytes: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ── Default directory layout ────────────────────────────────────────────────
# Compute project root (two levels up from this file) and default to
# the `app/data` folder inside the project. Users can override with
# the `SIGNSURE_DATA` environment variable.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = Path(os.environ.get("SIGNSURE_DATA", str(PROJECT_ROOT / "app" / "data")))

PATHS = {
    "ca":          DEFAULT_DATA_DIR / "ca",
    "keys":        DEFAULT_DATA_DIR / "keys",
    "signatures":  DEFAULT_DATA_DIR / "signatures",
    "encrypted":   DEFAULT_DATA_DIR / "encrypted",
    "uploads":     DEFAULT_DATA_DIR / "uploads",
}
