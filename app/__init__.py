"""SignSure Flask Web Application."""
from flask import Flask
from pathlib import Path
import os

def create_app(data_dir: str = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.urandom(32)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB
    # Normalize data directory to an absolute path so file operations are
    # deterministic regardless of current working directory or how the app
    # was invoked (foreground, background, tests, etc.).
    data_dir_val = data_dir or os.environ.get("SIGNSURE_DATA", "./data")
    app.config["DATA_DIR"] = os.path.abspath(data_dir_val)
    app.config["UPLOAD_FOLDER"] = str(Path(app.config["DATA_DIR"]) / "uploads")

    # Ensure directories
    for sub in ["ca", "keys", "signatures", "encrypted", "uploads"]:
        Path(app.config["DATA_DIR"], sub).mkdir(parents=True, exist_ok=True)

    from .routes import bp
    app.register_blueprint(bp)
    return app
