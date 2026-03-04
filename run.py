import argparse
import logging
import os
import sys
import subprocess
from signsure.utils import setup_logging


def _run_foreground(app, host: str, port: int, debug: bool):
    # In the child (foreground) process we suppress werkzeug access logs
    # to avoid spamming the terminal with each request.
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    app.run(host=host, port=port, debug=debug)


def main():
    parser = argparse.ArgumentParser(description="SignSure Document Signing Server")
    parser.add_argument("--host",  default="127.0.0.1",    help="Host (default: 127.0.0.1)")
    parser.add_argument("--port",  default=5000, type=int, help="Port (default: 5000)")
    parser.add_argument("--data",  default="./app/data",        help="Data directory (default: ./app/data)")
    parser.add_argument("--debug", action="store_true",     help="Enable debug mode")
    parser.add_argument("--stop", action="store_true", help="Stop background server")
    # Internal flag used to indicate the child server process
    parser.add_argument("--_child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    setup_logging("DEBUG" if args.debug else "INFO")
    logger = logging.getLogger("signsure")

    from app import create_app
    # Use an absolute data directory so the server always uses the same
    # location regardless of working directory when the child process runs.
    # If a relative path was provided, make it relative to the script's
    # location (project root) so running the command from other folders
    # won't change where data is stored.
    if os.path.isabs(args.data):
        abs_data = args.data
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        abs_data = os.path.abspath(os.path.join(script_dir, args.data))
    app = create_app(data_dir=abs_data)

    # Print startup banner from the parent process (friendly and short)
    logger.info("=" * 60)
    logger.info("  SignSure PKI Document Security Platform")
    logger.info("  Version 1.0.0 | MIT License")
    logger.info("=" * 60)
    logger.info("  URL:  http://%s:%d", args.host, args.port)
    logger.info("  Data: %s", abs_data)
    logger.info("=" * 60)

    # If invoked as the child process, run the Flask server directly
    if args._child:
        _run_foreground(app, args.host, args.port, args.debug)
        return

    # If asked to stop, find child processes and terminate them
    if args.stop:
        import signal
        try:
            pids = subprocess.check_output(["pgrep", "-f", f"{os.path.basename(__file__)} --_child"]).decode().strip().split() 
            for p in pids:
                try:
                    os.kill(int(p), signal.SIGTERM)
                except Exception:
                    pass
            logger.info("Stopped %d background process(es)", len(pids))
        except subprocess.CalledProcessError:
            logger.info("No background server process found to stop")
        return

    # Otherwise, spawn a detached child process that runs the server
    python = sys.executable or 'python3'
    cmd = [python, __file__, "--host", args.host, "--port", str(args.port), "--data", abs_data]
    if args.debug:
        cmd.append("--debug")
    cmd.append("--_child")

    # Use subprocess to start child in its own session so parent can exit
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        logger.info("Server started in background (detached). You may run other commands.")
    except Exception as e:
        logger.error("Failed to start background server: %s", e)


if __name__ == "__main__":
    main()
