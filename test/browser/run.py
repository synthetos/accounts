"""Run Chromium against the local Worker fixture, and always dispose its runtime."""
import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--port', type=int, default=18983)
parser.add_argument('--executable', help='Optional Chromium path; otherwise use pinned Playwright Chromium')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
# Refuse an occupied port; never accidentally test an unrelated running service.
with socket.socket() as probe:
    probe.bind(('127.0.0.1', args.port))
with tempfile.TemporaryFile(mode='w+') as log:
    server = subprocess.Popen(['node', 'test/browser/login-server.mjs'], cwd=root,
                              env={**os.environ, 'PORT': str(args.port)}, stdout=log,
                              stderr=subprocess.STDOUT, start_new_session=True)
    try:
        deadline = time.monotonic() + 45
        while True:
            if server.poll() is not None:
                raise RuntimeError('Worker fixture exited during startup')
            try:
                with socket.create_connection(('127.0.0.1', args.port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Worker fixture did not become ready')
                time.sleep(0.1)
        command = [sys.executable, 'test/browser/login_csp.py', '--port', str(args.port)]
        if args.executable:
            command.extend(['--executable', args.executable])
        subprocess.run(command, cwd=root, check=True, timeout=120)
    except BaseException:
        log.seek(0)
        print(log.read(), file=sys.stderr)
        raise
    finally:
        if server.poll() is None:
            os.killpg(server.pid, signal.SIGTERM)
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
                server.wait()
