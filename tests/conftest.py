import os
import socket
import sys
import threading
import time

import pytest
import requests

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TESTS_DIR = os.path.abspath(os.path.dirname(__file__))

for path in (PROJECT_ROOT, TESTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def app_url():
    """Base URL of the deliberately vulnerable Flask app, on a free port."""
    from vulnerable_test_app import app, init_db

    init_db()
    port = _free_port()
    threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        daemon=True,
    ).start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(40):
        try:
            requests.get(base + "/robots.txt", timeout=1)
            break
        except requests.RequestException:
            time.sleep(0.25)
    return base
