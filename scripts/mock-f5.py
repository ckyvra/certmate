#!/usr/bin/env python3
"""
Mock F5 BIG-IP REST API server for testing deploy-f5.py.

Simulates the endpoints used by the deployment script and logs every
request/response in a human-readable ASCII format.

Usage:

    python3 scripts/mock-f5.py [--port 8443]

Then run deploy-f5.py against it:

    F5_HOST=localhost:8443 \\
    F5_USER=admin F5_PASS=admin \\
    CERTMATE_DOMAIN=example.com \\
    CERTMATE_CERT_PATH=test.crt \\
    CERTMATE_KEY_PATH=test.key \\
    CERTMATE_CHAIN_PATH=test-chain.pem \\
    CERTMATE_EVENT=deployed \\
    python3 scripts/deploy-f5.py
"""

import argparse
import json
import logging
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)
logger = logging.getLogger("mock-f5")

SEPARATOR = "\u2500" * 60


class Store(dict):
    """Simple in-memory store keyed by ``(method, endpoint)``."""
    def __init__(self):
        super().__init__()
        self._objects: dict[str, dict] = {}
        self._next_id = 1

    def get(self, path: str) -> dict | None:
        return self._objects.get(path)

    def create(self, path: str, body: dict) -> dict:
        self._objects[path] = body
        return body

    def update(self, path: str, body: dict) -> dict:
        existing = self._objects.get(path, {})
        existing.update(body)
        self._objects[path] = existing
        return existing

    def exists(self, path: str) -> bool:
        return path in self._objects


store = Store()


class MockF5Handler(BaseHTTPRequestHandler):
    server_version = "mock-f5/1.0"

    # ── helpers ──────────────────────────────────────────────────────

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw.decode()}

    def _endpoint_key(self, full_path: str) -> str:
        """Normalise the request path as a dict key."""
        parsed = urlparse(full_path)
        return parsed.path.rstrip("/")

    def _log_request(self, body: dict | None = None) -> None:
        logger.info("")
        logger.info(SEPARATOR)
        logger.info("%s %s", self.command, self.path)
        if body:
            logger.info("%s", json.dumps(body, indent=2))

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body, indent=2).encode()
        logger.info("\u2192 %s %s", status, body.get("name", ""))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # ── dispatchers ──────────────────────────────────────────────────

    def _handle_crypto_cert_or_key(self, collection_path: str) -> None:
        """Handle /mgmt/tm/sys/crypto/{cert,key} requests."""
        body = self._read_body()
        self._log_request(body)

        # Determine the singular resource path
        key = self._endpoint_key(self.path)
        obj_name = body.get("name", "?")

        if self.command == "GET":
            obj = store.get(key)
            if obj is None:
                self._respond(404, {"code": 404, "message": "not found"})
            else:
                self._respond(200, obj)
            return

        if self.command == "POST":
            obj = store.create(key, body)
            obj["selfLink"] = f"https://localhost{key}"
            self._respond(201, obj)
            return

        if self.command == "PUT":
            if store.exists(key):
                obj = store.update(key, body)
                self._respond(200, obj)
            else:
                obj = store.create(key, body)
                obj["selfLink"] = f"https://localhost{key}"
                self._respond(201, obj)
            return

        self._respond(405, {"code": 405, "message": "method not allowed"})

    def _handle_client_ssl(self) -> None:
        """Handle /mgmt/tm/ltm/profile/client-ssl requests."""
        body = self._read_body()
        self._log_request(body)
        key = self._endpoint_key(self.path)

        if self.command == "GET":
            obj = store.get(key)
            if obj is None:
                self._respond(404, {"code": 404, "message": "not found"})
            else:
                self._respond(200, obj)
            return

        if self.command == "POST":
            obj = store.create(key, body)
            obj["selfLink"] = f"https://localhost{key}"
            self._respond(201, obj)
            return

        if self.command == "PUT":
            if store.exists(key):
                obj = store.update(key, body)
                self._respond(200, obj)
            else:
                obj = store.create(key, body)
                obj["selfLink"] = f"https://localhost{key}"
                self._respond(201, obj)
            return

        self._respond(405, {"code": 405, "message": "method not allowed"})

    # ── routing ──────────────────────────────────────────────────────

    def do_GET(self):
        path = self.path.rstrip("/")

        if "/sys/crypto/cert/~" in path or "/sys/crypto/key/~" in path:
            self._handle_crypto_cert_or_key("/sys/crypto/cert" if "/cert/" in path else "/sys/crypto/key")
            return

        if "/ltm/profile/client-ssl/~" in path:
            self._handle_client_ssl()
            return

        self._log_request()
        self._respond(404, {"code": 404, "message": "endpoint not found"})

    def do_POST(self):
        path = self.path.rstrip("/")

        if path == "/mgmt/tm/sys/crypto/cert":
            self._handle_crypto_cert_or_key("/sys/crypto/cert")
        elif path == "/mgmt/tm/sys/crypto/key":
            self._handle_crypto_cert_or_key("/sys/crypto/key")
        elif path == "/mgmt/tm/ltm/profile/client-ssl":
            self._handle_client_ssl()
        else:
            self._log_request(self._read_body())
            self._respond(404, {"code": 404, "message": "endpoint not found"})

    def do_PUT(self):
        # PUT uses the same paths as POST
        self.do_POST()

    def log_message(self, fmt, *args):
        """Suppress the default stderr logging (we use our own)."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mock F5 BIG-IP REST API server")
    parser.add_argument("--port", type=int, default=8443,
                        help="Listen port (default: 8443)")
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    host = "127.0.0.1"

    server = HTTPServer((host, args.port), MockF5Handler)

    logger.info("")
    logger.info(SEPARATOR)
    logger.info("Mock F5 BIG-IP server listening on http://%s:%s", host, args.port)
    logger.info("Press Ctrl+C to stop")
    logger.info(SEPARATOR)
    logger.info("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
