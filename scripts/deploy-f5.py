#!/usr/bin/env python3
"""
Deploy a TLS certificate + key + chain to a BIG-IP and update/create
a client-ssl profile.

Triggered by CertMate after issuance/renewal.  Environment variables:

  F5_URL / F5_USER / F5_PASS            — BIG-IP base URL (http[s]://host[:port])
  CERTMATE_DOMAIN                        — primary domain name
  CERTMATE_CERT_PATH                     — leaf certificate (PEM)
  CERTMATE_KEY_PATH                      — private key (PEM)
  CERTMATE_CHAIN_PATH                    — intermediate chain (PEM)
  CERTMATE_FULLCHAIN_PATH                — leaf + chain combined (PEM)
  CERTMATE_EVENT                         — "deployed" | "renewed"
  CERTMATE_DRY_RUN                       — "1" ⇒ log only, no API calls

Usage:

  python3 scripts/deploy-f5.py \\
    --prefix "myapp-" \\
    --suffix "-v1" \\
    --partition "Common" \\
    --parent-profile "clientssl"
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("deploy-f5")

DRY_RUN = os.environ.get("CERTMATE_DRY_RUN") == "1"
CERTMATE_EVENT = os.environ.get("CERTMATE_EVENT", "deployed")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy TLS certificate to F5 BIG-IP")

    parser.add_argument("--prefix", default="",
                        help="Optional name prefix for F5 objects")
    parser.add_argument("--suffix", default="",
                        help="Optional name suffix for F5 objects")
    parser.add_argument("--partition", default="Common",
                        help="BIG-IP partition (default: Common)")
    parser.add_argument("--parent-profile", default="clientssl",
                        help="Parent client-ssl profile (default: clientssl)")
    parser.add_argument("--server-name", default="",
                        help="serverName in the client-ssl profile "
                             "(default: CERTMATE_DOMAIN)")

    args = parser.parse_args(argv)

    # Validate required env vars
    for var in ("F5_URL", "F5_USER", "F5_PASS",
                "CERTMATE_DOMAIN", "CERTMATE_CERT_PATH",
                "CERTMATE_KEY_PATH", "CERTMATE_CHAIN_PATH"):
        if not os.environ.get(var):
            parser.error(f"{var} is required")

    for var in ("CERTMATE_CERT_PATH", "CERTMATE_KEY_PATH", "CERTMATE_CHAIN_PATH"):
        p = Path(os.environ[var])
        if not p.exists():
            parser.error(f"{var}={p} does not exist")

    if not args.server_name:
        args.server_name = os.environ["CERTMATE_DOMAIN"]

    return args


# ── helpers ──────────────────────────────────────────────────────────

def f5_name(prefix: str, domain: str, suffix: str) -> str:
    """Build the F5 object name, e.g.  myapp-example.com-v1"""
    return f"{prefix}{domain}{suffix}".replace("*", "wildcard")


def f5_path(name: str, partition: str) -> str:
    return f"/{partition}/{name}"


def _read_env(var: str) -> str:
    with open(os.environ[var]) as f:
        return f.read()


def _fmt(name: str, partition: str) -> str:
    return f"/{partition}/{name}"


def rest_url(base_url: str, endpoint: str) -> str:
    return f"{base_url}/mgmt/tm{endpoint}"


def rest_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _basic_auth() -> tuple[str, str]:
    return (os.environ["F5_USER"], os.environ["F5_PASS"])


def _request(method: str, url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("headers", rest_headers())
    kwargs.setdefault("auth", _basic_auth())
    if url.startswith("https"):
        kwargs.setdefault("verify", False)
    logger.debug("%s %s", method, url)
    if DRY_RUN:
        logger.info("[DRY-RUN] %s %s", method, url)
        if kwargs.get("json"):
            logger.info("[DRY-RUN] body: %s", json.dumps(kwargs["json"], indent=2))
        return None  # type: ignore[return-value]

    resp = requests.request(method, url, **kwargs)
    logger.debug("← %s %s", resp.status_code, resp.text[:500])
    return resp


def entity_exists(base_url: str, endpoint: str) -> bool:
    url = rest_url(base_url, endpoint)
    if DRY_RUN:
        logger.info("[DRY-RUN] GET %s", url)
        return False
    resp = _request("GET", url)
    return resp.status_code != 404


def upload_crypto_object(base_url: str, endpoint: str, name: str,
                         partition: str, content: str) -> None:
    """POST or PUT a crypto object (cert / key / chain)."""
    exists = entity_exists(base_url, f"{endpoint}/~{partition}~{name}")
    url = rest_url(base_url, endpoint)
    body = {
        "name": name,
        "partition": partition,
        "sourceType": "explicit",
        "sourcePath": content if endpoint == "/sys/crypto/key" else content,
    }

    if endpoint != "/sys/crypto/key":
        body["bundle"] = content

    method = "PUT" if exists else "POST"
    resp = _request(method, url, json=body)

    if resp is None:  # dry-run
        return

    if resp.status_code not in (200, 201, 202):
        logger.error("Failed to %s %s: HTTP %d – %s",
                      method, name, resp.status_code, resp.text[:500])
        raise RuntimeError(f"{method} {name} failed: {resp.text[:200]}")
    logger.info("%s %s on partition %s", "Updated" if exists else "Created", name, partition)


def upsert_client_ssl_profile(base_url: str, partition: str, name: str,
                              cert_name: str, key_name: str, chain_name: str,
                              parent_profile: str, server_name: str) -> None:
    """Create or update a client-ssl profile."""
    exists = entity_exists(base_url, f"/ltm/profile/client-ssl/~{partition}~{name}")

    url = rest_url(base_url, "/ltm/profile/client-ssl")
    body = {
        "name": name,
        "partition": partition,
        "defaultsFrom": parent_profile,
        "cert": f"/{partition}/{cert_name}",
        "key": f"/{partition}/{key_name}",
        "chain": f"/{partition}/{chain_name}",
        "serverName": server_name,
    }

    method = "PUT" if exists else "POST"
    resp = _request(method, url, json=body)

    if resp is None:
        return

    if resp.status_code not in (200, 201, 202):
        logger.error("Failed to %s client-ssl profile %s: HTTP %d – %s",
                      method, name, resp.status_code, resp.text[:500])
        raise RuntimeError(f"{method} client-ssl {name} failed: {resp.text[:200]}")
    logger.info("%s client-ssl profile %s on partition %s",
                "Updated" if exists else "Created", name, partition)


# ── main ─────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()

    base_url = os.environ["F5_URL"].rstrip("/")
    domain = os.environ["CERTMATE_DOMAIN"]
    obj_name = f5_name(args.prefix, domain, args.suffix)
    partition = args.partition

    cert_pem = _read_env("CERTMATE_CERT_PATH")
    key_pem = _read_env("CERTMATE_KEY_PATH")
    chain_pem = _read_env("CERTMATE_CHAIN_PATH")

    cert_obj_name = obj_name
    key_obj_name = obj_name
    chain_obj_name = f"{obj_name}-chain"

    if DRY_RUN:
        logger.info("=== DRY-RUN MODE – no requests will be sent ===")

    logger.info("Event: %s | Domain: %s | F5 object name: %s | Partition: %s",
                CERTMATE_EVENT, domain, obj_name, partition)

    # ── cert ──
    upload_crypto_object(base_url, "/sys/crypto/cert",
                         cert_obj_name, partition, cert_pem)

    # ── key ──
    upload_crypto_object(base_url, "/sys/crypto/key",
                         key_obj_name, partition, key_pem)

    # ── chain ──
    upload_crypto_object(base_url, "/sys/crypto/cert",
                         chain_obj_name, partition, chain_pem)

    # ── client-ssl profile ──
    upsert_client_ssl_profile(
        base_url, partition, obj_name,
        cert_obj_name, key_obj_name, chain_obj_name,
        args.parent_profile, args.server_name,
    )

    logger.info("Deployment to F5 complete for %s", domain)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.warning("Interrupted")
        raise SystemExit(1)
    except Exception as exc:
        logger.exception("%s", exc)
        raise SystemExit(1)
