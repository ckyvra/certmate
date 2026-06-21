#!/usr/bin/env python3
"""
Manage _acme-challenge TXT records in BIND zone files
hosted on GitHub, triggered by certbot manual hooks.

Usage -- certbot call (certbot populates CERTBOT_DOMAIN / CERTBOT_VALIDATION):

  python3 scripts/dns-github.py \
    --action add \
    --repo "https://github.com/user/dns-zones.git" \
    --token "ghp_xxxxxxxxxxxx" \
    --zone-path "zones/mail" \
    --zone-prefix "mail." \
    --zone-suffix ".zone" \
    --domain example.com

  python3 scripts/dns-github.py \
    --action remove \
    --repo "https://github.com/user/dns-zones.git" \
    --token "ghp_xxxxxxxxxxxx" \
    --zone-path "zones/mail" \
    --zone-prefix "mail." \
    --zone-suffix ".zone" \
    --domain example.com
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage _acme-challenge TXT records in BIND zone files hosted on GitHub"
    )

    parser.add_argument("--action", required=True, choices=("add", "remove"),
                        help="add or remove the _acme-challenge TXT record")
    parser.add_argument("--repo", required=True,
                        help="GitHub repository HTTPS URL")
    parser.add_argument("--token", required=True,
                        help="GitHub personal-access token (classic or fine-grained)")
    parser.add_argument("--zone-path", required=True,
                        help="Directory within the repository that holds zone files (e.g. zones/mail)")
    parser.add_argument("--zone-prefix", required=True,
                        help="Filename prefix before the domain (e.g. mail.)")
    parser.add_argument("--zone-suffix", required=True,
                        help="Filename suffix after the domain (e.g. .zone)")
    parser.add_argument("--domain",
                        default=os.environ.get("CERTBOT_DOMAIN", ""),
                        help="Domain being validated (default: $CERTBOT_DOMAIN)")
    parser.add_argument("--value",
                        default=os.environ.get("CERTBOT_VALIDATION", ""),
                        help="TXT record value (default: $CERTBOT_VALIDATION)")
    parser.add_argument("--branch", default="main",
                        help="Target branch (default: main)")
    parser.add_argument("--git-user", default="certbot-dns-github",
                        help="Git author name")
    parser.add_argument("--git-email", default="certbot@localhost",
                        help="Git author email")

    args = parser.parse_args(argv)

    if not args.domain:
        parser.error("--domain is required when CERTBOT_DOMAIN is not set")
    if args.action == "add" and not args.value:
        parser.error("--value is required when CERTBOT_VALIDATION is not set")

    return args


def make_authenticated_url(repo: str, token: str) -> str:
    """Embed the token into an HTTPS URL for passwordless git auth."""
    if repo.startswith("https://"):
        return repo.replace("https://", f"https://x-access-token:{token}@", 1)
    raise ValueError("Only HTTPS repository URLs are supported")


def run_git(cmd: list[str], cwd: Path) -> None:
    subprocess.run(["git", *cmd], cwd=cwd, check=True,
                   capture_output=True, text=True)


def resolve_zone_file(zone_dir: Path, prefix: str, domain: str, suffix: str) -> Path:
    return zone_dir / f"{prefix}{domain}{suffix}"


def _make_record_lines(action: str, domain: str, value: str, lines: list[str]
                       ) -> list[str]:
    """Return updated lines after adding or removing the ACME challenge.

    The BIND ``_acme-challenge`` record can appear in three forms:

    * ``_acme-challenge  IN TXT  "..."`` (relative, relies on ``$ORIGIN``)
    * ``_acme-challenge.<domain>.  IN TXT  "..."`` (absolute, trailing dot)
    * ``_acme-challenge.<domain>  IN TXT  "..."`` (no trailing dot;

    The matcher tries all three and, for **add**, normalises the record
    to the absolute form with a trailing dot.
    """
    domain_dot = f"{domain}."

    rel = re.compile(
        r"^\s*_acme-challenge\s+(?:\d+\s+)?(?:IN\s+)?TXT\s+\"(.*)\"\s*(?:;.*)?$",
        re.IGNORECASE,
    )
    abs_dot = re.compile(
        rf"^\s*_acme-challenge\.{re.escape(domain_dot)}\s+(?:\d+\s+)?(?:IN\s+)?TXT\s+\"(.*)\"\s*(?:;.*)?$",
        re.IGNORECASE,
    )
    abs_no_dot = re.compile(
        rf"^\s*_acme-challenge\.{re.escape(domain)}\s+(?:\d+\s+)?(?:IN\s+)?TXT\s+\"(.*)\"\s*(?:;.*)?$",
        re.IGNORECASE,
    )

    canonical_line = f"_acme-challenge.{domain_dot} IN TXT \"{value}\"\n"

    # find existing
    index = None
    for i, line in enumerate(lines):
        if rel.match(line) or abs_dot.match(line) or abs_no_dot.match(line):
            index = i
            break

    if action == "remove":
        if index is not None:
            lines.pop(index)
        return lines

    # action == "add"
    if index is not None:
        lines[index] = canonical_line
        return lines

    # Insert after the SOA record (closing paren) so the record
    # lives in a predictable spot rather than at end-of-file.
    insert_pos = len(lines)
    for i, line in enumerate(lines):
        if re.search(r"SOA\s", line, re.IGNORECASE):
            for j in range(i, min(i + 30, len(lines))):
                if ")" in lines[j]:
                    insert_pos = j + 1
                    break
            break

    lines.insert(insert_pos, canonical_line)
    return lines


def main() -> int:
    args = parse_args()
    tmpdir: Path | None = None

    try:
        tmpdir = Path(tempfile.mkdtemp(prefix="dns-github-"))
        auth_url = make_authenticated_url(args.repo, args.token)
        repo_dir = tmpdir / "repo"

        run_git(["clone", "--depth", "1", "--branch", args.branch,
                 auth_url, str(repo_dir)], cwd=tmpdir)

        zone_dir = repo_dir / args.zone_path
        if not zone_dir.is_dir():
            msg = f"zone path '{args.zone_path}' does not exist in the repository"
            print(f"ERROR: {msg}", file=sys.stderr)
            return 1

        zone_file = resolve_zone_file(zone_dir, args.zone_prefix,
                                      args.domain, args.zone_suffix)
        if not zone_file.exists():
            msg = f"zone file not found: {zone_file}"
            print(f"ERROR: {msg}", file=sys.stderr)
            return 1

        original = zone_file.read_text()
        lines = original.splitlines(keepends=True)
        lines = _make_record_lines(args.action, args.domain, args.value, lines)

        modified = "".join(lines)
        if modified == original:
            print("No change needed")
            return 0

        zone_file.write_text(modified)

        run_git(["add", str(zone_file)], cwd=repo_dir)
        run_git([
            "-c", f"user.name={args.git_user}",
            "-c", f"user.email={args.git_email}",
            "commit", "-m", f"dns: {args.action} _acme-challenge.{args.domain}",
        ], cwd=repo_dir)
        run_git(["push", "origin", args.branch], cwd=repo_dir)

        verb = "Added" if args.action == "add" else "Removed"
        print(f"{verb} _acme-challenge.{args.domain} and pushed")
        return 0

    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or "").strip() or (exc.stdout or "").strip()
        print(f"ERROR: git command failed: {msg}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
