"""Certbot DNS authenticator using nsupdate with Kerberos (GSS-TSIG).

Implements RFC 2136 (dynamic DNS updates) via the ``nsupdate`` command
with Kerberos / GSS-TSIG authentication (RFC 3645).

The authenticator accepts a Kerberos keytab as a base64-encoded string,
decodes it to a temporary file, runs ``kinit`` to obtain a ticket-granting
ticket, and then executes ``nsupdate -g`` for each challenge.
"""

import base64
import logging
import os
import subprocess
import tempfile

from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


def _extract_zone(domain: str) -> str:
    """Return the authoritative DNS zone for an ACME challenge domain.

    Strips the ``_acme-challenge.`` prefix and returns the remainder,
    which is the zone name for the ``nsupdate`` ``zone`` directive.
    The correct zone may be longer (e.g. ``sub.example.com`` rather than
    ``example.com``); the operator is responsible for ensuring the
    nsupdate server accepts updates for the correct zone.

    For bare domains without an ``_acme-challenge`` prefix (should not
    happen in practice), return the domain as-is.
    """
    prefix = '_acme-challenge.'
    if domain.startswith(prefix):
        return domain[len(prefix):]
    # wildcard: the challenge domain is _acme-challenge.<zone>
    # and the zone is everything after the first dot.
    dot = domain.find('.')
    if dot != -1 and dot + 1 < len(domain):
        return domain[dot + 1:]
    return domain


class Authenticator(dns_common.DNSAuthenticator):
    """DNS-01 authenticator using nsupdate with Kerberos (GSS-TSIG).

    Credentials file (``--dns-nsupdate-credentials``):

    .. code-block:: ini

        dns_nsupdate_server = dns.example.com
        dns_nsupdate_principal = host/dns-server@EXAMPLE.COM
        dns_nsupdate_keytab = <base64-encoded keytab>
        # dns_nsupdate_nsupdate_cmd = /usr/bin/nsupdate  (optional)

    Generate the base64 keytab::

        kinit -k -t /path/to/keytab principal@REALM
        base64 /path/to/keytab | tr -d '\\n'
    """

    description = 'DNS-01 using nsupdate with Kerberos (GSS-TSIG)'

    def more_info(self) -> str:
        return (
            'Manages ACME DNS-01 TXT records via the nsupdate command '
            'with Kerberos/GSS-TSIG authentication (RFC 2136 + RFC 3645). '
            'The Kerberos keytab is supplied as a base64-encoded string '
            'in the credentials file.'
        )

    @classmethod
    def add_parser_arguments(cls, add):
        super().add_parser_arguments(add, default_propagation_seconds=60)
        add('server',
            help='DNS server hostname (e.g. ns1.example.com)')
        add('principal',
            help='Kerberos principal (e.g. host/dns-server@EXAMPLE.COM)')
        add('keytab',
            help='Base64-encoded Kerberos keytab')
        add('nsupdate-cmd',
            default='nsupdate',
            help='Path to the nsupdate executable (default: nsupdate)')

    def _setup_credentials(self):
        super()._setup_credentials()
        self.credentials.require('server')
        self.credentials.require('principal')
        self.credentials.require('keytab')

    def _perform(self, domain, validation, **kwargs):
        _nsupdate(self.credentials, 'add', domain, validation)

    def _cleanup(self, domain, validation, **kwargs):
        _nsupdate(self.credentials, 'delete', domain, validation)


def _nsupdate(credentials, action, domain, validation):
    """Run nsupdate with GSSAPI authentication.

    Decodes the base64 keytab from the credentials to a temporary file,
    authenticates via ``kinit``, and executes ``nsupdate -g`` with the
    appropriate update script.

    Args:
        credentials: Certbot credentials object (conf).
        action: ``'add'`` or ``'delete'``.
        domain: Full ACME challenge domain (``_acme-challenge.<zone>``).
        validation: The ACME DNS-01 validation token.
    """
    server = credentials.conf('server')
    principal = credentials.conf('principal')
    keytab_b64 = credentials.conf('keytab').strip()
    nsupdate_cmd = credentials.conf('nsupdate-cmd') or 'nsupdate'

    keytab_data = base64.b64decode(keytab_b64)

    keytab_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(keytab_data)
            keytab_path = f.name
        os.chmod(keytab_path, 0o600)

        subprocess.run(
            ['kinit', '-k', '-t', keytab_path, principal],
            check=True, capture_output=True, text=True,
        )

        zone = _extract_zone(domain)
        quoted_validation = validation.replace('"', '\\"')

        if action == 'add':
            directive = f'update add {domain} 60 TXT "{quoted_validation}"'
        else:
            directive = f'update delete {domain} TXT "{quoted_validation}"'

        nsupdate_script = (
            f'server {server}\n'
            f'zone {zone}\n'
            f'{directive}\n'
            f'send\n'
        )

        logger.debug(
            'nsupdate %s for %s (zone=%s, server=%s)',
            action, domain, zone, server,
        )

        subprocess.run(
            [nsupdate_cmd, '-g'],
            input=nsupdate_script,
            check=True, capture_output=True, text=True,
        )

        logger.info('nsupdate %s succeeded for %s', action, domain)

    except base64.binascii.Error as exc:
        raise RuntimeError(
            f'Failed to decode base64 keytab for {principal}: {exc}'
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or '').strip()
        raise RuntimeError(
            f'nsupdate {action} for {domain} failed: {stderr}'
        ) from exc
    except FileNotFoundError as exc:
        raise RuntimeError(
            f'Required command not found: {exc.filename}. '
            f'Ensure nsupdate (bind-utils / bind9-dnsutils) and kinit '
            f'(krb5-user / libkrb5-dev) are installed.'
        ) from exc
    finally:
        if keytab_path:
            try:
                os.unlink(keytab_path)
            except OSError:
                pass
        try:
            subprocess.run(
                ['kdestroy'],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass
