"""
Tests for the nsupdate / Kerberos DNS provider.

Validates that the config file writes the INI keys expected by
the certbot-dns-nsupdate plugin, and that the strategy is wired
correctly through the factory.
"""

from pathlib import Path

import pytest

from modules.core.dns_strategies import DNSStrategyFactory, NsupdateStrategy
from modules.core.utils import create_nsupdate_config, _DNS_PROVIDER_CREDENTIALS


pytestmark = [pytest.mark.unit]


def test_nsupdate_strategy_in_factory():
    strategy = DNSStrategyFactory.get_strategy('nsupdate')
    assert isinstance(strategy, NsupdateStrategy)


def test_nsupdate_plugin_name():
    strategy = NsupdateStrategy()
    assert strategy.plugin_name == 'dns-nsupdate'


def test_nsupdate_default_propagation():
    strategy = NsupdateStrategy()
    assert strategy.default_propagation_seconds == 60


def test_nsupdate_credential_fields():
    assert 'nsupdate' in _DNS_PROVIDER_CREDENTIALS
    assert _DNS_PROVIDER_CREDENTIALS['nsupdate'] == ['server', 'principal', 'keytab']


def test_nsupdate_config_writes_plugin_ini_keys(tmp_path, monkeypatch):
    """certbot-dns-nsupdate expects dns_nsupdate_* INI keys."""
    monkeypatch.chdir(tmp_path)

    config_file = create_nsupdate_config(
        server='ns1.example.com',
        principal='host/ns1.example.com@EXAMPLE.COM',
        keytab='dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIGtleXRhYg==',
        nsupdate_cmd='/usr/local/bin/nsupdate',
    )

    assert config_file == Path('letsencrypt/config/nsupdate.ini')
    assert config_file.exists()

    content = config_file.read_text(encoding='utf-8')
    assert 'dns_nsupdate_server = ns1.example.com' in content
    assert 'dns_nsupdate_principal = host/ns1.example.com@EXAMPLE.COM' in content
    assert 'dns_nsupdate_keytab = dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIGtleXRhYg==' in content
    assert 'dns_nsupdate_nsupdate_cmd = /usr/local/bin/nsupdate' in content

    assert config_file.stat().st_mode & 0o777 == 0o600


def test_nsupdate_config_default_nsupdate_cmd(tmp_path, monkeypatch):
    """When nsupdate_cmd is omitted, the INI should contain 'nsupdate'."""
    monkeypatch.chdir(tmp_path)

    config_file = create_nsupdate_config(
        server='ns1.example.com',
        principal='host/ns1.example.com@EXAMPLE.COM',
        keytab='dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIGtleXRhYg==',
    )

    content = config_file.read_text(encoding='utf-8')
    assert 'dns_nsupdate_nsupdate_cmd = nsupdate' in content


def test_nsupdate_strategy_create_config(tmp_path, monkeypatch):
    """NsupdateStrategy.create_config_file must delegate to create_nsupdate_config."""
    monkeypatch.chdir(tmp_path)

    strategy = NsupdateStrategy()
    config_file = strategy.create_config_file({
        'server': 'dns.example.com',
        'principal': 'host/dns.example.com@EXAMPLE.COM',
        'keytab': 'a2V5dGFiIGRhdGE=',
    })

    assert config_file == Path('letsencrypt/config/nsupdate.ini')
    assert config_file.exists()

    content = config_file.read_text(encoding='utf-8')
    assert 'dns_nsupdate_server = dns.example.com' in content
    assert 'dns_nsupdate_principal = host/dns.example.com@EXAMPLE.COM' in content
    assert 'dns_nsupdate_keytab = a2V5dGFiIGRhdGE=' in content
