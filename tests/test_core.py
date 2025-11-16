import os
import json
import csv
import tempfile
from pathlib import Path
import pytest
import sys

# Ensure project root is on sys.path so tests can import local modules
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from domain_advanced import validate_domain, parse_ports_arg, write_outputs


def test_validate_domain_valid():
    assert validate_domain('example.com') == 'example.com'
    assert validate_domain('http://example.com') == 'example.com'
    assert validate_domain('https://www.example.com') == 'example.com'


def test_validate_domain_invalid():
    with pytest.raises(ValueError):
        validate_domain('not a domain')


def test_parse_ports_arg():
    assert parse_ports_arg('80,443') == [80, 443]
    assert parse_ports_arg('1-3') == [1, 2, 3]
    assert parse_ports_arg('22,100-102') == [22, 100, 101, 102]
    assert parse_ports_arg('') == []
    assert parse_ports_arg('70000') == []  # out of range


def test_write_outputs(tmp_path):
    domain = 'example.com'
    subs = ['a', 'b']
    formats = ['txt', 'json', 'csv']
    out_base = str(tmp_path / 'outbase')
    port_map = {'a': [80, 443], 'b': []}

    paths = write_outputs(domain, subs, formats, out_base, port_map=port_map)
    assert any(p.endswith('.txt') for p in paths)
    assert any(p.endswith('.json') for p in paths)
    assert any(p.endswith('.csv') for p in paths)

    # verify json content
    jpath = [p for p in paths if p.endswith('.json')][0]
    with open(jpath, 'r', encoding='utf-8') as f:
        payload = json.load(f)
    assert payload['domain'] == domain
    assert payload['count'] == 2
    assert isinstance(payload['subdomains'], list)
    assert payload['subdomains'][0]['open_ports'] == [80, 443]

    # verify csv content
    cpath = [p for p in paths if p.endswith('.csv')][0]
    with open(cpath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        rows = list(reader)
    # header + 2 rows
    assert len(rows) >= 3
