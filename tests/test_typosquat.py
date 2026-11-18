"""Tests for typosquat. Run: python3 -m pytest -q  (no network is used)"""

import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import typosquat as ts  # noqa: E402


def variants_for(domain="example.com"):
    label, suffix = ts.split_domain(domain)
    return {v["domain"]: v for v in ts.generate(label, suffix)}


def test_split_domain_shapes():
    assert ts.split_domain("example.com") == ("example", "com")
    assert ts.split_domain("https://www.example.co.uk/login") == ("example", "co.uk")
    assert ts.split_domain("EXAMPLE.COM.") == ("example", "com")


def test_split_domain_rejects_junk():
    for junk in ("", "localhost", "http://", "a..com"):
        try:
            ts.split_domain(junk)
        except ts.DomainError:
            continue
        raise AssertionError("expected DomainError for %r" % junk)


def test_each_technique_produces_expected_variant():
    found = variants_for()
    assert found["eample.com"]["technique"] == "omission"
    assert found["eaxmple.com"]["technique"] == "transposition"
    assert found["3xample.com"]["technique"] == "homoglyph"
    assert found["ex-ample.com"]["technique"] == "hyphenation"
    assert found["example.net"]["technique"] == "tld-swap"
    assert found["example-login.com"]["technique"] == "combosquat"
    assert found["eexample.com"]["technique"] == "repetition"
    cyrillic = [d for d, v in found.items() if v["technique"] == "cyrillic"]
    assert cyrillic and all(d.startswith("xn--") for d in cyrillic)


def test_no_duplicates_and_brand_never_included():
    label, suffix = ts.split_domain("example.com")
    variants = ts.generate(label, suffix)
    domains = [v["domain"] for v in variants]
    assert len(domains) == len(set(domains))
    assert "example.com" not in domains
    assert len(domains) > 100


def test_severity_mapping_is_applied():
    found = variants_for()
    assert found["eaxmple.com"]["severity"] == "high"
    assert found["example.net"]["severity"] == "medium"


def test_keyboard_and_bitsquat_helpers():
    assert ts.keyboard_neighbours("q") == ["w"]
    assert set(ts.keyboard_neighbours("z")) == {"x"}
    assert ts.keyboard_neighbours("1") == []
    flipped = ts.bitsquat("a")
    assert flipped and all(len(f) == 1 and f.isalnum() for f in flipped)


def test_multi_part_suffix_keeps_structure():
    label, suffix = ts.split_domain("example.co.uk")
    found = {v["domain"]: v for v in ts.generate(label, suffix)}
    assert "example.co.com" in found
    assert found["example.co.com"]["technique"] == "tld-swap"


def test_build_reports_errors_for_bad_brands():
    variants, errors = ts.build(["example.com", "not-a-domain"])
    assert variants and errors
    assert any("not-a-domain" in e for e in errors)


def test_resolves_uses_getaddrinfo(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [("1.2.3.4", 0)])
    assert ts.resolves("example.net") is True

    def boom(*_a, **_k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert ts.resolves("example.net") is False


def test_check_live_marks_variants(monkeypatch):
    monkeypatch.setattr(ts, "resolves", lambda domain, timeout=2.5: domain.endswith(".net"))
    variants = [{"domain": "a.net", "technique": "tld-swap", "severity": "medium", "live": None},
                {"domain": "b.com", "technique": "omission", "severity": "high", "live": None}]
    ts.check_live(variants, workers=2)
    assert [v["live"] for v in variants] == [True, False]


def test_summary_counts(monkeypatch):
    monkeypatch.setattr(ts, "resolves", lambda *a, **k: True)
    variants, _ = ts.build(["example.com"])
    variants = ts.check_live(variants, workers=8)
    data = ts.summary(variants, ["example.com"])
    assert data["checked"] is True
    assert data["live"] == len(variants)
    assert data["live_high"] == data["counts"]["high"]


def test_cli_json_and_csv(capsys):
    assert ts.main(["example.com", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["candidates"] > 100
    assert payload["summary"]["checked"] is False

    assert ts.main(["example.com", "--format", "csv"]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert out[0] == "domain,brand,technique,severity,live"
    assert len(out) > 50


def test_cli_out_file_and_watchlist(tmp_path, capsys):
    watch = tmp_path / "brands.txt"
    watch.write_text("# my brands\nexample.com\n", encoding="utf-8")
    target = tmp_path / "typos.csv"
    assert ts.main(["--watchlist", str(watch), "--format", "csv", "--out", str(target)]) == 0
    assert target.read_text(encoding="utf-8").startswith("domain,brand")


def test_cli_gate_fails_on_registered_high(monkeypatch):
    monkeypatch.setattr(ts, "resolves", lambda *a, **k: True)
    assert ts.main(["example.com", "--check", "--fail-on", "high"]) == 1
    assert ts.main(["example.com", "--check", "--fail-on", "none"]) == 0


def test_cli_live_only_filters(monkeypatch):
    monkeypatch.setattr(ts, "resolves", lambda domain, timeout=2.5: domain == "3xample.com")
    assert ts.main(["example.com", "--check", "--live-only", "--format", "json"]) == 1


def test_cli_requires_input():
    assert ts.main([]) == 2
