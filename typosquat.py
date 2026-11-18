#!/usr/bin/env python3
"""typosquat - build a lookalike-domain watchlist for the brands you defend.

Given your own domains, generate the domains an attacker would register to catch your
users: one character dropped, two swapped, a homoglyph, a flipped bit, a hyphen, a
different TLD, a "secure-login" prefix.

Generation is offline and deterministic. DNS lookups are opt-in, so the tool never
touches the network unless you ask.

Zero dependencies. Pure standard library.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

__version__ = "1.0.0"

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")

HOMOGLYPHS = {
    "o": ["0"], "l": ["1"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5", "$"],
    "g": ["9"], "t": ["7"], "b": ["8"], "z": ["2"], "m": ["rn"], "w": ["vv"], "d": ["cl"],
    "n": ["rn", "m"], "u": ["v"], "v": ["u"], "c": ["k"], "k": ["c"],
}

CYRILLIC = {
    "a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440",
    "c": "\u0441", "x": "\u0445", "y": "\u0443", "i": "\u0456", "s": "\u0455",
}

TLD_SWAPS = (
    "com", "net", "org", "info", "co", "biz", "xyz", "online", "site", "top", "shop",
    "live", "icu", "club", "app", "dev", "cc", "ws", "link", "click", "support", "help",
    "security", "email", "vip", "pro", "store", "website", "space", "fun",
)

COMBOS = (
    "login", "signin", "secure", "security", "verify", "verification", "account", "accounts",
    "update", "support", "helpdesk", "billing", "invoice", "auth", "portal", "wallet",
    "confirm", "recovery", "unlock", "service", "official", "alert", "notice", "my",
)

TECHNIQUE_SEVERITY = {
    "homoglyph": "high",
    "transposition": "high",
    "omission": "high",
    "cyrillic": "high",
    "repetition": "medium",
    "hyphenation": "medium",
    "tld-swap": "medium",
    "combosquat": "medium",
    "bitsquat": "medium",
    "keyboard": "low",
}

MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "co.jp", "com.au",
    "net.au", "org.au", "co.nz", "co.za", "com.br", "com.mx", "com.tr", "com.sg", "com.hk",
    "co.kr", "com.cn", "com.tw", "com.ar", "com.co", "com.my", "co.id", "com.ph", "com.vn",
}


class DomainError(Exception):
    """Raised for input that is not a usable domain."""


def split_domain(domain):
    """Return (label, suffix) for a domain, honouring common multi-part suffixes."""
    domain = (domain or "").strip().lower().rstrip(".")
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//", 1)[1]
    domain = domain.split("/", 1)[0].split(":", 1)[0]
    domain = domain.lstrip("www.") if domain.startswith("www.") else domain
    parts = domain.split(".")
    if len(parts) < 2 or not all(parts):
        raise DomainError("%r is not a domain (expected something like example.com)" % domain)
    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return parts[-3] if len(parts) > 2 else parts[0], ".".join(parts[-2:])
    return parts[0], ".".join(parts[1:])


def keyboard_neighbours(char):
    for row in KEYBOARD_ROWS:
        if char in row:
            index = row.index(char)
            out = []
            if index > 0:
                out.append(row[index - 1])
            if index < len(row) - 1:
                out.append(row[index + 1])
            return out
    return []


def bitsquat(char):
    """Characters one bit away from this one: a known attack on typed domains."""
    out = []
    code = ord(char)
    for bit in (1, 2, 4, 8, 16, 32):
        flipped = chr(code ^ bit)
        if flipped.isalnum() and flipped != char and not flipped.isupper():
            out.append(flipped)
    return out


def cyrillic_form(label):
    """Punycode form of the label with one Latin char swapped for a Cyrillic twin."""
    variants = []
    for index, char in enumerate(label):
        twin = CYRILLIC.get(char)
        if not twin:
            continue
        mixed = label[:index] + twin + label[index + 1:]
        try:
            encoded = mixed.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            continue
        if encoded.startswith("xn--"):
            variants.append(encoded)
    return variants


def generate(label, suffix):
    """All lookalike variants for one label/suffix pair, as (domain, technique)."""
    out, seen = [], set()

    def add(candidate, technique):
        candidate = candidate.strip(".-")
        if not candidate or candidate == label:
            return
        domain = "%s.%s" % (candidate, suffix)
        if domain in seen or len(candidate) < 2:
            return
        seen.add(domain)
        out.append((domain, technique))

    for index in range(len(label)):
        add(label[:index] + label[index + 1:], "omission")

    for index in range(len(label) - 1):
        swapped = label[:index] + label[index + 1] + label[index] + label[index + 2:]
        add(swapped, "transposition")

    for index, char in enumerate(label):
        for alt in HOMOGLYPHS.get(char, []):
            add(label[:index] + alt + label[index + 1:], "homoglyph")
        for alt in keyboard_neighbours(char):
            add(label[:index] + alt + label[index + 1:], "keyboard")
        for alt in bitsquat(char):
            add(label[:index] + alt + label[index + 1:], "bitsquat")
        add(label[:index] + char + char + label[index + 1:], "repetition")

    for index in range(1, len(label)):
        add(label[:index] + "-" + label[index:], "hyphenation")

    for variant in cyrillic_form(label):
        add(variant, "cyrillic")

    if "." in suffix:
        head = suffix.split(".")[0]
        for tld in TLD_SWAPS:
            if tld != head:
                domain = "%s.%s.%s" % (label, head, tld)
                if domain not in seen:
                    seen.add(domain)
                    out.append((domain, "tld-swap"))
    else:
        for tld in TLD_SWAPS:
            if tld != suffix:
                domain = "%s.%s" % (label, tld)
                if domain not in seen:
                    seen.add(domain)
                    out.append((domain, "tld-swap"))

    for word in COMBOS:
        add("%s-%s" % (label, word), "combosquat")
        add("%s-%s" % (word, label), "combosquat")
        add(label + word, "combosquat")

    result, emitted = [], set()
    for domain, technique in out:
        if domain in emitted or domain == "%s.%s" % (label, suffix):
            continue
        emitted.add(domain)
        result.append({"domain": domain, "technique": technique,
                       "severity": TECHNIQUE_SEVERITY.get(technique, "low"), "live": None})
    return result


def resolves(domain, timeout=2.5):
    """True when the name resolves. Opt-in only: this is the single network call."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return False
    finally:
        socket.setdefaulttimeout(previous)


def check_live(variants, workers=24):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        answers = list(pool.map(lambda v: resolves(v["domain"]), variants))
    for variant, alive in zip(variants, answers):
        variant["live"] = bool(alive)
    return variants


def build(brands, limit=None):
    results, errors = [], []
    for brand in brands:
        try:
            label, suffix = split_domain(brand)
        except DomainError as exc:
            errors.append(str(exc))
            continue
        for variant in generate(label, suffix):
            variant["brand"] = "%s.%s" % (label, suffix)
            results.append(variant)
    results.sort(key=lambda v: (SEVERITY_ORDER[v["severity"]], v["brand"], v["domain"]))
    if limit:
        results = results[:limit]
    return results, errors


def summary(variants, brands):
    counts = {sev: sum(1 for v in variants if v["severity"] == sev)
              for sev in ("high", "medium", "low", "info")}
    live = [v for v in variants if v.get("live")]
    checked = any(v.get("live") is not None for v in variants)
    return {
        "brands": brands,
        "candidates": len(variants),
        "checked": checked,
        "live": len(live),
        "live_high": sum(1 for v in live if v["severity"] == "high"),
        "counts": counts,
        "techniques": sorted({v["technique"] for v in variants}),
    }


def render(payload):
    s, lines = payload["summary"], []
    lines.append("typosquat %s" % __version__)
    lines.append("brand(s)   : %s" % ", ".join(s["brands"]))
    lines.append("candidates : %d   high %d  medium %d  low %d"
                 % (s["candidates"], s["counts"]["high"], s["counts"]["medium"], s["counts"]["low"]))
    if s["checked"]:
        lines.append("dns        : %d registered (of %d checked)" % (s["live"], s["candidates"]))
    else:
        lines.append("dns        : not checked (pass --check to resolve)")
    lines.append("")
    lines.append("%-9s %-16s %-42s %s" % ("SEVERITY", "TECHNIQUE", "DOMAIN", "LIVE"))
    lines.append("-" * 92)
    shown = 0
    for variant in payload["variants"]:
        if s["checked"] and not variant["live"]:
            continue
        lines.append("%-9s %-16s %-42s %s"
                     % (variant["severity"].upper(), variant["technique"],
                        variant["domain"][:42], "yes" if variant["live"] else "-"))
        shown += 1
        if shown >= (payload.get("shown_limit") or 40) and not s["checked"]:
            break
    if s["checked"] and shown == 0:
        lines.append("no registered lookalikes in this candidate set")
    lines.append("")
    lines.append("register the high-severity names defensively, or add them to your blocklist.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="typosquat",
        description="Generate the lookalike domains an attacker would register for your brand.")
    parser.add_argument("brands", nargs="*", help="domain(s) you own, e.g. example.com")
    parser.add_argument("--watchlist", help="file with one brand domain per line")
    parser.add_argument("--check", action="store_true", help="resolve each candidate over DNS (network)")
    parser.add_argument("--workers", type=int, default=24, help="parallel DNS lookups (default 24)")
    parser.add_argument("--limit", type=int, help="keep only the first N candidates")
    parser.add_argument("--format", default="text", choices=["text", "json", "csv"], help="output format")
    parser.add_argument("--out", help="write results to this file instead of stdout")
    parser.add_argument("--live-only", action="store_true", help="only report domains that resolve")
    parser.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "none"],
                        help="fail when a registered candidate is at least this severe (needs --check)")
    parser.add_argument("--version", action="version", version="typosquat " + __version__)
    args = parser.parse_args(argv)

    brands = list(args.brands)
    if args.watchlist:
        try:
            with open(args.watchlist, "r", encoding="utf-8") as handle:
                brands.extend(line.strip() for line in handle if line.strip() and not line.startswith("#"))
        except OSError as exc:
            sys.stderr.write("typosquat: %s\n" % exc)
            return 2
    if not brands:
        parser.print_usage(sys.stderr)
        sys.stderr.write("typosquat: give at least one brand domain, or --watchlist FILE\n")
        return 2

    variants, errors = build(brands, limit=args.limit)
    if errors:
        for err in errors:
            sys.stderr.write("typosquat: %s\n" % err)
    if not variants:
        sys.stderr.write("typosquat: no candidates generated\n")
        return 2

    if args.check:
        variants = check_live(variants, workers=args.workers)
    if args.live_only:
        variants = [v for v in variants if v.get("live")]

    payload = {"summary": summary(variants, brands), "variants": variants, "shown_limit": 40}
    if errors:
        payload["errors"] = errors

    if args.format == "json":
        text = json.dumps(payload, indent=2, sort_keys=True)
    elif args.format == "csv":
        rows = ["domain,brand,technique,severity,live"]
        rows.extend("%s,%s,%s,%s,%s" % (v["domain"], v.get("brand", ""), v["technique"],
                                        v["severity"], "" if v["live"] is None else int(v["live"]))
                    for v in variants)
        text = "\n".join(rows)
    else:
        text = render(payload)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(text + ("\n" if not text.endswith("\n") else ""))
        except OSError as exc:
            sys.stderr.write("typosquat: %s\n" % exc)
            return 2
        sys.stderr.write("typosquat: wrote %d candidates to %s\n" % (len(variants), args.out))
    else:
        print(text)

    if args.fail_on == "none" or not args.check:
        return 0
    if args.fail_on == "high":
        return 1 if payload["summary"]["live_high"] else 0
    limit = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[v["severity"]] <= limit for v in variants if v.get("live")) else 0


if __name__ == "__main__":
    sys.exit(main())
