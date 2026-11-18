# typosquat

**Generate the lookalike domains an attacker would register for your brand, then find out which ones are live.**

Your users type `yourbrand.com` from memory. An attacker buys `yourbrnad.com`, `yourbrand-login.com`
or a Cyrillic twin of it and waits. Defending that space is usually guesswork, because nobody wants
to enumerate a hundred permutations by hand.

`typosquat` generates the whole candidate set deterministically, scores each technique and, if you
ask it to, resolves them so you only look at names that actually exist.

<p>
  <img src="https://img.shields.io/badge/python-3.8%2B-0d1117?style=flat-square&logo=python&logoColor=39D353" alt="python" />
  <img src="https://img.shields.io/badge/runtime%20dependencies-zero-0d1117?style=flat-square" alt="zero dependencies" />
  <img src="https://img.shields.io/badge/network-opt--in-0d1117?style=flat-square" alt="network optional" />
  <img src="https://img.shields.io/badge/output-text%20%7C%20json%20%7C%20csv-0d1117?style=flat-square" alt="formats" />
  <img src="https://img.shields.io/badge/license-MIT-0d1117?style=flat-square" alt="MIT" />
</p>

## Why

Brand protection lists in most organisations are a spreadsheet someone updates after an incident.
The permutations are mechanical, so they should be generated, not remembered. And the only candidate
worth acting on is the one that resolves, which is exactly the part a spreadsheet cannot tell you.

## Install

One file, standard library only.

```bash
git clone https://github.com/mehulpatel23b-pixel/typosquat.git
cd typosquat
python3 typosquat.py --help
```

## Usage

```bash
# generate only, no network
python3 typosquat.py example.com

# resolve the candidates and show only registered ones
python3 typosquat.py example.com --check --live-only

# a blocklist for the mail gateway or proxy
python3 typosquat.py --watchlist brands.txt --format csv --out typos.csv

# CI: fail when a high-severity lookalike is registered
python3 typosquat.py --watchlist brands.txt --check --fail-on high --format json
```

Sample output:

```text
typosquat 1.0.0
brand(s)   : example.com
candidates : 183   high 22  medium 150  low 10
dns        : 4 registered (of 183 checked)

SEVERITY  TECHNIQUE        DOMAIN                                     LIVE
--------------------------------------------------------------------------------------------
HIGH      homoglyph        3xample.com                                yes
MEDIUM    combosquat       example-login.com                          yes
```

## Techniques

| Technique | Severity | What it produces |
| :-- | :-- | :-- |
| `homoglyph` | high | `3xample.com`, `examp1e.com`, `exarnple.com` |
| `transposition` | high | two adjacent characters swapped: `eaxmple.com` |
| `omission` | high | one character dropped: `eample.com` |
| `cyrillic` | high | a Cyrillic twin encoded to punycode (`xn--...`) |
| `repetition` | medium | one character doubled: `eexample.com` |
| `hyphenation` | medium | `ex-ample.com` |
| `tld-swap` | medium | the same label on 29 other TLDs |
| `combosquat` | medium | `example-login.com`, `secure-example.com`, `examplebilling.com` |
| `bitsquat` | medium | one bit flipped: catches hardware and typo-corruption mistakes |
| `keyboard` | low | adjacent key on a QWERTY row |

Multi-part suffixes are understood: `example.co.uk` keeps its structure when the TLD is swapped.

## Output

- `--format text` for reading, `json` for pipelines, `csv` for import into a blocklist.
- `--out FILE` writes the result and keeps stdout clean, so it is safe inside an automation step.
- `--limit N` caps the candidate set for a quick look.

## Gate

`--check` is required for the gate to mean anything. `--fail-on high` returns 1 only when a
**registered** candidate is high severity. With no `--check`, the run always exits 0, because
generating a name is not evidence that anyone bought it.

## Exit codes

| Code | Meaning |
| :-- | :-- |
| `0` | Nothing registered at or above `--fail-on`, or no DNS check requested |
| `1` | A registered lookalike meets the threshold |
| `2` | No usable brand input |

## Design

- **Deterministic.** Same brand in, same candidate set out, so diffs between runs are meaningful.
- **Offline by default.** One opt-in network call per candidate, and nothing else leaves the machine.
- **Bounded.** Parallel lookups with a hard socket timeout, so a hostile resolver cannot hang a run.
- **Honest.** No "risk score" theatre: a technique severity plus a real DNS answer.

## Ethics

This maps the names that impersonate **your own** brand. It creates nothing, registers nothing and
does not enumerate other people's trademarks.

## License

MIT. See [LICENSE](LICENSE).
