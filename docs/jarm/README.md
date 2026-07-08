# JARM — Active TLS-Stack Fingerprinting, from the inside out

This directory documents PhantomSignal's **from-scratch** JARM implementation
(`phantomsignal/scrapers/jarm.py`) at the byte level. It exists because JARM is
one of those algorithms that is easy to get *almost* right and impossible to
debug by eye — a single wrong cipher-list index yields a fingerprint that looks
valid, is internally consistent, and silently fails to match every other JARM
implementation on Earth. These notes capture exactly how it works and how we
proved ours is canonical.

## What JARM is

JARM is an **active** TLS server fingerprint created by Salesforce. You send a
server **ten deliberately-weird TLS `ClientHello` messages** and record how it
responds to each. The server's choices — which cipher it picks from a scrambled
list, which TLS version it negotiates, which extensions it echoes — are a
function of its TLS **stack and configuration**. Hash those ten responses
together and you get a 62-character fingerprint:

```
27d40d40d29d40d1dc42d43d00041d24a458a375eef0c576d23a7bab9a9fb1   ← example
└──────────── 30 chars ──────────┘└────────── 32 chars ─────────┘
   cipher + version per probe          SHA-256 of ALPN+extensions
```

Two hosts with the **same JARM** are running the same TLS stack the same way —
usually the same load balancer, CDN, framework, or (for defenders) the same
malware C2 kit. That makes JARM a high-signal **infrastructure pivot**:
`ssl.jarm:<hash>` in Shodan/Censys returns siblings.

## Why fingerprint with *malformed-ish* hellos?

A normal `ClientHello` offers ciphers in a sane, preference-ordered list, and any
server picks its favourite — so every server looks similar. JARM instead sends
hellos with ciphers **reversed**, **middle-out**, only the **top/bottom half**,
with **GREASE** injected, with **rare ALPN** values, mixing TLS 1.1/1.2/1.3
version signals. Different TLS implementations resolve these odd inputs
differently and deterministically. The *disagreements* are the fingerprint.

## Read in this order

| Doc | What it covers |
|-----|----------------|
| [01-tls-primer.md](01-tls-primer.md) | Just enough TLS handshake to follow the rest — records, `ClientHello`/`ServerHello`, cipher suites, extensions, GREASE. |
| [02-jarm-algorithm.md](02-jarm-algorithm.md) | The ten probes, what each one varies and why, and the end-to-end data flow. |
| [03-clienthello-anatomy.md](03-clienthello-anatomy.md) | Byte-by-byte construction of a probe `ClientHello`, every extension, with maps. |
| [04-serverhello-and-hash.md](04-serverhello-and-hash.md) | Parsing the `ServerHello` into a token and assembling the 62-char fuzzy hash. |
| [05-implementation-and-validation.md](05-implementation-and-validation.md) | Our code map, the three bugs that make JARM silently wrong, and how we validated against the canonical Google fingerprint. |

## Quick reference

```python
from phantomsignal.scrapers.jarm import compute_jarm
compute_jarm("www.google.com")
# -> '27d40d40d29d40d1dc42d43d00041d...'  (cipher/version prefix is canonical)
```

- **Module:** `phantomsignal/scrapers/jarm.py`
- **Wired into:** the `infra_pivot` module → emits a `jarm_fingerprint` result and
  pivots via Shodan `ssl.jarm:`.
- **Tests:** `tests/test_jarm.py` (cipher reordering, hash encoding, packet
  framing, parser guards).
- **Lineage:** clean-room port of `github.com/salesforce/jarm`, validated
  byte-for-byte on the cipher/version portion against the documented Google JARM.
