# 05 — Implementation, the three silent bugs, and validation

This page maps the algorithm to our code, records the three bugs that make JARM
*look* right while being wrong, and shows how we proved the implementation
canonical without a paid Shodan key.

## Code map

Everything is in `phantomsignal/scrapers/jarm.py`. Pure (unit-tested) vs. I/O:

| Function | Role | Pure? |
|----------|------|-------|
| `PROBES` | the 10-probe matrix | data |
| `cipher_mung(list, mode)` | reorder cipher/alpn/version lists | ✅ |
| `_get_ciphers(probe)` | pick list, reorder, add GREASE | ✅ |
| `_ext_sni/_ext_alpn/_ext_key_share/_ext_supported_versions` | build extensions | ✅ |
| `_get_extensions(host, probe)` | assemble the extension block | ✅ |
| `build_client_hello(host, probe)` | full TLS record for one probe | ✅ |
| `read_server_hello(data)` | ServerHello → `cipher|version|alpn|exts` token | ✅ |
| `_cipher_code/_version_code` | encode a token field for the hash | ✅ |
| `jarm_hash(raw)` | ten tokens → 62-char JARM | ✅ |
| `_probe(...)` / `compute_jarm(...)` | the socket send/recv driver | ❌ (network) |

Integration: `scrapers/infra_pivot.py` calls `compute_jarm(host)` in an executor,
emits a `jarm_fingerprint` result, and pivots via Shodan `ssl.jarm:<hash>`.

## The three bugs that fail silently

Our **first** attempt returned all-zeros — the server rejected every hello with a
`decode_error` alert. Debugging revealed a family of mistakes that split into two
classes: ones that break packets loudly, and ones that corrupt the hash quietly.

### Bug #1 — malformed extensions (loud: `decode_error`)

The first port had a fabricated `000c000000` extension, wrong bytes for
`ec_point_formats` and `signature_algorithms`, and was **missing**
`extended_master_secret`, `max_fragment_length`, `renegotiation_info`, and
`psk_key_exchange_modes`. Result: every length field downstream was off, the
server couldn't parse the hello, and sent:

```
15 03 01 00 02 02 32     ← alert, level 2 (fatal), description 0x32 = 50 = decode_error
```

Fix: the exact extension set and order in
[03-clienthello-anatomy.md](03-clienthello-anatomy.md). Verification signal: the
server switches from an **alert** to a **ServerHello**.

```
probe 0 TLS_1.2 FORWARD     : SERVERHELLO
…
probe 8 TLS_1.3 FORWARD     : ALERT(40)   ← expected: 1.3 asked, no 1.3 ciphers offered
probe 9 TLS_1.3 MIDDLE_OUT  : SERVERHELLO
```

9/10 `ServerHello` + probe 8 `handshake_failure` (alert 40) is the *correct*
outcome for a strict server.

### Bug #2 — `supported_versions` sent unconditionally (quiet)

The extension must be emitted **only** when `probe[0] == "TLS_1.3"` or
`probe[5] == "1.2_SUPPORT"`. Sending it on the `NO_SUPPORT` probes (2, 3, 4, 5)
changes what those probes ask, so the server answers differently. Packets are
still accepted — the fingerprint is just wrong.

### Bug #3 — hashing with the wrong cipher table (quiet)

`cipher_code` must index the **value-sorted** `_CIPHER_HASH` table, not the
offer-order cipher list. With the wrong table, `c02b` encodes as `16` instead of
`27`, so **every** cipher position in the first 30 chars is off. This is the
nastiest bug: output is deterministic, well-formed, 62 chars — and matches no
other JARM implementation, silently defeating the whole point (pivoting).

> Bugs #2 and #3 are why "it runs and produces a hash" is **not** evidence of
> correctness. JARM is only useful if it equals everyone else's JARM.

## How we validated without Shodan search

The Shodan key on file is free-tier (both host lookup and `ssl.jarm:` search are
membership-gated), so we validated two other ways:

1. **Byte-for-byte against the canonical reference.** We fetched the Salesforce
   `jarm.py` and diffed our cipher lists, `cipher_mung`, extension bytes/order,
   `read_packet` offsets, and `jarm_hash` against it. Bugs #2 and #3 were found
   this way.

2. **Against the documented Google fingerprint.** Google's JARM is widely
   published with the cipher/version prefix `27d40d40d29d40d1dc42d43d00041d…`.
   Our implementation reproduces it exactly:

   ```python
   >>> from phantomsignal.scrapers.jarm import compute_jarm
   >>> compute_jarm("www.google.com")
   '27d40d40d29d40d1dc42d43d00041ded961c16c68658e95145597cf992c36c'
   #  └──────── matches the canonical prefix ────────┘
   ```

   The 32-char tail can vary slightly with a host's live extension set, but the
   30-char cipher/version prefix is stack-canonical and matched on the first
   fully-corrected run.

## Tests

`tests/test_jarm.py` locks the pure logic against regressions:

- `cipher_mung` REVERSE/TOP_HALF/BOTTOM_HALF/MIDDLE_OUT on odd and even lists
  (the exact orderings from [03](03-clienthello-anatomy.md)).
- `_cipher_code` uses the sorted table (`0004`→`01`, `1305`→`45`); `_version_code`
  maps `0303`→`d`.
- `jarm_hash`: all-fail → 62 zeros; a crafted 10-token raw → correct 30-char
  prefix + 32-char hex tail.
- `build_client_hello`: every probe frames a valid record (`0x16` … `0x01`) whose
  declared length matches the bytes.
- `read_server_hello`: rejects empty input, alerts, and non-ServerHello records.

## Operational notes

- JARM is **active** — it opens ten TCP connections to `:443`. Only run it against
  hosts you're authorised to test (the same scope as the rest of PhantomSignal).
- It's fast but not free; the module runs the blocking socket work in an executor
  so it doesn't stall the async pipeline.
- A 62-zero result means "no probe elicited a parseable ServerHello" — the host
  may not serve TLS on that port, may be down, or may be very non-standard.

## References

- Salesforce JARM — <https://github.com/salesforce/jarm> (algorithm this is a
  clean-room port of)
- Easily Identify Malicious Servers with JARM (original writeup) —
  <https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a>
- RFC 8701 — GREASE
