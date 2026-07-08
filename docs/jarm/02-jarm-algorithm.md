# 02 — The algorithm: ten probes and one hash

JARM is a fixed recipe: **ten specific `ClientHello` variants**, sent in order,
their responses concatenated and fuzzy-hashed. The probes are not random — they
are a carefully chosen matrix that maximises how differently TLS stacks behave.

## The pipeline

```
                 ┌──────────── for each of the 10 probes ────────────┐
  target host ──▶│  build ClientHello  ──▶  TCP:443  ──▶  ServerHello │──▶ token
                 └───────────────────────────────────────────────────┘
                                                                        │  ×10
                                                                        ▼
                          "t0,t1,t2,t3,t4,t5,t6,t7,t8,t9"   (raw, comma-joined)
                                                                        │
                                                                        ▼
                                          jarm_hash()  ──▶  62-char JARM
```

Each **token** captures one probe's answer as:

```
<selected_cipher> | <negotiated_version> | <selected_alpn> | <ext-type-list>
     e.g.   c02b   |   0303                |   h2            | 0000-0017-ff01-...
```

A probe that gets an alert or no answer contributes the empty token `|||`.
If **all ten** are `|||`, the JARM is 62 zeros (server didn't speak TLS the way
any probe expected).

## The ten probes

Each probe is a 7-field spec in our code
(`phantomsignal/scrapers/jarm.py`, `PROBES`):

```
[ tls_version, cipher_list, cipher_order, grease, alpn, version_support, ext_order ]
```

| # | TLS ver | ciphers | cipher order | GREASE | ALPN | supported_versions | ext order |
|---|---------|---------|--------------|--------|------|--------------------|-----------|
| 0 | 1.2 | ALL   | FORWARD     | no  | normal | 1.2 | reverse |
| 1 | 1.2 | ALL   | REVERSE     | no  | normal | 1.2 | forward |
| 2 | 1.2 | ALL   | TOP_HALF    | no  | normal | none | forward |
| 3 | 1.2 | ALL   | BOTTOM_HALF | no  | rare   | none | forward |
| 4 | 1.2 | ALL   | MIDDLE_OUT  | yes | rare   | none | reverse |
| 5 | 1.1 | ALL   | FORWARD     | no  | normal | none | forward |
| 6 | 1.3 | ALL   | FORWARD     | no  | normal | 1.3 | reverse |
| 7 | 1.3 | ALL   | REVERSE     | no  | normal | 1.3 | forward |
| 8 | 1.3 | NO1.3 | FORWARD     | no  | normal | 1.3 | forward |
| 9 | 1.3 | ALL   | MIDDLE_OUT  | yes | normal | 1.3 | reverse |

What each axis probes:

- **cipher order** (`FORWARD`/`REVERSE`/`TOP_HALF`/`BOTTOM_HALF`/`MIDDLE_OUT`) —
  the same ~69 suites presented in five different orders. A server that always
  picks, say, `c02b` when it's present reveals a strict preference; one that picks
  "first acceptable in my order" reveals list position sensitivity. The **choice
  from each ordering** is the richest part of the fingerprint.
- **TLS version** (1.1 / 1.2 / 1.3) — does the stack downgrade, refuse, or
  negotiate? Probe 5 offers only TLS 1.1; probe 8 asks for 1.3 but offers **no
  1.3 ciphers** (`NO1.3`), a contradiction many stacks answer with
  `handshake_failure` (a legitimate, fingerprintable `|||`).
- **GREASE** (probes 4, 9) — tolerance of junk values.
- **rare ALPN** (probes 3, 4) — offering unusual app protocols.
- **ext order** — whether we present extensions/versions forward or reversed;
  affects which the server echoes and in what order.

> Probe 8 returning an **alert** for a strict server is *expected and correct* —
> it is signal, not a bug. During development we confirmed 9/10 probes return a
> `ServerHello` from Google and probe 8 returns `handshake_failure`.

## From tokens to hash (preview)

`jarm_hash` walks the ten tokens and builds the 62-char string in two parts:

```
for each token "cipher|version|alpn|exttypes":
    fuzzy += cipher_code(cipher)   # 2 chars, index into a value-SORTED cipher table
    fuzzy += version_code(version) # 1 char,  a..f from the version nibble
    blob  += alpn + exttypes       # accumulated for the tail hash

fuzzy += sha256(blob).hexdigest()[:32]   # 32-char tail
# 10 probes × 3 chars = 30, + 32 = 62
```

The subtle part — and the reason JARM is easy to get wrong — is that
`cipher_code` indexes a **different, value-sorted** cipher table than the one we
*offered* in the `ClientHello`. Get that wrong and every number in the first 30
chars is off. Details in [04-serverhello-and-hash.md](04-serverhello-and-hash.md)
and [05-implementation-and-validation.md](05-implementation-and-validation.md).

Next: how a single probe `ClientHello` is built byte-by-byte —
[03-clienthello-anatomy.md](03-clienthello-anatomy.md).
