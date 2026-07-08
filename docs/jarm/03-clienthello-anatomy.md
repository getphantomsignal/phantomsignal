# 03 — A probe ClientHello, byte by byte

This is the part that has to be **exactly** right. A server validates every length
field; one wrong byte and it replies with a `decode_error` alert instead of a
`ServerHello`, and the probe silently becomes `|||`. (That's precisely how our
first attempt failed — see
[05-implementation-and-validation.md](05-implementation-and-validation.md).)

We build the hello inside-out: extensions → cipher list → hello body → handshake
→ record. Code references are to `phantomsignal/scrapers/jarm.py`.

## Outer framing

```
record:     16 03 0v  LL LL   <handshake>
                       └────┴── length of <handshake>
handshake:  01  00 LL LL      <clienthello_body>
             │  └───┴───────── 3-byte length of body
             └──────────────── 0x01 = ClientHello
```

`build_client_hello()` assembles the body, then wraps it:

```python
handshake = b"\x01" + b"\x00" + struct.pack(">H", len(ch)) + ch
return      b"\x16" + record_ver + struct.pack(">H", len(handshake)) + handshake
```

Note the two version fields differ for TLS 1.3 probes: the **record** version is
`0x0301` but the **hello** `legacy_version` is `0x0303` — 1.3 is really negotiated
via the `supported_versions` extension, a compatibility quirk JARM reproduces.

## The hello body

```python
ch  = hello_ver + os.urandom(32)          # legacy_version + 32-byte random
ch += b"\x20" + os.urandom(32)            # session_id: length 0x20 (32) + bytes
ch += struct.pack(">H", len(ciphers)) + ciphers
ch += b"\x01\x00"                         # compression: 1 method, null
ch += get_extensions(host, probe)
```

```
┌──────────┬───────────┬──────────┬───────────┬──────────────┬──────┬──────────────┐
│ 03 03    │ random×32 │ 20 id×32 │ len ciph. │  ciphers…    │ 01 00│ extensions…  │
└──────────┴───────────┴──────────┴───────────┴──────────────┴──────┴──────────────┘
```

## The cipher list

Start from one of two fixed lists (`ALL` = 69 suites, or `NO1.3` = the same minus
the five `13xx` TLS-1.3 suites), reorder per the probe, then optionally prepend a
GREASE value:

```python
ciphers = list(_CIPHERS_ALL if probe[1] == "ALL" else _CIPHERS_NO13)
if probe[2] != "FORWARD":
    ciphers = cipher_mung(ciphers, probe[2])   # REVERSE / TOP_HALF / …
if probe[3] == "GREASE":
    ciphers.insert(0, _grease())
```

`cipher_mung` **must** match the reference exactly. The non-obvious ones:

```
TOP_HALF     = [middle cipher if odd] ++ BOTTOM_HALF(REVERSE(list))
BOTTOM_HALF  = list[n//2 + 1 :]  when n is odd   (skips the middle element!)
             = list[n//2 :]      when n is even
MIDDLE_OUT   = center, then walk outward: right, left, right, left, …
```

Worked example on `[1,2,3,4,5,6,7]` (odd, n=7):

```
REVERSE      → 7 6 5 4 3 2 1
BOTTOM_HALF  → 5 6 7            (index 4.. ; the middle '4' is dropped)
TOP_HALF     → 4 3 2 1          ([middle 4] ++ BOTTOM_HALF(REVERSE))
MIDDLE_OUT   → 4 5 3 6 2 7 1
```

Getting `TOP_HALF`/`BOTTOM_HALF` wrong is bug #1 from our validation writeup.

## The extensions block

`get_extensions()` concatenates these in this **exact order** (order is part of
what the server echoes, so it matters):

```
[GREASE 0000]         only on GREASE probes
server_name (SNI)     0000  — the target host
extended_master_secret 0017 0000
max_fragment_length   0001 0001 01
renegotiation_info    ff01 0001 00
supported_groups      000a 000a 0008 001d 0017 0018 0019
ec_point_formats      000b 0002 0100
session_ticket        0023 0000
ALPN                  0010 …            — normal or RARE set, maybe reversed
signature_algorithms  000d 0014 0012 0403 0804 0401 0503 0805 0501 0806 0601 0201
key_share             0033 …            — x25519 + 32 random bytes (+GREASE)
psk_key_exchange_modes 002d 0002 0101
supported_versions    002b …            — ONLY if TLS_1.3 probe OR 1.2_SUPPORT
```

Two of these are conditional/variable and are where bugs #2 and #3 lived:

### ALPN (`0x0010`)

```python
if probe[4] == "RARE_APLN":
    alpns = [http/0.9, http/1.0, spdy/1, spdy/2, spdy/3, h2c, hq]      # no http/1.1, no h2
else:
    alpns = [http/0.9, http/1.0, http/1.1, spdy/1, spdy/2, spdy/3, h2, h2c, hq]
if probe[6] != "FORWARD":
    alpns = cipher_mung(alpns, probe[6])     # reversed for REVERSE ext-order
```

Layout: `0010  <total_len>  <list_len>  (len,proto)…`, each proto prefixed by a
1-byte length (`08 http/1.1`).

### supported_versions (`0x002b`) — conditional

```python
if probe[0] == "TLS_1.3" or probe[5] == "1.2_SUPPORT":
    tls = ["0301","0302","0303"]            if 1.2_SUPPORT else
          ["0301","0302","0303","0304"]     # + 1.3
    if probe[6] != "FORWARD":
        tls = cipher_mung(tls, probe[6])     # reorder the version list too
    body = (grease?) + tls…
    ext  = 002b <len+1> <len> body
```

**Emitting this on `NO_SUPPORT` probes (2, 3, 4, 5) was bug #2** — it changes the
hello the contradiction probes send, so the server answers differently and the
fingerprint drifts. It must be *omitted* for those probes.

### key_share (`0x0033`)

```
0033 <len+2> <len> [GREASE 0001 00]  001d 0020 <32 random bytes>
                                      │    │    └ the ephemeral key
                                      │    └───── key length 0x20 = 32
                                      └────────── group 0x001d = x25519
```

---

Once every length field lines up, real servers answer with a `ServerHello`.
Parsing that reply and turning ten of them into the hash is next:
[04-serverhello-and-hash.md](04-serverhello-and-hash.md).
