# 01 — Just enough TLS to understand JARM

You don't need to know all of TLS to follow JARM — you need the handshake's first
two messages and how they're framed on the wire. This page covers exactly that.

## The TLS record layer

Everything TLS sends is wrapped in a **record**. A record is a 5-byte header
followed by a payload:

```
 byte:  0        1   2        3   4       5 ...
       ┌────────┬────────────┬────────────┬───────────────────────┐
       │  type  │  version   │   length   │       payload         │
       │ 1 byte │  2 bytes   │  2 bytes   │   <length> bytes      │
       └────────┴────────────┴────────────┴───────────────────────┘
   type: 0x16 = handshake   0x15 = alert   0x17 = application data
version: 0x0301 = TLS 1.0 … 0x0303 = TLS 1.2  (legacy; real version negotiated in extensions for 1.3)
```

JARM only ever cares about two record types:
- `0x16` **handshake** — carries `ClientHello` (from us) and `ServerHello` (reply).
- `0x15` **alert** — the server rejected us (e.g. `handshake_failure`). JARM treats
  an alert as "no answer" for that probe.

## The handshake message inside the record

A handshake record's payload is itself framed:

```
 byte:  0          1   2   3        4 ...
       ┌──────────┬──────────────┬───────────────────────┐
       │ hs type  │    length    │      hs body          │
       │ 1 byte   │   3 bytes    │   <length> bytes      │
       └──────────┴──────────────┴───────────────────────┘
   hs type: 0x01 = ClientHello   0x02 = ServerHello
```

So the first six bytes of a `ClientHello` packet are always:

```
16 03 03 LL LL   01
│  │     │       └── handshake type 0x01 = ClientHello
│  │     └────────── record length (2 bytes)
│  └──────────────── record version 0x0303
└─────────────────── record type 0x16 = handshake
```

A `ServerHello` reply likewise starts `16 03 03 LL LL 02 …` — and JARM's parser
keys off exactly `data[0] == 0x16 and data[5] == 0x02`.

## What's in a ClientHello body

```
┌─────────────────────────────────────────────────────────────┐
│ legacy_version            2 bytes   (0x0303)                 │
│ random                   32 bytes   (client nonce)           │
│ session_id_len + id      1 + 32     (we send 32 random)      │
│ cipher_suites_len        2 bytes                             │
│ cipher_suites            N bytes     ← JARM scrambles these  │
│ compression (len+null)   2 bytes    (0x01 0x00)              │
│ extensions_len           2 bytes                             │
│ extensions               M bytes     ← JARM tunes these      │
└─────────────────────────────────────────────────────────────┘
```

The two fields JARM manipulates are **cipher_suites** (offer order) and
**extensions**. Everything else is boilerplate.

## Cipher suites

A cipher suite is a 2-byte code for a bundle of crypto choices. Example:

```
c0 2b  =  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
13 01  =  TLS_AES_128_GCM_SHA256   (a TLS 1.3 suite)
```

In a normal hello, the client lists suites in **preference order** and the server
picks the first it supports. JARM sends the same big list but in **weird orders**
(reversed, middle-out, half of it) across different probes. Which suite the server
ends up choosing from each scrambled list is a fingerprint of its selection logic.

## Extensions

After the cipher list, a `ClientHello` carries **extensions** — TLV blobs that
advertise capabilities:

```
┌────────────┬────────────┬─────────────────┐
│  ext type  │  ext len   │    ext data     │
│  2 bytes   │  2 bytes   │  <len> bytes    │
└────────────┴────────────┴─────────────────┘
```

Ones that matter for JARM:
- **`0x0000` server_name (SNI)** — the hostname.
- **`0x0010` ALPN** — which app protocols (h2, http/1.1…) we offer; the server
  echoes its pick. JARM sometimes offers a **rare** ALPN set to see what happens.
- **`0x002b` supported_versions** — how TLS 1.3 is actually negotiated (the record
  `version` stays `0x0303` for compatibility).
- **`0x0033` key_share**, **`0x000d` signature_algorithms**, etc. — standard 1.3
  plumbing JARM includes so real servers answer.

## GREASE

**GREASE** (RFC 8701) is a deliberately-reserved set of "junk" values
(`0x0a0a`, `0x1a1a`, … `0xfafa`) that clients randomly sprinkle into cipher lists
and extensions to keep servers tolerant of unknown values. Well-behaved servers
**ignore** GREASE; broken ones choke. JARM's GREASE probes test that tolerance —
part of the fingerprint is *how* a stack reacts to GREASE.

---

With records, the two hello messages, cipher suites, extensions, and GREASE in
hand, you can read the rest of these docs. Next:
[02-jarm-algorithm.md](02-jarm-algorithm.md).
