# 04 — Parsing the ServerHello and building the hash

Each probe yields a `ServerHello` (or an alert). We distil each into a **token**,
join the ten with commas into a **raw** string, then fuzzy-hash it into the
62-char JARM.

## Parsing one ServerHello → a token

`read_server_hello(data)` extracts four things and formats them as
`cipher|version|alpn|ext-types`.

First, guard: only a handshake record (`0x16`) whose handshake type is
`ServerHello` (`0x02`) is parsed; an alert (`0x15`) or anything else is `|||`.

```python
if not data:                                   return "|||"
if data[0] == 0x15:                            return "|||"   # alert
if not (data[0] == 0x16 and data[5] == 0x02):  return "|||"
```

Then the field offsets. The `ServerHello` layout after the 9-byte
record+handshake preamble is: `version(2) random(32) session_id_len(1)
session_id(var) cipher(2) compression(1) ext_len(2) extensions`. The session id
is variable, so JARM reads its length from `data[43]` and uses it as a `counter`
to reach the later fields:

```
data[9:11]                    → legacy version   (e.g. 0303)
counter = data[43]            → session_id length
data[counter+44 : counter+46] → selected cipher  (e.g. c02b)
data[counter+47 : counter+49] → extensions length
data[counter+49 : …]          → the extensions themselves
```

```
        preamble            random           sid          cipher
   ┌──────────────────┐┌──────────────┐┌───┬─────┐   ┌──────────┐
   16 03 03 LL LL 02 .. 00 .. 33  <32 random>  20 <sid>  <cipher>  00  <extlen>  <exts>
   0                 5  6..8   9,10          43=sidlen   +44/+46        +47/+49    +49…
```

Walk the extension TLVs, collecting their **types** in order and pulling the
server's **selected ALPN** out of the `0x0010` extension:

```python
while count < end:
    t    = data[count:count+2]
    elen = int.from_bytes(data[count+2:count+4], "big")
    types.append(t); values.append(data[count+4:count+4+elen])
    count += elen + 4
alpn    = value of the 0x0010 extension, bytes[3:] decoded   # e.g. "h2"
ext_hex = "-".join(t.hex() for t in types)                   # "0000-0017-ff01-..."
return f"{cipher}|{version}|{alpn}|{ext_hex}"
```

A concrete token from Google probe 0:

```
c02b|0303|h2|002b-0033
 │    │   │   └─ extension types the server echoed, hyphen-joined
 │    │   └──── selected ALPN
 │    └──────── legacy version 0x0303
 └───────────── selected cipher suite
```

## Ten tokens → the fuzzy hash

`jarm_hash(raw)` splits the raw string on commas and processes each token.

### Part A — the 30-char cipher/version prefix (3 chars/probe)

```python
for token in raw.split(","):
    cipher, version, alpn, exttypes = token.split("|")
    fuzzy += cipher_code(cipher)     # 2 chars
    fuzzy += version_code(version)   # 1 char
    blob  += alpn + exttypes         # saved for Part B
```

**`cipher_code` is the trap.** It maps the chosen suite to a number — but it
indexes a **value-sorted** table (`_CIPHER_HASH`), *not* the offer-order list we
put in the `ClientHello`:

```python
_CIPHER_HASH = ["0004","0005","0007","000a","0016","002f","0033", …, "1305"]  # sorted
def cipher_code(cipher):
    if cipher == "": return "00"
    n = 1
    for c in _CIPHER_HASH:
        if c == cipher: break
        n += 1
    return format(n, "x").rjust(2, "0")     # 1-based index, 2 hex chars
```

So `c02b` → position 39 in the sorted table → `27`. Using the *offer* list here
instead gives `16` — a self-consistent but **non-canonical** fingerprint that
matches nobody. This was bug #3.

`version_code` maps the legacy version's last nibble to `a..f`:

```python
def version_code(version):           # "0303" → nibble 3 → "abcdef"[3] → "d"
    return "0" if version == "" else "abcdef"[int(version[3:4])]
```

### Part B — the 32-char extension hash

```python
fuzzy += sha256(blob).hexdigest()[:32]
```

`blob` is every probe's `alpn + ext-types` concatenated in order. Two servers that
echo the same extensions in the same order across all ten probes share this tail.

### The all-fail shortcut

```python
if raw == ",".join(["|||"] * 10):
    return "0" * 62
```

## Putting it together

```
probe tokens:  c02b|0303|h2|002b-0033 , cca9|0303|h2|… , … (×10)
                    │                        │
   Part A ──────────┴── 27 d ── … ──────────┴── …          30 chars
   Part B ── sha256("h2002b-0033h2…")[:32]                  32 chars
                                                            ─────────
   JARM = 27d40d40d29d40d1dc42d43d00041d  +  <32 hex>       62 chars
```

The first 30 chars are stable and human-comparable (Google and Cloudflare share
`27d40d40…` because both front similar TLS stacks); the 32-char tail separates
them by their exact extension behaviour.

Next — how this maps to our code, the bugs, and how we proved it canonical:
[05-implementation-and-validation.md](05-implementation-and-validation.md).
