# PhantomSignal — Locate (Person Geographic Footprint)

> **Legal reminder:** Locate is for **authorized investigative / missing-persons
> OSINT** only. Every person run is framed as a **case** with a purpose and a
> chain-of-custody log. Do not use it to track, surveil, or locate anyone without
> lawful authority. See the [Legal & Ethics](../README.md#️-legal--ethics) section.

Locate reconstructs *where a subject has been* from public and licensed signals —
a **historical footprint**, not live tracking. It aggregates and correlates data
the Profiler already collects, adds honest confidence and corroboration, and
produces a sourced, prioritized area an investigator can hand to law enforcement.

Design spec: [`specs/geo-locate.md`](../specs/geo-locate.md).

---

## Table of Contents

1. [Core principles](#1-core-principles)
2. [Opening a case](#2-opening-a-case)
3. [What gets collected](#3-what-gets-collected)
4. [Adding signals by hand](#4-adding-signals-by-hand)
   - [Known / negative signals](#known--negative-signals)
   - [EXIF location from a photo URL](#exif-location-from-a-photo-url)
5. [Reading the case view](#5-reading-the-case-view)
6. [Confidence, corroboration, conflict](#6-confidence-corroboration-conflict)
7. [Pattern-of-life & the search grid](#7-pattern-of-life--the-search-grid)
8. [Exports & handoff](#8-exports--handoff)
9. [Chain of custody, purge & retention](#9-chain-of-custody-purge--retention)
10. [OPSEC](#10-opsec)
11. [Configuration](#11-configuration)
12. [Limits & tips](#12-limits--tips)

---

## 1. Core principles

- **Every point carries source + timestamp + attribution + confidence.** Nothing
  renders without provenance.
- **Confidence is compound.** A location is only as trustworthy as our certainty
  that the observation is *real* **and** that it belongs to *the subject*.
- **Corroboration beats authority.** Independent agreement raises confidence;
  conflicts are surfaced, never silently resolved.
- **Historical footprint, not live tracking.**
- **Area + confidence, never a false-precision pin.**
- **Passive by default.** No action that tips off the subject; investigation
  egress routes through the stealth client.

---

## 2. Opening a case

Web UI → **Locate** → fill the *open case* form:

| Field | Notes |
|---|---|
| First / Last name | At least one identifier is required |
| Email | Optional; strengthens attribution when it recurs in records |
| Username | Optional; drives social-profile pivots |
| Opened by | Your handle — recorded in the chain of custody |
| Purpose | Free-text case note (e.g. "missing-persons — LE ref #…") |
| Subject is a minor | Extra-sensitive handling flag |

On submit, Locate runs the Profiler against the identifiers (degrading to no-key
public sources when no API keys are set), extracts geo signals, geocodes them,
and opens the case. **The case opens even if collection finds nothing** — you can
add signals by hand afterward.

CLI/API equivalent is not exposed yet; Locate is web-only.

---

## 3. What gets collected

From the Profiler result, Locate extracts attributed [`GeoSignal`](../phantomsignal/intel/geo/signals.py)s:

| Signal (`kind`) | From | Tier |
|---|---|---|
| `exif_gps` | GPS EXIF in the subject's images (fetched + parsed) | hard fix |
| `geotag` / `checkin` | social geotags / check-ins | hard fix |
| `stated_location` | bio "location" fields (Twitter, GitHub, Keybase, Flickr, LinkedIn, Facebook…) | stated |
| `address_record` | people-search addresses | stated |
| `archived_location` | Wayback snapshots of the subject's profiles — flagged **scrubbed** when gone from the current profile | stated |
| `breach_field` | location fields in breach/dark-web data | inferred |
| `area_code` | phone country | inferred |
| `timezone` | profile timezone | inferred |
| `associate` | a known relative/associate's location | inferred |

**EXIF and archived-location capture fetch network resources**, so they run
best-effort through the stealth client and degrade to nothing on failure.
Coordinates are reverse-geocoded to a place so a photo's GPS clusters with named
locations rather than sitting as an isolated pin.

---

## 4. Adding signals by hand

Automatic collection is a starting point. Investigators add signals inline on the
case page (each is logged to the chain of custody).

### Known / negative signals

**Add a known signal** — pick a kind, enter city/region/country and an optional
observed date. Tick **NEGATIVE** to record an *alibi / elimination* ("confirmed
NOT here") — a negative signal removes an area from consideration.

### EXIF location from a photo URL

**Add location from photo (EXIF)** — paste the URL of an image (a posted photo, a
tip, an original file) and Locate fetches it and reads GPS EXIF, adding a hard fix
if present. This is the manual counterpart to automatic EXIF mining, for when you
*have* a specific photo.

- Paste the **direct URL to the image file** (ending in the image, e.g.
  `https://…/IMG_4821.jpg`), not the page it sits on.
- **Most social platforms strip EXIF on upload.** If nothing is found, try the
  **original file** (the camera's copy, a cloud-drive original, an email
  attachment). A "no GPS EXIF found" notice means the file carried no location.
- There is intentionally **no file-upload box** — a URL keeps provenance clean
  (the source is linkable) and avoids storing uploaded files.

---

## 5. Reading the case view

- **Last-known card** — best current estimate: place, ±radius, confidence,
  corroboration count, as-of date. Radius is tight for a corroborated hard fix,
  wide for a lone or coarse signal.
- **Map** (Leaflet) — confidence-graded markers with dashed **uncertainty
  circles** sized to each place's radius. Basemap follows the site light/dark
  theme. Click a candidate area or search-grid row to fly the map to it.
- **Timeline scrubber** — drag to reveal the footprint cumulatively over time;
  ▶ animates it. Shows how the footprint built up.
- **Movement track** — chronological line between timed fixes; a
  **travel-infeasible** leg (implied speed faster than a flight) is drawn **red**
  — one fix is likely wrong, spoofed, or a shared account.
- **Conflicts** — competing high-confidence places and travel-infeasible pairs,
  shown side-by-side rather than averaged away.
- **Candidate areas** — every clustered place, ranked; expand a card to see the
  sourced signals backing it. A **⚑ scrubbed** badge marks an archived location
  removed from the current profile.
- **Signals (sourced)** — every datapoint with its compound confidence
  (`kind × attribution`), source link, and observed date.

---

## 6. Confidence, corroboration, conflict

```
effective   = kind_confidence × attribution_confidence
corroborated = 1 − Π(1 − effectiveᵢ)   over independent signals on the same place
```

- **`kind_confidence`** — how likely the observation is a real location fix
  (hard fix 0.85–1.0, stated 0.5–0.7, inferred 0.2–0.4).
- **`attribution_confidence`** — how sure we are the record is *the subject*, not
  a namesake. Derived per record: an explicit source match wins, otherwise the
  profile's match confidence, adjusted for kind/source directness and boosted
  when a record independently echoes the searched email/username.
- **Corroboration** — independent signals agreeing on a place combine to a higher
  confidence than any one alone.
- **Conflict** — two strong places, or two timed fixes too far apart to travel
  between, are flagged for review.

A perfect EXIF fix on a profile that's only 40% the subject is a ~0.4 location,
**not** a 0.95 one. That is the core correctness rule.

---

## 7. Pattern-of-life & the search grid

Locate classifies each place from its signals' timestamps:

- **home** — night presence or a residential record
- **work** — weekday daytime
- **frequented** — repeat visits without a clear home/work signature
- **seen** — a lone sighting (never over-claimed)

The **search grid** ranks *where to look next* by `confidence × recency ×
pattern-weight` (home > work > frequented > seen); eliminated areas drop out. It
is the deliverable — surfaced in the case view and led in the report export.

---

## 8. Exports & handoff

From the case header:

- **Report** (Markdown) — a sourced, LE-ready writeup: last-known, the prioritized
  search grid, conflicts, a **scrubbed-locations** callout, and every signal with
  source + timestamp + confidence.
- **GeoJSON** / **KML** — the clustered places for mapping tools.

---

## 9. Chain of custody, purge & retention

- **`AuditEvent` chain of custody** — every ingest, manual add, edit, export, and
  delete is logged (what, when, by whom), so the output is defensible.
- **Purge case** (case header) — deletes the case and *all* its signals and audit
  trail; nothing is left behind.
- **Delete signal** (✕ in the signal table) — removes one signal, keeps the case,
  and logs the removal.
- **Minor subjects** — the `minor` flag drives a prominent badge and
  extra-conservative handling.

---

## 10. OPSEC

Locate's outbound calls — people-search, geocoder, profile/archive/image fetches
— leak the *investigator's* interest. They all route through the **stealth
client** (proxy/identity/impersonation honored) and stay **passive** (no
profile-view tip-offs, no contact). The **Identity** tab shows exactly what your
egress presents.

---

## 11. Configuration

`config.yaml` → `geo`:

| Key | Default | Purpose |
|---|---|---|
| `map_tiles` | `true` | Show the Leaflet map (external tiles). Set `false` for a no-external-dependency deployment. |
| `tile_url` | CARTO `light_all` | Light-theme basemap tiles |
| `tile_url_dark` | CARTO `dark_all` | Dark-theme basemap tiles |
| `tile_attribution` | `© OpenStreetMap contributors © CARTO` | Map attribution |

Geocoding uses Nominatim (OpenStreetMap) and is cached (forward + reverse,
including negatives) so re-runs don't re-hit it.

---

## 12. Limits & tips

- **EXIF is usually stripped** by social platforms on upload — original files are
  where GPS survives. This is the single biggest reason an image yields no fix.
- **IP / timezone signals are coarse** — treated as inferred, low-confidence
  region hints, never street-level.
- **Geocoding is best-effort** and rate-limited; a place with no coordinates still
  clusters by name and shows in the signal table, just not on the map.
- **The map needs external tiles** (CARTO) and Leaflet from a CDN. Behind a strict
  network policy, set `geo.map_tiles: false` — everything else still works.
- Locate is **subject-centric** (person → where). The inverse (location → who is
  there) is out of scope by design.
