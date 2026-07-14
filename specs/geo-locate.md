# Geo / Locate — Design Spec (Draft v2)

Status: **draft for review** · Author: the-clipper + Claude · Depends on: Profiler
(`ShadowProfile`, `profile_pivot`, `username_enum`, `doc_metadata`), intel APIs
(Shodan, Censys, people-search, HIBP, darkweb, archive), `ip_geolocation`, and the
stealth HTTP client (`core/http.py`).

> v2 folds in the design-review gaps: compound (attribution-aware) confidence,
> corroboration + conflict handling, movement plausibility / pattern-of-life,
> the handoff deliverable (search grid + export), human-in-the-loop and negative
> signals, chain-of-custody, investigation OPSEC via the stealth client, and the
> place-normalization/geocode mechanics the clustering depends on. Phasing is
> reordered so correctness + the handoff artifact land in Phase 1.

## 1. Summary

One **Geo** capability, two subjects, sharing a signal model, a map + timeline UI,
and the same honest-precision rules:

- **Locate (person)** — *person → geographic footprint*. A geo-aggregation +
  correlation layer over the Profiler, for investigative / missing-persons OSINT
  (Trace Labs model): reconstruct where a subject has been from public + licensed
  signals, and hand a sourced, prioritized area to an investigator or LE.
- **Geo Recon (asset)** — *place → internet-facing assets*. A geocoding + query
  layer over Shodan/Censys geo filters, correlated with existing enrichment.

Both are **aggregation/correlation layers over sources already integrated** — not
new collection. The new engineering is: a signal model with *compound* confidence,
a corroboration/conflict step, a plausibility/pattern engine, a geocoder, the
handoff export, and a map/timeline UI.

**Boundary (stated, not implied):** Locate is **subject-centric** — *person →
where*. The inverse, *location → who is there*, is a surveillance-shaped query and
is **out of scope** for the person pipeline by design. (`Geo Recon` answers
*location → what assets*, which is infrastructure, not people.)

## 2. Goals / Non-goals

**Goals**
- Person footprint reconstruction that is sourced, attribution-aware, and
  **handoff-ready** (export + report an investigator can give to police).
- Geographic infrastructure recon scoped to an authorized target/org.
- Honest precision: area + confidence, never a false-precision pin.

**Non-goals (explicit)**
- Real-time / continuous tracking of a person's current location.
- Street-level precision inferred from IP geolocation.
- *Location → who is there* for people (the surveillance direction).
- Any person Locate run outside an investigative **case** frame.

## 3. Principles — tradecraft that is also the guardrail

1. **Every geo point carries `source + timestamp + attribution + confidence`.**
   No orphan locations; verifiability first.
2. **Confidence is compound** — a location is only as trustworthy as our certainty
   that (a) the observation is real and (b) it belongs to the subject (§6).
3. **Corroboration beats authority** — independent agreement raises confidence more
   than one high-tier signal; **conflict is surfaced, never silently resolved**.
4. **Historical footprint, not live tracking.**
5. **Person subjects are cases** with a chain-of-custody log (§10).
6. **Passive by default** — no action that tips off the subject (profile views,
   direct contact); investigation egress routes through the stealth client (§11).
7. **Render area + confidence, never false-precision pins.**

## 4. Architecture

```
                 ┌─────────────────────────────────────┐
                 │              GeoEngine               │
                 │  geocode/reverse (cached) · distance │
                 │  compound confidence · corroboration │
                 │  conflict · plausibility · patterns  │
                 └───────────────────┬─────────────────┘
      ┌──────────────────────────────┴──────────────────────────────┐
  Locate (person)  ── egress via stealth client, passive ──   Geo Recon (asset)
  subject: Case(ShadowProfile / handle / email)               input: country|city|
  sources: username_enum, profile_pivot, people-search,              zip|lat,lon+r|ASN
           doc_metadata EXIF, archive_miner, HIBP/darkweb,           (+ org/domain scope)
           associate graph                                    geocode → Shodan/Censys
  → GeoSignals (attributed) → corroborate/conflict →            geo query → enrich
    footprint · plausibility · pattern-of-life ·                 (ip_geo, ports/tech)
    last-known+radius · search grid                             → dedupe
      └──────────────────────────────┬──────────────────────────────┘
                        shared GeoSignal model
                        shared map + timeline UI
                        shared export (KML / GeoJSON / report)
```

Locate plugs in as a Profiler action (a `Case` operating on a `ShadowProfile`),
running its collectors through the async engine the same way `origin_pivot` does.

## 5. Data model

### `GeoSignal` — one row per located observation

| field | notes |
|---|---|
| `id`, `subject_id` | subject = `ShadowProfile` id (person) or scan id (asset) |
| `case_id` | for person subjects, the owning `Case` |
| `kind` | `exif_gps` / `geotag` / `checkin` / `stated_location` / `address_record` / `archived_location` / `news_mention` / `breach_field` / `associate` / `asn_region` / `timezone` / `area_code` / `bssid` |
| `polarity` | `positive` \| `negative` (negative = "confirmed **not** here" — alibi/elimination) |
| `entry` | `auto` \| `manual` (investigator-added, e.g. a witness tip) |
| `lat`, `lon` | nullable — absent for coarse signals; **stored rounded to match confidence** (§12) |
| `place_id` | FK to a canonical `Place` (normalized — §12) |
| `source`, `source_url` | which module/API + link back |
| `observed_at` | timestamp of the *signal* when known (not the collection run) |
| `kind_confidence` | 0..1 from `kind` (§6) |
| `attribution_confidence` | 0..1 — certainty the signal belongs to the subject |
| `corroborated_by` | ids of independent signals agreeing on the same place/time |
| `raw` | JSON provenance blob |

Derived per signal: `effective_confidence` (§6). Not stored raw-only — recomputed
so re-runs and new corroboration update it.

### `Case`, `AuditEvent`, `Place`

- **`Case`**: `subject_id`, `purpose`, `opened_by`, `opened_at`, `status`,
  `sensitivity` (e.g. `minor` flag), `retention_until`.
- **`AuditEvent`** (chain-of-custody): `case_id`, `actor`, `action`, `source`,
  `detail`, `at` — every signal ingested / edited / exported is logged.
- **`Place`** (canonical): normalized name + `{city, region, country, zip}` +
  centroid; many raw strings/coords map to one `Place` (§12).

`ShadowProfile` gains `geo_case` and a computed `last_known_location`
(`{place_id, lat, lon, radius_km, confidence, as_of, corroboration}`).

## 6. Confidence model (compound)

A location's trust is the product of *is it real* and *is it the subject*, then
adjusted by corroboration:

```
effective = kind_confidence × attribution_confidence
corroborated = 1 − Π(1 − effective_i)   over independent signals on the same place
```

`kind_confidence` tiers:

| tier | conf | kinds |
|---|---|---|
| hard fix | 0.85–1.0 | `exif_gps`, `geotag`, `checkin`, `bssid` |
| stated | 0.5–0.7 | `stated_location`, `address_record`, `archived_location`, `news_mention` |
| inferred | 0.2–0.4 | `asn_region`, `timezone`, `area_code`, `breach_field`, `associate` |

`attribution_confidence` comes from the upstream match (e.g. how confidently
`profile_pivot`/`username_enum` tied that profile to the subject). **A perfect EXIF
GPS fix on a profile that is only 40% the subject is a 0.4-ish location, not a
0.95 one** — this is the core correctness rule.

**Conflict:** signals that disagree beyond travel feasibility (§7) are flagged and
shown side-by-side with their provenance; the aggregator never hides a conflict to
present a tidy answer.

## 7. Plausibility & pattern-of-life

- **Travel feasibility:** two positive fixes separated by distance `d` and time
  `Δt` imply a required speed; implausible speed → flag one as suspect (error,
  spoof, or a shared/compromised account) rather than averaging them.
- **Pattern-of-life:** temporal clustering separates **home** (nights/weekends),
  **work** (weekday daytime), and **frequented** places — usually the real payoff,
  and what a prioritized search grid is built from.
- **Negative signals** subtract: a confirmed alibi eliminates an area/time.

## 8. Signal sources (reuse + additions)

| signal | from |
|---|---|
| EXIF GPS | `doc_metadata` (already extracts EXIF geo) |
| geotag / check-in / stated location | `username_enum`, `profile_pivot` |
| address record | people-search APIs (pipl, spokeo, whitepages, intelius, fullcontact) |
| **archived / scrubbed location** | `archive_miner` (Wayback) — a location deleted *after* someone went missing is a strong signal |
| **news / obituary / missing-persons registry** | search APIs — high value for this use case |
| **breach-data location fields** | HIBP / darkweb (already integrated) |
| **associate / relative clustering** | Profiler graph — subjects are usually near known associates |
| asn / timezone | `ip_geolocation`, session artifacts |
| **RIR/whois registrant address, MX geo** | (asset side) whois, mail records |
| **BSSID / Wi-Fi** | WiGLE — RF angle; **gated** (sensitive) and opt-in |
| asset location | Shodan / Censys (`ip_geolocation`) |

## 9. The deliverable (Phase 1 — this is the point)

Not a pretty map — an **actionable handoff**:

- **Prioritized search grid / next-area** — ranked candidate areas with confidence
  and the signals backing each, seeded from pattern-of-life + last-known.
- **Export** — **KML / GeoJSON** for mapping tools, and a **sourced report**
  (every datapoint with source + timestamp + confidence) suitable for LE handoff.
- **Last-known card** — place, radius, confidence, as-of, corroboration count.

## 10. Case, chain-of-custody, sensitive data

- A person Locate run **requires a `Case`** (subject + purpose + opener).
- **`AuditEvent` chain-of-custody**: every ingest/edit/export logged — what, when,
  from where, by whom — so the output is defensible.
- **Retention/purge**: `retention_until` per case; explicit delete.
- **Minor subjects**: `sensitivity=minor` flag drives extra-conservative handling
  and a prominent notice (missing-persons work frequently involves minors).

## 11. Investigation OPSEC

Locate's own outbound calls (people-search, geocoder, profile/archive fetches)
leak the *investigator's* interest and egress — so they route through the
**stealth client** (proxy/profile/impersonation honored) and stay **passive**
(no profile-view tip-offs, no contact). The Identity tab already shows the
operator exactly what that egress presents.

## 12. Mechanics the clustering depends on

- **Place normalization** — "NYC" / "New York, NY" / a Manhattan lat-lon
  canonicalize to one `Place` (via geocoder + a normalization pass) so signals
  actually cluster.
- **Geocode caching** — cache forward + reverse geocodes (Nominatim rate limits
  bite immediately).
- **Coordinate rounding** — store/display lat-lon rounded to the signal's
  confidence so precision is never overstated.

## 13. UI

- **Locate case view** (`/profiler/<subject>/locate`): map with
  confidence-graded markers (radius circles for low confidence), a scrubbable
  timeline, a signal table with source links + attribution, a **conflict** panel,
  a **last-known** card, the **search-grid** list, and **export** buttons. Nothing
  renders without a source; manual/negative signals are addable inline.
- **Geo Recon** (`/geo`): geo-identifier form + org/domain scope → shared map +
  summary pipeline.
- **Map**: Leaflet; tile source is an open question (§15).

## 14. Phasing (reordered)

- **Phase 1 — Locate, handoff-ready (correctness + deliverable).**
  `GeoSignal`/`Case`/`Place`/`AuditEvent` models; extraction from existing
  Profiler results; **compound (attribution-aware) confidence + corroboration +
  conflict surfacing**; last-known + radius; **export (KML/GeoJSON + sourced
  report)**; chain-of-custody; egress via the stealth client. *This is the
  credible, defensible core.*
- **Phase 2 — Intelligence layer.** Travel-feasibility, pattern-of-life
  clustering, the **prioritized search grid / next-area** recommendation, and
  **manual + negative** human-in-the-loop signals.
- **Phase 3 — Geo Recon + reach.** Geocoder + Shodan/Censys geo-search;
  additional sources (news/obituary/registry, breach fields, associate
  clustering, RIR/whois + MX geo, WiGLE gated); shared-map polish + heatmap.

## 15. Open questions

1. **Map tiles.** Leaflet needs a tile server; OSM tiles are an external
   dependency (self-containment/CSP concern). Self-host a tile pack, ship static
   maps, or accept the dependency behind a config toggle?
2. **Geocoder hosting.** Nominatim (free, rate-limited) vs self-host vs hosted.
3. **People-search APIs.** Which are keyed/available in practice; per-datapoint
   ToS/compliance.
4. **Last-known / plausibility tuning.** Recency-decay curve, cluster radii, and
   speed thresholds need real cases to calibrate (Trace Labs archives are public).
5. **Attribution source.** Exact shape of the `attribution_confidence` handed up
   from `profile_pivot`/`username_enum` — needs a small contract defined.
