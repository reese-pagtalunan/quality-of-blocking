# Part 2 — NGFW deny counting for blocked IPs (Palo Alto default)

Companion plan to the [QoB overview](./README.md). Part 1 (black-hole impact) is
[`plan-netflow-counting.md`](./plan-netflow-counting.md). This describes **Part 2**:
count **policy deny events** per honeypot-flagged IP on the NG firewall **without
changing the block pipeline**, by correlating Palo Alto **Traffic logs** (or
equivalent) against the **same authoritative blocked-IP list** held by BHR.

> The blocking plane (Cowrie → STINGAR → BHR → BH router + NGFW EDL) is left
> **unchanged**. BHR is **instantaneous** and sits **upstream of PAN** (~5 min
> EDL refresh; FW blocks up to **7 days**). This adds a parallel **confirmation
> plane** only.

---

## 0. Relationship to the QoB plan (read first)

README (add vs mark) defines two roles:

| Signal | QoB role | Part |
| --- | --- | --- |
| `bh_hits` / `bh_bytes` | **Add** — traffic sunk at BH | Part 1 (`plan-netflow-counting.md`) |
| `fw_deny_count` | **Mark** — `edge_confirmed` + small capped weight | Part 2 (this document) |

Do **not** sum BH bytes and FW bytes for the same packets unless network paths
are proven disjoint. Default: **BH drives `impact_score`; FW drives
`confirmation_score`.**

Part 1 is **implemented** (`qob/join_flows.py`, `qob/ingest/flow_redis.py`,
`lab/`). Part 2 is **planned** (`qob/ingest/fw_denies.py`, etc.).

**Neteng discovery (2026)** resolved path, timing, and BHR scope — see §10.
Still open: exact PAN rule name, Splunk/ES field map, EDL match direction.
Implementation can proceed with CSV fixtures while the remainder completes.

---

## 1. Goal and non-goals

### Goal

- Produce, per blocked IP and per time window, **`fw_deny_count`** (denied
  sessions / log rows) on the STINGAR EDL security rule, attributed to the
  honeypot `indicator_id` from BHR.
- Set **`edge_confirmed = true`** when ≥1 deny is seen while the IP's block
  entry is active.
- Feed **`confirmation_score`** = `w_f · min(fw_deny_count, cap)` (§9 below).

### Non-goals

- No change to Cowrie → STINGAR → BH → FW promotion pipeline.
- No replacement for BH impact measurement (that's Part 1).
- No Threat-log / zone-protection / dataplane-discard counters (not EDL policy
  denies). See `docs/black_hole_blocking.md` Part 1.
- No Palo Alto in containerlab for v1 — test with CSV/Splunk/ES fixtures (like
  Part 1 fixtures before the RTBH lab existed).
- Not using Splunk as the primary **counter** (billions of deny events/month;
  pulls are slow). Use targeted deny queries or PAN API; Splunk is for samples
  and lineage discovery only.

---

## 2. Architecture

```mermaid
flowchart TB
    subgraph CONTROL["Blocking plane (UNCHANGED)"]
        STG["STINGAR"]
        BHR["bhr-site<br/>publist / query_limited"]
        BH["BH router<br/>SDN API, instantaneous"]
        FW["Palo Alto NGFW<br/>EDL ~5 min refresh"]
        STG --> BHR
        BHR --> BH
        BHR --> FW
    end

    subgraph LIST["Authoritative blocked-IP list (join key)"]
        BHR
    end

    subgraph MEASURE["Confirmation plane (NEW)"]
        LOG["PAN Traffic logs<br/>action = deny / drop"]
        SIEM["Splunk or ES<br/>pan-traffic / deny export"]
        CORR["Consumer<br/>join denies ⋈ blocked-IP list<br/>by src_ip + time window"]
        RDS[("Redis<br/>qob:fw_denies / edge_confirmed")]
        LOG --> SIEM --> CORR
        BHR -.-> CORR
        CORR --> RDS
    end

    subgraph SCORE["QoB merge"]
        BH[("Redis<br/>qob:hits (Part 1)")]
        MERGE["per (ip, day)"]
        OUT["impact_score + confirmation_score"]
        BH --> MERGE
        RDS --> MERGE
        MERGE --> OUT
    end
```

### Part 2 pipeline (step by step)

```mermaid
flowchart LR
    PAN["Palo Alto denies"] --> SYS["Syslog → Splunk or ES"]
    SYS --> READ["poll_fw: read new denies<br/>filter rule = STINGAR-EDL"]
    LIST["BHR block list"] --> MATCH["match IP + active window"]
    READ --> MATCH --> COUNT["count per IP per day"]
    COUNT --> REDIS[("qob:fw_denies")]
    REDIS --> FLAG["edge_confirmed"]
```

### Full system — Part 1 + Part 2

```mermaid
flowchart TB
    subgraph DETECT["Detection (unchanged)"]
        COW["Cowrie honeypots"]
        STG["STINGAR"]
        BHR["BHR block list"]
        COW --> STG --> BHR
    end

    subgraph ENFORCE["Enforcement (unchanged)"]
        BH["Black-hole router<br/>upstream of PAN"]
        FW["Palo Alto NGFW<br/>EDL up to 7d"]
        BHR --> BH
        BHR --> FW
    end

    subgraph MEASURE1["Part 1 — BH impact (built)"]
        NF["NetFlow export"]
        GF["goflow2"]
        J1["join_flows.correlate()"]
        R1["Redis qob:hits / qob:bytes"]
        BH --> NF --> GF --> J1
        BHR --> J1 --> R1
    end

    subgraph MEASURE2["Part 2 — FW confirmation (planned)"]
        LOG["PAN Traffic logs"]
        SIEM["Splunk or ES"]
        J2["correlate_fw_denies()"]
        R2["Redis qob:fw_denies"]
        FW --> LOG --> SIEM --> J2
        BHR --> J2 --> R2
    end

    subgraph SCORE["QoB score"]
        MERGE["merge per IP + day"]
        OUT["impact_score + confirmation_score"]
        R1 --> MERGE
        R2 --> MERGE
        MERGE --> OUT
    end
```

---

## 3. What we count (Palo Alto default)

**Log type:** Security policy **Traffic** logs where:

- `action` ∈ `{deny, drop, reset-both, reset-client, reset-server}`
- `rule` = configured STINGAR EDL rule name(s) — the join key to STINGAR intel

**Not in scope:** Threat logs, zone-protection drops, `show counter global`
discards. Those are different enforcement layers (`docs/black_hole_blocking.md`).

**Match field:** `src_ip` by default (source-based RTBH — **confirmed by neteng
2026**). Still confirm the STINGAR EDL rule matches source vs destination on
PAN (§10).

**Lineage:** Bad-actor / EDL feeds include blocks from honeypot and non-honeypot
detections. There is **no** “blocked because of honeypot” flag on the firewall
feed. Attribute `indicator_id` via BHR + Cowrie/STINGAR session data, not from
the deny log alone.

**Granularity:** One Traffic log row ≈ one denied session (exact count; no
sampling scale). Optional `bytes` field stored but **not** added to
`impact_score`.

---

## 4. Correlation rules

Reuse `BlockedSet` from `qob/join_flows.py` (same BHR list, same
`block_start` / `block_end` semantics).

For each deny event:

1. Filter `action` and `rule` against config allowlists.
2. Take attacker IP from `src_ip` (or `dst_ip` if configured).
3. `entry = blocked.match(ip, deny.ts)` — skip if no active block.
4. Bucket `(ip, align_window(deny.ts))`; increment `fw_deny_count`.
5. Attach `indicator_id` from the matched `BlockEntry`.

Post-`removed` denies are excluded (same as Part 1 flow join tests).

**Deduping (optional v1.1):** dedupe on `(src, dst, sport, dport, proto,
sessionid)` if PAN session id is present in ES; otherwise count log rows and
document as a possible overcount.

---

## 5. Data model (additions to `qob/models.py`)

```python
@dataclass(frozen=True)
class FwDenyRecord:
    ts: datetime
    src_ip: str
    dst_ip: str
    action: str
    rule: str
    device_id: str = ""
    bytes: int = 0

@dataclass
class ConfirmationCount:
    ip: str
    window_start: datetime
    window_end: datetime
    fw_deny_count: int = 0
    edge_confirmed: bool = False
    indicator_id: str = ""
```

---

## 6. Repository layout (Part 2 additions)

```text
qob/
  join_fw_denies.py          # correlate() for denies (parallel to join_flows)
  ingest/
    fw_denies.py             # CSV, ES, PAN XML API parsers
    fw_redis.py              # qob:fw_denies:{ip}:{day} + meta
  scoring.py                 # confirmation_score(), qob_raw merge
collectors/
  poll_fw.py                 # scheduled ES / API poll
jobs/
  compute_qob.py             # extend: --source fw, merge bh+fw
config/
  sources.yaml.example       # firewall: rules, es_index, field map
tests/
  fixtures/fw_denies.csv
  test_join_fw.py
```

Part 1 modules stay unchanged; Part 2 is a **parallel ingest path** merged at
score time.

---

## 7. Ingest adapters (priority order)

| Priority | Adapter | When |
| --- | --- | --- |
| 1 | **CSV / JSONL replay** | Tests, Phase 0 sample export |
| 2 | **Splunk** | Duke production default (~30d retention); targeted queries only |
| 3 | **Elasticsearch** | If `stingar-efk` PAN traffic index is still in use post-Forewarned |
| 4 | **PAN XML API** | Backfill or sites without SIEM export |

### 7.1 Splunk (Duke production default)

PAN Traffic denies land in **Splunk** today (~30 days retention). Post-Forewarned
migration status is unclear — confirm with security/data team whether Splunk
remains the deny source or ES replaces it. Ask Hugh about the **SIF feed** for
block lineage exports.

Do **not** pull full-month deny universes (millions/billions of events); neteng
can help with a **narrow export** filtered to STINGAR EDL rule + blocked-IP
sample. Parse into `FwDenyRecord` and reuse `join_fw_denies.correlate()`.

### 7.2 Elasticsearch (if available)

Mirror `qob/ingest/flow_es.py`: push aggregation into ES, read back small
`(ip, window)` buckets. Filter on `action`, `rule.name`, time range, and
blocked source IPs.

Configurable field map (confirm in Phase 0):

```yaml
firewall:
  fields:
    src_ip: source.ip
    dst_ip: destination.ip
    action: event.action      # or pan-os specific field
    rule: rule.name
    timestamp: "@timestamp"
```

### 7.3 PAN XML API (optional)

Async job pattern from `docs/black_hole_blocking.md`:

```text
GET type=log&log-type=traffic&query=(action eq deny) and (rule eq 'STINGAR-EDL')
→ poll job-id → parse XML log entries → FwDenyRecord
```

Poll every 5–15 minutes; respect API rate limits.

### 7.4 CSV fixture schema (tests)

```csv
ts,src,dst,action,rule,device,bytes
2026-06-10T01:05:00Z,203.0.113.50,10.0.0.5,deny,STINGAR-EDL-BLOCK,fw1,800
```

---

## 8. Redis key schema

| Key | Purpose |
| --- | --- |
| `qob:fw_denies:{ip}:{YYYYMMDD}` | INCRBY deny count, TTL ~8d |
| `qob:meta:{ip}` | HSET `edge_confirmed`, `indicator_id`, `fw_last_seen` |
| `qob:fw:cursor` | Poll watermark (ES `search_after` or last timestamp) |

Align TTL with Part 1 (`flow_redis.py`, 8 days for rolling 7-day sums).

---

## 9. Scoring merge

```text
impact_score       = f(bh_hits, bh_bytes)           # Part 1 — unchanged
confirmation_score = w_f · min(fw_deny_count, cap)  # Part 2
edge_confirmed     = fw_deny_count > 0

QoB_raw = impact_score + confirmation_score + …   # other components later
```

Missing FW data → `edge_confirmed = false` (not an error).

**Production expectation (neteng 2026):** BHR/black-hole is **upstream of PAN**
and applies **instantaneously**. PAN EDL refreshes every **~5 minutes** and
holds blocks up to **7 days**. There is a **overlap window** where both BH and
FW block the same IP, but steady-state attacker traffic often never reaches PAN
— so **high BH + zero FW is normal**, not proof that FW is broken.

**Interpretation:**

| BH | FW | Meaning |
| --- | --- | --- |
| High | High | Overlap window or traffic reached PAN before BH; edge confirmed |
| High | Zero | **Expected** when BH upstream is working; FW may not see packets |
| Zero | High | Long-term FW-only stage (BHR entry expired; PAN holds up to 7d) |
| High | Zero for days | Possible EDL sync issue — only if BH impact also dropped |

---

## 10. Discovery checklist

### Resolved (neteng, 2026)

| # | Question | Answer |
| --- | --- | --- |
| 5 | FW promotion lag after BH? | BHR **instantaneous**; PAN EDL **~5 min** refresh. Overlap where both block. |
| 7 | BHR scope for BH and FW? | STINGAR → **BHR output plugin** feeds BH; same intel also drives **bad-actor / EDL** feeds on PAN (mixed sources). **BHR list** remains QoB join key. |
| 8 | Packet path — BH before PAN? | **Yes.** BHR sits **in front of** firewalls. FW denies often **rare/zero** when BH works. |
| — | RTBH direction? | **All source-based** → correlate on `src_ip` (see Part 1). |
| — | BH trigger mechanism? | **Custom SDN API** (replaced ExaBGP); lab still uses ExaBGP stand-in. |
| — | FW block duration? | Up to **7 days** on Palo Alto. |
| — | Honeypot-only blocks? | **No** — bad-actor feeds mix detections. Need Cowrie/STINGAR `indicator_id` lineage. |

### Still open

1. Exact STINGAR EDL **rule name(s)** on PAN / Panorama.
2. EDL matches **source** or **destination** IP? (RTBH is source-based; EDL direction unconfirmed.)
3. Denies logged at full rate (suppression / log forwarding limits)?
4. **Splunk** index/sourcetype and field names for a redacted Traffic deny sample
   (or confirm ES if Forewarned migration moved logs). Ask **Hugh** about **SIF feed**.
5. NAT: outer vs inner IP for `src_ip` in logs.
6. Part 1: NetFlow **sampling rate** and ingress **Null0** accounting on RTBH routers.

**Exit artifact:** Narrow Splunk or ES export of `(action deny) AND (rule = STINGAR-…)`
with 2–3 sample rows for field mapping — not a full-month pull.

---

## 11. Implementation phases

### Phase 2a — Discovery (1 week)

- [x] Path, timing, BHR scope (§10 resolved table).
- [ ] Splunk or ES field map + redacted deny sample (ask Hugh / SIF feed).
- [ ] Exact PAN EDL rule name(s).
- [ ] Confirm non-zero `fw_deny_count` for a known blocked IP **during overlap window** (may be zero outside it).

### Phase 2b — Core (1 week)

- [ ] `FwDenyRecord`, `ConfirmationCount`, `join_fw_denies.correlate()`.
- [ ] `fw_denies.load_csv()` + fixtures + `test_join_fw.py`.
- [ ] `confirmation_score()` in `scoring.py`.

### Phase 2c — SIEM adapter (1 week)

- [ ] `SplunkFwDenySource` or `EsFwDenySource` (whichever is live post-Forewarned).
- [ ] CI replay against captured Splunk/ES JSON export.

### Phase 2d — Collector + Redis (1 week)

- [ ] `fw_redis.py`, `poll_fw.py`, watermarking.
- [ ] Extend `compute_qob` to merge BH + FW JSONL output.

### Phase 2e — PAN API (optional)

- [ ] XML API adapter for non-ES sites.

---

## 12. Pitfalls

1. **Double counting with BH** — same packets may never reach FW if BH drops
   first (confirmed: BH upstream); keep streams separate.
2. **Promotion lag** — BHR instantaneous, PAN ~5 min; correlate using BHR
   `added`/`removed`, not “on FW list now”. FW may hold blocks up to **7 days**
   after BHR entry expires.
3. **Wrong log type** — Threat / zone-protection ≠ EDL confirm.
4. **Session-end logging** — deny may appear minutes after packet; use
   `receive_time` / `@timestamp`.
5. **Log suppression / Splunk volume** — billions of deny events/month; use
   filtered exports, not full pulls. `fw_deny_count` may be a lower bound.
6. **Mixed bad-actor feed** — cannot tell honeypot vs other detection from PAN
   deny alone; join `indicator_id` from BHR/Cowrie.
7. **NAT** — document which IP is scored (§10 open question #5).
8. **Multi-FW** — sum across fleet or dedupe by session id per device.
9. **Forewarned migration** — confirm whether Splunk, ES, or both remain authoritative.

---

## 13. Testing strategy

| Layer | Approach |
| --- | --- |
| Join | `test_join_fw.py` + `fixtures/fw_denies.csv` |
| Adapter | Record/replay Splunk or ES PAN traffic JSON |
| Integration | Weekly CI replay (no live PAN in CI) |
| Validation | Spot-check top confirmed IPs in PAN Traffic log GUI |

No Palo Alto containerlab for v1 (contrast with Part 1 `lab/`).

---

## 14. Config sketch (`config/sources.yaml.example`)

```yaml
firewall:
  vendor: paloalto
  match_field: src_ip
  deny_actions: [deny, drop, reset-both]
  rules:
    - STINGAR-EDL-BLOCK     # exact name TBD — §10
  source: splunk              # splunk | elasticsearch | pan_api | csv
  poll_interval_seconds: 300  # PAN EDL ~5 min refresh
  es_url: https://es.example.edu:9200
  es_index: "pan-traffic-*"
  fields:
    src_ip: source.ip
    dst_ip: destination.ip
    action: event.action
    rule: rule.name
    timestamp: "@timestamp"
```

---

## 15. References

- [README](./README.md) — QoB overview, add vs mark
- [`plan-netflow-counting.md`](./plan-netflow-counting.md) — Part 1 BH impact
- [`docs/black_hole_blocking.md`](./docs/black_hole_blocking.md) — PAN Traffic
  log filters, XML API, STINGAR-EDL correlation (Part 1 NGFW section)
