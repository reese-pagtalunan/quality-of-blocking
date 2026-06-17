# Neteng 1-hour session — golden test prep

Companion to [`plan-netflow-counting.md`](../plan-netflow-counting.md) Phase 0 / Phase 2.
Use this as a runbook before and during your meeting with neteng.

**Goal:** In one hour, prove enough to greenlight production wiring — not perfect accuracy.

---

## The honest answer upfront

> "Everything works as long as I point records to goflow2."

**Partially true.** Pointing export at goflow2 validates the **collector half** of the pipeline. You can still get zero meaningful QoB counts if:

- Flow monitors are not on the right interfaces (uRPF drops never exported)
- The test IP is not on the BHR list during the window
- Sampling rate is unknown or wrong (counts off by 1000×)
- Hardware accounts flows **after** the drop (packets never appear in flow records)

**Your 1-hour target:** nail layers **A + B + a smoke test on C** (below). Defer layer D.

---

## What "everything works" means (four layers)

| Layer | What it proves | Needs goflow2? |
| --- | --- | --- |
| **A. Export reaches goflow2** | Routers → UDP 2055 → JSON lines appear | Yes |
| **B. Consumer + join works** | BHR blocklist ⋈ `src_addr` → Redis `qob:hits:*` | Yes + publist + consumer running |
| **C. Counts are real BH traffic** | Blocked IP traffic shows up in flows *and* router drop counters move | Yes + blocked test IP + router counters |
| **D. Production-ready accuracy** | Known sampling rate, multi-router plan, 1-week replay | Mostly async after the hour |

---

## Before the meeting (do this yourself)

Have **goflow2 and Redis** already running when neteng walks in. Do not spend the hour
installing Docker.

You **do not** need the blocklist before the meeting — that is a neteng discovery item
(see §3 below; **Splunk export is a likely answer**). Start the consumer once you have
`/tmp/publist.csv`, which may be mid-session.

### 1. goflow2

Note the host IP neteng will point routers at.

```bash
docker run -d --name goflow2 -p 2055:2055/udp \
  -v /tmp/goflow2:/var/log/goflow2 \
  netsampler/goflow2:v2.1.5 \
  -listen netflow://:2055 \
  -format json \
  -transport file \
  -transport.file /var/log/goflow2/flows.json
```

### 2. Redis

```bash
docker run -d --name qob-redis -p 6379:6379 \
  redis:7-alpine redis-server --appendonly yes
```

### 3. Blocked-IP list (blocklist) — **you may not have this yet**

The consumer joins flow records against the **blocked-IP list** (BHR `publist.csv` or
equivalent). That list is the authoritative join key for QoB counting.

**If you do not already have a publist URL or file, that is expected.** This repo does
not ship one, and you cannot guess it. **Ask neteng in the first five minutes** where
the live list lives — at many sites it is **not** a public BHR URL but a **Splunk
search or saved export** (block lineage, STINGAR/BHR events, SIF feed, etc.).

#### Where the blocklist might live (ask neteng to pick one)

| Source | What to ask for | Golden-test use |
| --- | --- | --- |
| **BHR `publist.csv`** | Hostname + URL (or `query_limited` API + token) | `curl` → `/tmp/publist.csv` |
| **Splunk** (common) | Index, sourcetype, field names for **current RTBH/BHR blocks** (not PAN denies) | Export search results → CSV → `/tmp/publist.csv` |
| **On-the-spot snapshot** | Neteng or security exports from BHR UI / internal API | Copy file → `/tmp/publist.csv` |

**Splunk vs BHR URL:** Splunk is often where operators *query* "what is blocked right
now" even when BHR is the system of record. For this session you only need a **CSV
snapshot** the consumer can read — the lab does not connect to Splunk live.

**Do not confuse two different Splunk uses:**

| Splunk role | Purpose in golden test |
| --- | --- |
| **Blocklist export** | Feeds layer **B** — who is blocked (`/tmp/publist.csv`) |
| **Flow / deny logs** | Fallback if routers **cannot** export to goflow2 — find where NetFlow already lands |

Opening questions for neteng (blocklist):

- Do we run **BHR** (or STINGAR → BHR) in production?
- Is the **current block list** available as **`publist.csv`**, an internal API, or a **Splunk saved search**?
- If Splunk: **index**, **sourcetype**, and which field holds the blocked **source IP/CIDR**? (Ask about **SIF / block-lineage** feeds if they use them.)
- Who can run a **narrow export today** — neteng, security ops, or Splunk admin?
- If none of the above: can they hand you a **CSV snapshot** during the meeting?

Until you have `/tmp/publist.csv`, **skip starting the consumer** — layers A and C still
work (flow export + router counters). Layer B (Redis join) waits on the blocklist.

#### Option A — Direct BHR URL (if they have one)

```bash
curl -o /tmp/publist.csv 'https://<bhr-host>/bhr/publist.csv'
```

#### Option B — Splunk export (likely path)

Neteng (or whoever owns Splunk) runs a **narrow** search for **currently blocked
source IPs** — not a full-month PAN deny pull. Field names vary by deployment; fill
in placeholders from neteng.

Example SPL skeleton (adjust index, sourcetype, and fields):

```spl
index=<bhr_or_stingar_index> sourcetype=<block_events>
  earliest=-7d latest=now
| search <blocked-active-filter>          # e.g. action=block OR status=active
| stats latest(_time) AS added BY src_ip  # or cidr, indicator_id — confirm field names
| where isnotnull(src_ip)
| eval cidr=if(match(src_ip, "/"), src_ip, src_ip."/32")
| table cidr, indicator_id, added
| outputcsv /tmp/publist_export.csv
```

Or use the Splunk UI: run the search → **Export** → **CSV** → save as `/tmp/publist.csv`.

**Minimum columns for the consumer** ([`qob/ingest/bhr_list.py`](../qob/ingest/bhr_list.py)):
`cidr` (or `ip` / `block`) is required; `indicator_id`, `added`, etc. are optional.
Rename columns in Splunk or with a quick post-process if neteng's export uses different
headers (`src_ip` → `cidr`, etc.).

```bash
# If Splunk export used src_ip instead of cidr — one-time fix:
python3 - <<'PY'
import csv
from pathlib import Path
rows = list(csv.DictReader(open("/tmp/publist_export.csv")))
with open("/tmp/publist.csv", "w", newline="") as out:
    w = csv.DictWriter(out, fieldnames=["cidr", "indicator_id", "added"])
    w.writeheader()
    for r in rows:
        ip = r.get("src_ip") or r.get("cidr") or r.get("ip")
        if not ip:
            continue
        cidr = ip if "/" in ip else f"{ip}/32"
        w.writerow({"cidr": cidr, "indicator_id": r.get("indicator_id", ""), "added": r.get("added", "")})
PY
```

#### Option C — File neteng hands you

```bash
cp /path/from/neteng/publist.csv /tmp/publist.csv
```

#### Sanity-check before starting the consumer

```bash
wc -l /tmp/publist.csv
head -3 /tmp/publist.csv    # expect cidr (or ip) column with blocked /32s
grep '<sample-blocked-ip>' /tmp/publist.csv   # after neteng picks TEST_IP
```

### 4. Consumer (start **after** you have `/tmp/publist.csv`)

From the repo root (same path as `lab/consumer/run.py`):

```bash
export REDIS_HOST=localhost
export REDIS_PORT=6379
export FLOW_FILE=/tmp/goflow2/flows.json
export BLOCKLIST=/tmp/publist.csv
export WINDOW=86400
python lab/consumer/run.py
```

Leave this running in a terminal. The lab consumer **loads the blocklist only at
startup** — if the list changes during the meeting, re-pull and restart.

### Pre-meeting sanity checks

```bash
wc -l /tmp/goflow2/flows.json
# May be 0 until routers export — that's fine.

python lab/test/verify.py --redis-host localhost --src 0.0.0.0
# Confirms Redis read path works (may show no counts yet).
```

Write down your **goflow2 host IP** — that is what neteng types into the flow exporter.

---

## 60-minute agenda with neteng

### Minutes 0–5: Opening questions

Get these on paper:

1. **Which router(s)** handle RTBH? Hostname(s): ___________
2. **Sampling rate** on that exporter (1 = unsampled, 1000 = 1:1000): ___________
3. **Can you point export at `<your-goflow2-ip>:2055` today** (even temporarily)? Y / N
4. **Blocked-IP list** — where do we get it today?
   - BHR `publist.csv` URL: ___________
   - **Splunk** index / sourcetype / blocked-IP field: ___________
   - Saved search or export owner (neteng / security / Splunk admin): ___________
   - Fallback CSV snapshot contact: ___________

If **#3 is No**, spend the hour finding **where flow already goes** (Splunk, Kentik, nfdump, ES). You cannot complete the golden test in-room without a flow path to your collector.

If **#4 is unclear**, you can still validate **layer A** (export → goflow2) and **layer C**
(router Null0 counters) in the same session, but **layer B** (Redis join) is blocked until
you have `/tmp/publist.csv`. **Splunk is a valid path for #4** — neteng may not know the
BHR hostname but can often point you at the index or run the export in the room.

---

### Minutes 5–15: Neteng points export at goflow2

They add or change the flow exporter destination to your host:

- Protocol: **NetFlow v9** (IPFIX also works on the same port)
- Destination: **`<goflow2-host-ip>:2055`**
- Ingress monitors on **attacker-facing interfaces** (not only internal links)

**You watch** (do not wait for QoB yet):

```bash
watch -n2 'wc -l /tmp/goflow2/flows.json'

tail -1 /tmp/goflow2/flows.json | python -m json.tool | head -20
```

**Pass layer A:** lines incrementing; JSON has `src_addr`, `packets`, `bytes`.

If **zero lines after 5 minutes:** firewall, wrong IP, exporter not committed, or monitors on wrong interfaces. Debug layer A only.

---

### Minutes 15–25: Pick the test IP and load the blocklist

**Step 1 — Get `/tmp/publist.csv`** (if not done yet): BHR URL, Splunk CSV export, or
file from neteng (see §3). Start the consumer (§4) once the file exists.

**Step 2 — Pick `$TEST_IP`:** an IP that is **both**:

- On the blocklist **right now** (`grep <ip> /tmp/publist.csv`)
- Generating traffic through the RTBH router

**Best option:** an IP **already blocked** with ongoing attack traffic — zero coordination.
Neteng may suggest one from **Splunk** (recent high-volume block) or from the router's
blackhole table; confirm it appears in `/tmp/publist.csv` before the golden test.

**Fallback:** neteng triggers a short test block on a source they control (lab IP, routed test host, etc.) for ~10 minutes.

After any new block, refresh the blocklist and restart the consumer (loads blocklist only at startup):

```bash
# BHR URL — if they gave you one
curl -o /tmp/publist.csv 'https://<bhr-host>/bhr/publist.csv'

# Splunk — re-run the saved search / export (index + sourcetype from opening questions)
# Or re-copy a fresh snapshot from neteng

# Restart consumer with updated BLOCKLIST
```

---

### Minutes 25–40: Golden test

For test IP `$TEST_IP`:

```bash
# 1. Flows mention the IP?
grep "$TEST_IP" /tmp/goflow2/flows.json | tail -3

# 2. Redis counters via verify script
python lab/test/verify.py --redis-host localhost --src "$TEST_IP" --label "golden"

# 3. Or directly
redis-cli GET "qob:hits:${TEST_IP}:$(date -u +%Y%m%d)"
```

**Neteng simultaneously** on the router (~30 seconds):

```bash
show interface Null0
show ip route <TEST_IP>
```

Use platform equivalents on non-Cisco gear (discard counter, confirm blackhole route).

#### Decision table

| Result | Verdict |
| --- | --- |
| goflow2 has `$TEST_IP` as **`src_addr`**, Redis `bh_hits > 0`, Null0/discard counters moved | **Pipeline works for BH counting** — proceed with Phase 2 production wiring |
| goflow2 has traffic but Redis = 0 | Join problem: IP not on blocklist, wrong time window, stale Splunk export, or consumer not running |
| goflow2 has **no** `$TEST_IP` but Null0 moved | **Accounting/capture problem** — flows do not see BH drops on this platform; goflow2 alone will not fix it |
| goflow2 has `$TEST_IP` but Null0 did not move | Traffic is not actually blackholed on this path (wrong router, not blocked yet, asymmetric path) |

---

### Minutes 40–50: Document what they leave you

Get these in writing (email is fine):

- Router hostname(s) + platform (IOS-XE, Junos, etc.)
- **Sampling rate** per exporter
- Exporter config snippet (so they can make the export permanent)
- **Blocklist source**: BHR `publist.csv` URL *or* Splunk index/sourcetype/field map + saved search name, owning team, refresh cadence
- Confirm: **source-based RTBH** → you join on `src_addr` (already known from 2026 discovery; note it anyway)
- Whether today's export is permanent or reverted after the meeting

---

### Minutes 50–60: Capture artifacts

```bash
cp /tmp/goflow2/flows.json ~/qob-golden-test-$(date +%F).jsonl
cp /tmp/publist.csv ~/publist-golden-$(date +%F).csv
```

Screenshot `verify.py` output and neteng's Null0/discard counter.

Optional offline replay (after converting or using goflow2 JSONL):

```bash
python -m jobs.compute_qob --source csv \
  --blocklist ~/publist-golden-$(date +%F).csv \
  --flows <normalized-flow-csv> \
  --window 86400
```

---

## What you do NOT need to prove in one hour

- Exact byte accuracy vs Null0 (sampling makes this approximate for v1)
- Multi-router dedupe (`RedisQobStore.seen_flow()`)
- Production `collectors/poll_flows.py` / k8s / cron
- 1-week replay dataset
- Full Cisco vs Juniper accounting study — one successful golden test on **your** prod hardware is enough for v1

---

## One-liner to open the meeting

> I have goflow2 listening on `<IP>:2055` and Redis ready for the QoB consumer. I need three things from you: point the RTBH router's NetFlow export at that IP for 30 minutes, tell me the sampling rate, and help me get today's blocked-IP list — I don't have the BHR URL; it might be a Splunk export or a CSV snapshot. Once we have that list and a blocked IP on it, we'll confirm flows → Redis counters match router drops.

---

## Reference: pipeline under test

```text
RTBH router ──NetFlow v9 UDP 2055──▶ goflow2 ──JSON──▶ consumer (lab/consumer/run.py)
                                              │
Blocked-IP list (/tmp/publist.csv) ───────────┘
  (BHR publist.csv | Splunk CSV export | snapshot)
                                              │
                                              ▼
                                         Redis (qob:hits, qob:bytes, qob:rank)
                                              │
                                              ▼
                                    lab/test/verify.py / RedisInsight
```

Blocking plane (Cowrie → STINGAR → BHR → SDN API → RTBH) is **unchanged**. This session only validates the measurement plane.

---

## Already confirmed (do not re-litigate)

From neteng discovery 2026 — note for context only:

- **Source-based RTBH (S/RTBH)** — join on `flow.src_addr`
- **BHR upstream of Palo Alto** — high BH impact with zero PAN denies is normal
- BHR list (`publist.csv` / `query_limited`) is the authoritative join key

Still open and worth getting in this session if time allows: **sampling rate**, **ingress
Null0 accounting on hardware routers**, and **Splunk index/sourcetype for the blocklist**
(if that is how the site queries current blocks).

---

## Related docs

- [`plan-netflow-counting.md`](../plan-netflow-counting.md) — full Part 1 plan
- [`lab/README.md`](../lab/README.md) — containerlab A/B test (lab validates code, not prod ASIC accounting)
- [`docs/black_hole_logging.md`](./black_hole_logging.md) — Cisco FNF / Null0 monitoring reference for neteng
- [`plan-fw-denies.md`](../plan-fw-denies.md) — Splunk / SIF context for block and deny lineage
- [`config/sources.yaml.example`](../config/sources.yaml.example) — production config sketch
