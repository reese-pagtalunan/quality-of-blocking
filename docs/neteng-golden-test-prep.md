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

Have this **already running** when neteng walks in. Do not spend the hour installing Docker.

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

### 3. BHR publist

Live pull or a snapshot from this morning:

```bash
curl -o /tmp/publist.csv https://<bhr-host>/bhr/publist.csv
```

### 4. Consumer

From the repo root (same path as `lab/consumer/run.py`):

```bash
export REDIS_HOST=localhost
export REDIS_PORT=6379
export FLOW_FILE=/tmp/goflow2/flows.json
export BLOCKLIST=/tmp/publist.csv
export WINDOW=86400
python lab/consumer/run.py
```

Leave this running in a terminal.

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

### Minutes 0–5: Three yes/no questions

Get these on paper:

1. **Which router(s)** handle RTBH? Hostname(s): ___________
2. **Sampling rate** on that exporter (1 = unsampled, 1000 = 1:1000): ___________
3. **Can you point export at `<your-goflow2-ip>:2055` today** (even temporarily)? Y / N

If **#3 is No**, spend the hour finding **where flow already goes** (Splunk, Kentik, nfdump, ES). You cannot complete the golden test in-room without a flow path to your collector.

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

### Minutes 15–25: Pick the test IP

You need an IP that is **both**:

- On the BHR publist **right now** (`grep <ip> /tmp/publist.csv`)
- Generating traffic through the RTBH router

**Best option:** an IP **already blocked** with ongoing attack traffic — zero coordination.

**Fallback:** neteng triggers a short test block on a source they control (lab IP, routed test host, etc.) for ~10 minutes.

After any new block, refresh publist and restart the consumer (lab consumer loads the blocklist only at startup):

```bash
curl -o /tmp/publist.csv https://<bhr-host>/bhr/publist.csv
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
| goflow2 has traffic but Redis = 0 | Join problem: IP not on publist, wrong time window, or consumer not running / stale blocklist |
| goflow2 has **no** `$TEST_IP` but Null0 moved | **Accounting/capture problem** — flows do not see BH drops on this platform; goflow2 alone will not fix it |
| goflow2 has `$TEST_IP` but Null0 did not move | Traffic is not actually blackholed on this path (wrong router, not blocked yet, asymmetric path) |

---

### Minutes 40–50: Document what they leave you

Get these in writing (email is fine):

- Router hostname(s) + platform (IOS-XE, Junos, etc.)
- **Sampling rate** per exporter
- Exporter config snippet (so they can make the export permanent)
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

> I have goflow2 listening on `<IP>:2055` and the QoB consumer writing Redis. I need you to point the RTBH router's NetFlow export at that IP for 30 minutes, tell me the sampling rate, and help me pick one IP that's on BHR right now so we can confirm flows → Redis counters match router drops.

---

## Reference: pipeline under test

```text
RTBH router ──NetFlow v9 UDP 2055──▶ goflow2 ──JSON──▶ consumer (lab/consumer/run.py)
                                              │
BHR publist.csv ──────────────────────────────┘
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

Still open and worth getting in this session if time allows: **sampling rate** and **ingress Null0 accounting on hardware routers**.

---

## Related docs

- [`plan-netflow-counting.md`](../plan-netflow-counting.md) — full Part 1 plan
- [`lab/README.md`](../lab/README.md) — containerlab A/B test (lab validates code, not prod ASIC accounting)
- [`docs/black_hole_logging.md`](./black_hole_logging.md) — Cisco FNF / Null0 monitoring reference for neteng
- [`config/sources.yaml.example`](../config/sources.yaml.example) — production config sketch
