# Quality of Blocking (QoB)

Per-IP score measuring how strongly we block Cowrie-sourced threats. Part 1
counts traffic sunk at black-hole routers; Part 2 confirms blocks at the NG
firewall. QoB will later fuse with behavior telemetry for an **attack severity**
rating.

## Status

| Part | Topic | Plan | Code |
| --- | --- | --- | --- |
| 1 | Black-hole impact (NetFlow) | [`plan-netflow-counting.md`](./plan-netflow-counting.md) | Implemented (`qob/join_flows.py`, `flow_redis.py`, `lab/`) |
| 2 | NGFW deny confirmation (Palo Alto) | [`plan-fw-denies.md`](./plan-fw-denies.md) | Planned |
| — | Cloud SSH honeypot (Azure VPC) | [`ssh-cloud-plan.md`](./ssh-cloud-plan.md) | Planned |

## Add vs mark

| Signal | QoB role |
| --- | --- |
| `bh_hits` / `bh_bytes` (Part 1) | **Add** — traffic sunk at BH (`impact_score`) |
| `fw_deny_count` (Part 2) | **Mark** — `edge_confirmed` + capped `confirmation_score` |
| Cowrie sessions | **Evidence** (planned) |
| Time on blocklists | **Persistence** (planned) |
| Whitelist / churn | **Penalty** (planned) |

Do not sum BH bytes and FW bytes for the same packets unless network paths are
proven disjoint. Part 1 accepts **sampled** NetFlow for v1; exact ACL counters
are a later refinement.

## Pipeline

Blocking is unchanged: Cowrie → STINGAR (Forewarned) → BHR → black-hole router
(**immediate**, upstream of PAN) + NGFW EDL (**~5 min** refresh, blocks up to
**7 days**). STINGAR submits to BHR via an output plugin; production RTBH uses a
**custom SDN API** (the lab uses ExaBGP as a stand-in). QoB adds parallel
**measurement** only.

**Neteng-confirmed:** BHR sits **in front of** the firewalls, so high BH impact
with **zero** PAN denies is often normal — not a failure. Bad-actor feeds mix
honeypot and other detections; QoB needs **Cowrie/STINGAR lineage**
(`indicator_id`) to score honeypot-sourced blocks, not the blocklist alone.

## Scoring

**Today:** `impact_score = w_h·bh_hits + w_b·log(1 + bh_bytes)` in `qob/scoring.py`.

**Next:** Part 2 confirmation, then evidence / persistence / penalty →
`QoB_raw` / `qob_rank` for downstream severity.

## Plan docs

Implementation detail lives in companion plans:

- [Part 1 — flow counting](./plan-netflow-counting.md)
- [Part 2 — FW denies](./plan-fw-denies.md)
- [Cloud SSH honeypot](./ssh-cloud-plan.md)
- [RTBH lab](./lab/README.md)

## Quick start

```bash
python -m jobs.compute_qob --source csv \
  --blocklist tests/fixtures/publist.csv \
  --flows tests/fixtures/flows.csv --window 3600
```

## Success criteria

- ≥95% of blocked IPs have a QoB record within 24h of first block
- Production `as_of` lag ≤ 30 minutes
- Every rank traceable to component breakdown and source timestamps
