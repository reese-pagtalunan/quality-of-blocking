# Archived: NetFlow-based QoB (June 2026)

**Status:** Superseded — do not build on this code.

After neteng discovery (June 2026), the project pivoted away from the
**goflow2 → consumer → Redis** measurement plane for black-hole counting.
This folder preserves the last implementation of that approach for reference.

## Git tag

The commit **before** this archive move is tagged:

```text
archive/qob-netflow-2026-06
```

```bash
git checkout archive/qob-netflow-2026-06   # browse the pre-pivot tree
```

## What was this?

**Quality of Blocking (QoB) Part 1 — Option 1:** correlate router NetFlow/IPFIX
with the BHR blocked-IP list (`src_addr` join) to produce per-IP `bh_hits` /
`bh_bytes` in Redis.

| Path | Purpose |
| --- | --- |
| [`lab/`](./lab/) | containerlab RTBH A/B test (FRR + ExaBGP + goflow2 + consumer) |
| [`qob/`](./qob/) | Join logic, BHR list loader, Redis store, scoring |
| [`jobs/`](./jobs/) | `compute_qob` CLI (CSV / ES replay) |
| [`collectors/`](./collectors/) | Production collector sketch (`poll_flows.py`) |
| [`tests/`](./tests/) | Unit tests and fixtures |
| [`config/`](./config/) | `sources.yaml.example` |
| [`plan-netflow-counting.md`](./plan-netflow-counting.md) | Part 1 design doc |
| [`docs/`](./docs/) | Neteng golden-test runbook, Flow Collector, edge router, BH logging |

## Why archived

Production path assumptions (direct BHR publist, Mac-hosted goflow2 golden test,
ingress NetFlow accounting on RTBH routers) did not match neteng's revised
architecture. See the root [`README.md`](../../README.md) for the new direction.

## Related docs still at repo root

- [`plan-fw-denies.md`](../../plan-fw-denies.md) — Part 2 NGFW confirmation (may inform future work)
- [`docs/cowrie.md`](../../docs/cowrie.md) — honeypot / playbook planning
- [`ssh-cloud-plan.md`](../../ssh-cloud-plan.md) — cloud SSH honeypot
