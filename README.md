# Quality of Blocking (QoB)

Measuring how effectively we block threats surfaced from honeypot telemetry
(Cowrie → STINGAR → edge enforcement).

## Status (June 2026 — pivot)

**Active development is restarting** after a neteng discovery session that
changed production assumptions. The previous approach — NetFlow-based black-hole
counting via goflow2, a Python consumer, and Redis — is **archived** and should
not be extended.

| Area | Location | Notes |
| --- | --- | --- |
| **Archived Part 1 (NetFlow QoB)** | [`archive/2026-06-netflow-qob/`](./archive/2026-06-netflow-qob/) | lab, `qob/`, plans, golden-test runbook |
| **Pre-pivot git snapshot** | tag `archive/qob-netflow-2026-06` | `git checkout archive/qob-netflow-2026-06` |
| **Part 2 (NGFW denies)** | [`plan-fw-denies.md`](./plan-fw-denies.md) | Planned; may be revised with new scope |
| **Cloud SSH honeypot** | [`ssh-cloud-plan.md`](./ssh-cloud-plan.md) | Planned |
| **Cowrie / playbooks** | [`docs/cowrie.md`](./docs/cowrie.md) | Ongoing research |

## New scope (TBD)

Document here after the neteng follow-up:

- **Measurement source** — what telemetry replaces (or drops) router NetFlow join
- **Join key** — authoritative blocklist / indicator lineage
- **Deployment** — where collectors and stores run in production
- **Success criteria** — what “golden test” means under the new model

Suggested next artifact: `plan-<new-scope>.md` at repo root.

## Repository layout

```text
archive/2026-06-netflow-qob/   # frozen Part 1 implementation (reference only)
docs/                          # cowrie and related planning
plan-fw-denies.md              # Part 2 sketch (subject to revision)
ssh-cloud-plan.md
```

## Quick start

No active Python package at root yet. To browse or replay the archived stack:

```bash
git checkout archive/qob-netflow-2026-06
cd archive/2026-06-netflow-qob   # after archive commit on main branch
# see archive/2026-06-netflow-qob/README.md
```
