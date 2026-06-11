# Playbook Distillation Honeypot: Concept and Implementation Plan

**Purpose:** Define a honeypot and data-collection architecture where (1) an LLM-backed honeypot captures full command/response transcripts, (2) those transcripts are distilled into lightweight **playbooks** for a non-LLM honeypot that grows its response vocabulary over time, (3) production sensors prefer playbook-backed replies for scale and latency, (4) accumulated transcripts form a **corpus** for TTP analysis, clustering, and reporting, and (5) a **core shell honeypot** (Cowrie-class SSH/shell engine plus virtual OS) is the shared runtime for the playbook tier, optionally fed by **ground-truth transcripts** from attack scripts run only against **your own** lab infrastructure to capture authentic command outputs and expand playbooks with higher fidelity than LLM-only emulation.

**Status:** Concept and phased plan (not yet implemented).

**Related documents:**

- [COWRIE_REMOTE_INTERPRETER_PLAN.md](cowrie_remote_interpreter.md) — Tactical plan for the Cowrie + remote interpreter slice (Tier A producer) of this strategic plan; surveys upstream Cowrie LLM backend, shelLM/LLMHoney/HoneyGPT/Beelzebub, and five concrete implementation options

---

## 1. Research grounding

### 1.1 Hybrid LLM + dictionary is already the right shape

Published systems converge on **not** answering every command with an LLM:

- **LLMHoney** (arXiv [2509.01463](https://arxiv.org/abs/2509.01463)): dictionary-based virtual filesystem for common commands (low latency); LLM for novel inputs. Evaluated on 138 representative Linux commands; ~3 s mean latency for LLM path; smaller models often drift or hallucinate.
- **HoneyGPT** (arXiv [2406.01882](https://arxiv.org/abs/2406.01882)): structured prompts, chain-of-thought, long-term memory and per-cycle feedback (response, state transition, aggressiveness). Field evaluation showed deeper engagement and capture of novel vectors versus baselines.

Your proposal **extends** the dictionary idea: the dictionary is not static—it is **learned from real attacker sessions** and versioned as playbooks.

### 1.2 Rule authority vs. LLM phrasing

**TrustHoneypot** (community/production pattern): rule-based engine as single authority; LLMs may improve phrasing but do not override safety/detection logic. That aligns with a **two-tier** runtime: compiled playbooks enforce deterministic behavior; optional LLM only where policy allows.

### 1.3 Systematization (SoK)

**SoK: Honeypots & LLMs** (arXiv [2510.25939](https://arxiv.org/abs/2510.25939)): taxonomy of architectures and evolution toward **automated intelligence generation** from logs. Your playbook distillation is explicitly “logs → structured policy → cheaper runtime,” which matches the direction of that survey.

### 1.4 Agentic exposure (optional later phase)

**Towards Agentic Honeynet Configuration** (arXiv [2603.14122](https://arxiv.org/abs/2603.14122)): dynamically adjusts which honeypots are exposed from a pool under resource constraints. Not required for v1, but compatible: **LLM nodes** can be a scarce “high yield” tier; **playbook nodes** scale wide.

### 1.5 Corpus and downstream analysis

Unsupervised methods on session/command data (topic models, clustering, autoencoder anomaly scoring) are documented in `Roadmap/blocking rules roadmap.md` Appendix E. A **single canonical transcript schema** plus stable session IDs makes those pipelines much easier to run at scale.

---

## 2. Concept definitions

### 2.1 Playbook (operational meaning)

A **playbook** is a versioned artifact that a non-LLM honeypot can execute deterministically. It is **not** a full chat log; it is compiled material derived from logs.

Minimum useful structure:

| Component | Role |
|-----------|------|
| **Metadata** | Playbook id, source session ids, creation time, confidence, language/locale, honeypot profile (e.g. “ubuntu22-sshd”) |
| **Environment model** | Snapshot rules for cwd, user, hostname, umask, and virtual filesystem deltas (paths → content hash or inline text) |
| **Transition table** | Ordered matchers over **normalized** input (see below) → **effects** (stdout, stderr, exit code, fs mutations, optional delay) |
| **Fallback policy** | What to do when input matches nothing: e.g. generic “command not found”, syslog line, or escalation flag to LLM tier |

Normalization is critical: attackers vary spacing, quoting, and flags. The compiler should store matchers on **parsed** structures where possible (argv tokens) plus selective regex buckets for high-variance commands (`curl`, `wget`, `bash -c`).

### 2.2 Relationship: one session → many playbook candidates

One attacker session may yield:

- One **atomic** playbook (single command/response pair promoted to a rule), or
- One **session playbook** (ordered sequence with environment updates), or
- **Merged** rules into a **corpus-wide** playbook (deduplicated global dictionary)

Recommended: treat **session playbooks** as the unit of record, then run **merge/dedupe** jobs to promote high-frequency patterns into a **global** playbook.

### 2.3 Corpus

The **corpus** is the append-only store of raw (or redacted) transcripts and derived labels:

- Full transcript: timestamp, command text, normalized command, LLM prompt hash, model id, raw response, latency, vfs state hash before/after
- Optional enrichments: campaign id, HASSH, source IP ASN, MITRE technique tags (manual or automated)

This supports TTP mining, replay for testing, and training/eval of smaller models **without** conflating corpus with the compiled playbooks (corpus = evidence; playbook = deployable policy).

### 2.4 Core shell honeypot (Cowrie-class foundation)

The **playbook honeypot** (Tier B) is not only a flat rule file: it requires a **core shell honeypot**—the same architectural class as **Cowrie**: SSH (and optionally Telnet) termination, session state, a virtual filesystem, user/hostname/cwd context, and a **command dispatcher** that maps parsed input to effects (stdout, stderr, exit code, side effects on the VFS).

| Layer | Responsibility |
|-------|----------------|
| **Protocol / session** | SSH keys, env, PTY, window size, idle timeout; session id for logging |
| **Shell front-end** | Receive a line or token stream; optional basic parsing (simple commands first; `bash -c` later) |
| **Virtual OS model** | Users, groups, `/proc`-like stubs, paths, file contents, permissions, timestamps (enough to be credible) |
| **Command runtime** | Lookup: playbook rule → apply effects idempotently on the VFS; must match playbook schema in §2.1 |
| **Playbook binding** | Hot-reload or version-pinned playbook artifact; metrics on match vs fallback |

**Why a dedicated core instead of “only Cowrie”:** Cowrie can be used as a **reference implementation** or starting fork, but the STINGAR roadmap needs explicit **playbook versioning**, **compiler output** as first-class inputs, and **diff testing** against golden transcripts (below). The core should expose a stable **plugin API** so command families (`ls`, `cat`, `ps`, package managers) are implemented once and driven by playbook data where possible.

**Relationship to Tier A:** Tier A may share the same core for VFS consistency, swapping only the **responder** (LLM vs playbook lookup). That avoids two divergent emulations.

### 2.5 Ground-truth lab (owned infrastructure + attack scripts)

**Goal:** Improve emulated responses and grow the playbook using **authentic machine behavior**, not only LLM guesses.

**Scope (mandatory):** All “real target” runs happen on **systems and networks you own** (lab VMs, containers, dedicated lab hosts). No probing of third-party systems. Document ownership and permitted use in an internal policy.

**Method:**

1. **Lab targets:** Disposable Linux hosts (same distros/versions you want the honeypot to mimic—e.g. Ubuntu 22.04, Debian 12). Snapshot or IaC (Terraform/Ansible) so each run starts from a known baseline.
2. **Attack scripts:** Curated scripts that mirror real attacker behavior: shell one-liners, brute-force then command chains, copy-paste from honeypot corpus, or staged sequences from public **playbooks** (e.g. Metasploit resource scripts, Atomic Red Team-style steps) **restricted to the lab**. Scripts should be parameterized (target user, path prefixes) and stored in version control.
3. **Capture:** For each command (or script step), record `raw_cmd`, `cwd`, `user`, `env` subset, `stdout`, `stderr`, `exit_code`, and **filesystem diffs** (allow-listed paths only if needed). Use `script`, `asciinema`, or a small wrapper that logs PTY I/O; avoid leaking lab secrets into logs (strip keys, internal hostnames if required).
4. **Export format:** Same **event schema** as Tier A (§5 Phase 0), plus `provenance: { "source": "ground_truth_lab", "lab_profile": "ubuntu22-minimal-v3", "script_id": "...", "run_id": "..." }`.
5. **Compiler priority:** When merging rules for the same normalized command, **ground-truth lab** rows override LLM-derived rows unless contradicted by a newer reviewed lab run. Mark playbook entries with `confidence: lab_golden` vs `llm_distilled` vs `attacker_observed`.

**Outcome:** The playbook honeypot’s vocabulary grows toward **parity with real OS output** for heavily scripted paths (e.g. `uname`, `ls -la /bin`, `cat /etc/os-release`), while LLM + attacker sessions still fill long-tail novelty.

**Optional loop:** Run **diff tests** in CI: replay the same commands through the core shell honeypot against the compiled playbook and **compare** stdout/stderr/exit (and selected VFS state) to the golden lab capture; fail or warn on divergence.

---

## 3. End-to-end architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ Ground-truth lab (owned infrastructure only)                              │
│ - Lab VMs / containers · reset from snapshot or IaC                      │
│ - Versioned attack scripts → real shell · real stdout/stderr/exit/fs    │
│ - Export: same event schema + provenance (lab_profile, script_id, run_id) │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ golden transcripts
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Tier A: LLM honeypot (fewer instances, high fidelity)                     │
│ - Core shell engine (see §2.4): SSH, session, VFS, dispatcher              │
│ - LLM responder for novel input · logs + LLM metadata                    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ append-only event stream
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Ingestion & normalization                                                │
│ - PII/redaction policy · command parsing · secret stripping              │
│ - Session reconstruction · dedupe keys · provenance routing             │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
┌──────────────────────────┐        ┌──────────────────────────┐
│ Corpus store              │        │ Playbook compiler         │
│ (search, export, ML)      │        │ Lab golden > LLM > field  │
└──────────────────────────┘        └────────────┬────────────┘
                                                 │ versioned playbooks
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Tier B: Playbook honeypot (many instances, low cost)                     │
│ - Same core shell engine as Tier A · playbook rules only on hot path     │
│ - Matcher + VFS · optional escalate unmatched to Tier A                    │
│ - CI diff tests vs golden lab captures (optional)                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Playbook compilation pipeline

### 4.1 Automated steps

1. **Segment sessions** into command rounds (already natural in shell interaction).
2. **Normalize** input: trim, unicode normalize, parse shell where safe; retain raw string for audit.
3. **Extract environment deltas** from the LLM-side state machine (if using HoneyGPT-like state summaries, map those into vfs mutations).
4. **Propose rules**: `(matcher, response_template, exit_code, fs_delta)`.
5. **Deduplicate**: merge rules that are identical post-normalization; keep frequency counts and source session references.
6. **Safety filter**: drop rules that contain secrets, real IPs of victims, or instructions that could cause real harm if replayed incorrectly (policy-dependent).

### 4.2 Ground-truth ingestion (lab → playbook)

Inputs from §2.5 are merged like any other transcript, with these differences:

- **Priority:** For a given `(normalized_cmd, lab_profile)` tuple, lab golden rules **supersede** LLM-derived rules unless a policy flag demotes stale lab data.
- **Naming:** Playbook bundles may ship **profiles** (e.g. `ubuntu-22.04-minimal`) so the honeypot can advertise a consistent “personality” matching what was recorded in the lab.
- **Regression:** Store golden captures as **fixtures**; core shell + playbook releases must pass replay tests or emit warnings (see §7 metrics).

### 4.3 Human or semi-automated QA (recommended for production playbooks)

- Sample stochastically from new rules.
- Reject hallucination-heavy patterns (e.g. impossible file listings inconsistent with vfs).
- Mark **confidence** tier: `auto_promoted` vs `reviewed`.

### 4.4 Runtime matching strategy (practical ordering)

1. **Exact argv match** for simple commands (`pwd`, `whoami`, `uname -a` with normalized flags).
2. **Trie / prefix** for command-first-token indexing (`ls`, `cat`, `cd`).
3. **Regex buckets** for parameterized forms (`curl http://%`, `wget %`).
4. **Embedding nearest-neighbor** (optional): map novel input to closest known command **only if** distance below threshold; else fallback. This is a small model or fixed embedding table—not a full generative LLM on the hot path.
5. **Fallback**: generic errors, or escalate to Tier A with rate limits.

---

## 5. Phased implementation plan

### Phase 0: Schema and logging contract

- Define JSONL (or protobuf) **event schema** for Tier A: `session_id`, `seq`, `raw_cmd`, `parsed_cmd`, `vfs_pre_hash`, `vfs_post_hash`, `stdout`, `stderr`, `exit_code`, `model`, `prompt_template_version`, `latency_ms`.
- Add optional fields for **all** sources: `provenance.source` (`llm_honeypot` | `ground_truth_lab` | `playbook_replay`), `provenance.lab_profile`, `provenance.script_id`, `provenance.run_id`.
- Define **playbook** JSON/YAML schema v1 and a `playbook compile` validator.
- Redaction policy document (passwords, keys, email domains).

**Exit criteria:** One session can be replayed in a test harness from logs alone.

### Phase 0a: Core shell honeypot MVP (Cowrie-class basis)

- Implement or adapt a **minimal** SSH shell honeypot: one OS profile, PTY, virtual filesystem with a small tree (`/bin`, `/etc/os-release`, `/proc` stubs), cwd/user context.
- **Command dispatcher:** pluggable handlers; start with a **hardcoded** set of commands (e.g. `pwd`, `ls`, `whoami`, `uname`, `cat` for a few files) to prove end-to-end behavior without a playbook file.
- **Unified logging:** every round-trip writes the Phase 0 event schema (no LLM yet).
- Document how this core will load **external playbooks** in Phase 2 (API boundary: “resolve command → effects”).

**Exit criteria:** A client can SSH in, run the hardcoded command set, disconnect; logs validate against schema; unit tests for VFS mutations.

### Phase 0b: Ground-truth lab v1 (owned infrastructure)

- Stand up an **isolated lab** (separate VLAN or cloud project): target VMs/containers **you own**, rebuildable from snapshot or IaC.
- Choose **one** lab profile to mimic first (e.g. Ubuntu 22.04 minimal) matching the core honeypot’s advertised personality.
- Author **versioned attack scripts** (shell or automation) that exercise the same command set as Phase 0a **plus** a short list of realistic follow-on steps (download stubs to `file://` or lab-only HTTP, no third-party attack traffic).
- Run scripts against lab targets; **capture** golden transcripts (stdout/stderr/exit; optional fs diff); export using the same schema as Phase 0 with `provenance.source=ground_truth_lab`.
- Check fixtures into repo (or artifact store) for **replay tests** in Phase 2.

**Exit criteria:** At least one `run_id` per script with complete golden export; internal policy doc signed off (lab scope, data handling).

### Phase 1: LLM honeypot MVP + corpus ingestion

- Integrate **LLM responder** into the **same core shell** from Phase 0a (dictionary/known commands first, LLM for novel input per LLMHoney-style routing).
- Stream logs to object storage + index (e.g. SQLite/Postgres for metadata; blob store for bulk).
- Minimal UI or CLI: list sessions, export corpus slice.
- **Feed Phase 0b golden captures** into the compiler sandbox (optional dry-run) to validate schema alignment.

**Exit criteria:** Corpus queryable; sample transcripts exportable for analysis; Tier A shares one codebase path with Tier B for VFS/dispatcher.

### Phase 2: Compiler v1 (rule extraction without fancy ML)

- Offline job: session → candidate playbook (sequence of rules); **merge lab golden** with highest priority (§4.2).
- Dedupe + merge into global playbook; version tags (`global-2026-04-01`); **profile** tags per lab OS (`ubuntu-22.04-minimal`).
- Tier B deployment: **core shell** loads playbook file; no LLM on hot path; metrics on match rate.
- **Diff tests (recommended):** replay golden lab commands through Tier B; compare stdout/stderr/exit to fixtures; fail CI on unexpected drift after playbook updates.

**Exit criteria:** Match rate and latency measured; playbook version pinned per sensor; first green run of lab-vs-emulation diff suite (even if narrow scope).

### Phase 3: Promotion workflow and safety

- CI checks: schema validation, secret scanning, max response size, forbidden patterns.
- Manual review queue for high-impact rules (e.g. `curl|bash` chains).
- Canary: deploy new playbook to a subset of Tier B nodes; compare session length and abandonment vs. baseline.

**Exit criteria:** Safe promotion pipeline; rollback to previous playbook version.

### Phase 4: Intelligence layer (corpus → TTPs)

- Batch jobs: topic modeling / clustering on command sequences (see Appendix E in blocking rules roadmap).
- Optional: LLM **offline** (not on hot path) to propose MITRE tags per session for analyst review.
- STIX export of sessions/campaigns as in roadmap Section 5e.

**Exit criteria:** Monthly report: top new command patterns, novel clusters, overlap with known campaigns.

### Phase 5 (optional): Embedding fallback + Tier A escalation

- Small embedding model for Tier B near-match; threshold tuned to limit false confidence.
- Rate-limited escalation of unmatched lines to Tier A to **grow** playbooks deliberately.

**Exit criteria:** Documented cost model; abuse controls on escalation.

---

## 6. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| LLM hallucinations in distilled rules (not lab-backed) | Prefer lab golden where available; compiler uses structured outputs (exit code, bounded stdout); reject contradictions with VFS; mark `confidence: llm_distilled` |
| Lab scripts run outside owned scope | Written policy; automation only targets lab inventory; no third-party hosts; code review on scripts that accept host parameters |
| Lab captures contain secrets or internal hostnames | Strip/redact in export; use disposable identities; separate “shareable golden” vs internal raw logs |
| Ground-truth vs advertised honeypot profile drift | Version `lab_profile` with playbook bundles; CI diff tests; explicit OS fingerprint files (`/etc/os-release`) aligned with lab |
| Cowrie/fork maintenance burden | Prefer thin fork or library reuse with clear boundaries; upstream security patches tracked |
| Poisoned sessions teaching bad rules | Rate limits; reputation by source ASN; manual review for rare high-impact commands |
| Privacy / leakage in corpus | Redaction pipeline; retention limits; optional aggregate-only export for sharing |
| Playbook bloat / slow matching | Trie indexing; rule pruning by frequency; periodic merge |
| False confidence from embedding match | Conservative thresholds; default to safe fallback |

---

## 7. Success metrics

| Metric | Purpose |
|--------|---------|
| Tier B **match rate** | Fraction of commands served without fallback |
| **p95 latency** Tier B | Should stay sub-100 ms for typical rules |
| **Session depth** (commands per session) | Engagement vs. Cowrie/static baseline |
| **Novel cluster rate** from corpus | New TTPs discovered per week |
| **Compiler yield** | New promoted rules per GB of Tier A logs |
| **Lab golden coverage** | Share of high-frequency attacker commands that have a `ground_truth_lab` rule for the active `lab_profile` |
| **Lab-vs-emulation diff pass rate** | Fraction of golden lab commands where Tier B output matches fixture (stdout/stderr/exit); track regressions on playbook releases |
| **Core API stability** | Number of breaking changes to dispatcher/playbook binding per release (drive toward zero after v1) |

---

## 8. Key references (external)

- LLMHoney — arXiv 2509.01463: <https://arxiv.org/abs/2509.01463>
- HoneyGPT — arXiv 2406.01882: <https://arxiv.org/abs/2406.01882>
- SoK: Honeypots & LLMs — arXiv 2510.25939: <https://arxiv.org/abs/2510.25939>
- Towards Agentic Honeynet Configuration — arXiv 2603.14122: <https://arxiv.org/abs/2603.14122>

---

## 9. Open decisions (for STINGAR product)

- Single-tenant vs federated playbook sharing (HP App Store / community playbooks).
- Whether Tier B may **never** call an LLM (air-gapped sites) vs optional escalation.
- License for corpus derived from production sensors (research use only vs commercial).
- **Core implementation:** Fork Cowrie (or similar) vs greenfield Python/Go core; trade-off is velocity vs control of the playbook API surface.
- **Lab topology:** On-prem only vs isolated cloud account; who approves new attack scripts; retention for raw PTY captures.
- **Golden sharing:** Whether lab fixtures are checked into the product repo, a private artifact bucket, or both.

