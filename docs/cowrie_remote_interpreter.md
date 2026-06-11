# Cowrie Remote Command Interpreter: Research and Implementation Plan

**Purpose:** Research and concrete implementation options for extending the Cowrie SSH honeypot so that interactions with **unknown commands** are forwarded to a **remote interpreter service** that generates a plausible response, with the response returned to the attacker over the same SSH session. Goals: (1) expand the apparent command vocabulary and depth of the honeypot, (2) capture richer attacker behaviour for analysis, (3) do this without compromising operational stability, observability, or the existing STINGAR architecture.

**Audience:** Honeypot engineering, threat-intel research, security architect on-call.

**Status:** Research and options (no implementation has begun). The work in this doc is a **tactical** slice of the broader STINGAR strategic plan in [`PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md`](PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md); it does not replace it.

**Related documents:**

---

## 1. Problem statement

### 1.1 What Cowrie does today with unknown commands

Cowrie is a **medium-interaction** SSH/Telnet honeypot that emulates a Linux shell through a hand-written virtual file system and a small library of command implementations under `cowrie/commands/`. When an attacker types something Cowrie does not implement (e.g. `dpkg -l` for an attacker probing distro identity, or a niche post-exploit script), Cowrie returns one of two static responses:

```text
bash: <command>: command not found
```

or for partial implementations, an empty stdout + exit code 0.

Two problems follow:

- **Fingerprinting.** A skilled attacker who runs three or four commands rapidly observes the static behaviour and concludes they are on a honeypot, then disconnects with minimal further engagement. Cowrie's static signature is well documented; it is detected by published fingerprinting tools.
- **Lost signal.** The interesting commands -- the ones we have no implementation for -- are exactly the ones we most want to *see* the attacker run. A bare `command not found` ends the engagement before we learn anything from the follow-up.

### 1.2 What this plan proposes

Add a **fallback path** to Cowrie so unknown commands are routed to a remote interpreter service that:

1. Receives the command, normalized form, and **session context** (user, cwd, env, command history, virtual FS hash).
2. Generates a plausible stdout/stderr/exit-code response, optionally with side-effects on the virtual FS state.
3. Returns the response back through the same Cowrie session **as if Cowrie had implemented the command natively**.

The interpreter service may be backed by an LLM, by a rule engine, by a learned playbook (per the playbook distillation plan), or by a hybrid. The Cowrie-side change is the same regardless of backend.

### 1.3 What this plan is not

- Not a replacement for the playbook distillation plan. That plan covers the *strategic* tier model: (Tier A) LLM-backed honeypot captures transcripts; (Tier B) compiled playbooks serve cheap responses at scale; (Tier C) corpus drives downstream analysis. This document focuses on **the Tier A producer** -- specifically the Cowrie integration -- and leaves Tier B/C compilation to the strategic plan.
- Not a high-interaction (real-VM) honeypot proposal. We stay in the medium-interaction band; the LLM/interpreter does not execute real code.
- Not a multi-protocol effort. SSH/shell only. HTTP-style honeypots (Galah-class) are a separate workstream.

---

## 2. Prior art (research grounding)

The 2023-2026 timeframe produced both academic and OSS systems converging on this approach. The research is mature enough that **STINGAR should not invent its own model architecture**; the design question is integration topology.

### 2.1 Cowrie's built-in LLM backend (experimental, 2025-2026 upstream)

Upstream Cowrie main (2.9.x) includes a `backend = llm` mode (see <https://docs.cowrie.org/en/latest/LLM.html>). Highlights:

- Configurable via `cowrie.cfg` `[honeypot]` and `[llm]` sections.
- Talks to **any OpenAI-compatible HTTP endpoint** -- `host` + `path` are configurable, so a STINGAR-controlled service can sit transparently behind it.
- Maintains a **rolling 10-command history** as context for follow-up commands ("`cd /tmp` then `pwd` correctly returns `/tmp`").
- ~1-3 s typical latency; `gpt-4o-mini` is the documented default.
- Marked **experimental**; STINGAR would be an early adopter.
- Critically: **the backend pattern matches the user's request almost exactly** -- Cowrie already forwards unknown-command interactions to a remote OpenAI-compatible service and returns the response over the same session. The integration work is therefore mostly on the **service side** STINGAR provides, not on Cowrie itself.

### 2.2 shelLM (CTU Prague, arXiv 2309.00155, 2023)

Python, single-process, GPT-3.5-turbo-16k. Twelve security experts evaluated against a real Linux shell; "TNR" (true-negative rate -- attackers correctly judging it as real) competitive with real shell. Demonstrated that LLMs handle commands Cowrie cannot. **Not productionised; research prototype.** Approach informs prompt engineering but not deployment topology.

### 2.3 LLMHoney (arXiv 2509.01463, 2025)

**Hybrid** dictionary + LLM: dictionary-based virtual filesystem for common commands (low latency), LLM for novel inputs. Evaluated on 138 representative Linux commands. ~3 s mean latency for the LLM path. Smaller models often drifted; larger models more consistent. **Most directly relevant prior art** for the hybrid architecture STINGAR should pursue long-term; matches the playbook distillation tiering.

### 2.4 HoneyGPT (arXiv 2406.01882, Wang et al., 2024)

Structured prompts with **chain-of-thought** and explicit per-cycle feedback (response, state transition, aggressiveness). Field evaluation showed deeper attacker engagement and capture of novel attack vectors. Informs prompt schema; the per-cycle "what state did this command change?" pattern is exactly what the playbook distillation pipeline needs.

### 2.5 Beelzebub (mariocandela / beelzebub-labs, latest v3.6.7 Mar 2026)

Go-based, low-code, multi-protocol (SSH, HTTP, TCP, Telnet, MCP). YAML service definitions; `LLMHoneypot` plugin supports **OpenAI** and **Ollama** providers. Docker + Kubernetes ready, Prometheus metrics, ELK-stack integration. Example SSH-with-Ollama config:

```yaml
apiVersion: "v1"
protocol: "ssh"
address: ":2222"
description: "SSH Ollama"
commands:
  - regex: "^(.+)$"
    plugin: "LLMHoneypot"
serverVersion: "OpenSSH"
serverName: "ubuntu"
passwordRegex: "^(root|qwerty|...)$"
deadlineTimeoutSeconds: 60
plugin:
  llmProvider: "ollama"
  llmModel: "codellama:7b"
  host: "http://localhost:11434/api/chat"
```

This is **the most operationally mature LLM-honeypot today**. STINGAR should consider running Beelzebub *in addition to* Cowrie rather than treating it as a Cowrie replacement: different attack surface (Beelzebub is low-interaction architecturally; Cowrie is medium-interaction with VFS), different audience (Beelzebub maintained, Cowrie sparser).

### 2.6 LLM-Honeypot-Intelligence (T-Pot extension)

Layered architecture: Beelzebub (SSH) + Galah (HTTP) → Ollama proxy → caching + RL scoring + rule generation. Demonstrates the **caching proxy + LLM** topology in production, which is what STINGAR's interpreter service should look like.

### 2.7 SoK: Honeypots and LLMs (arXiv 2510.25939, 2025)

Systematization survey -- categorises architectures and notes the field's trajectory toward "logs → structured policy → cheaper runtime". STINGAR's playbook distillation plan is explicitly on this trajectory.

### 2.8 What the research collectively settles

The 2024-2026 literature converges on five design conclusions; the STINGAR plan adopts all of them:

1. **Hybrid is the right shape.** Pure LLM is too slow, too expensive, and inconsistent. Pure rules cannot keep up with novel commands. The winning architecture is rules/dictionary first, LLM fallback, learned playbooks promoting rules over time.
2. **Session context matters.** Per-command isolated calls produce inconsistent honeypots. A rolling history (Cowrie ships with 10 commands; Beelzebub uses configurable windows) plus an environment model (cwd, env, simulated FS hash) is the minimum.
3. **Self-hosting is viable for cost-sensitive deployments.** Ollama + Llama 3.x 7B/8B or CodeLlama 7B is usable on a single GPU and avoids per-call cost. Cloud LLMs (GPT-4o, Claude) are higher quality but tax-budget-sensitive deployments.
4. **Caching the LLM output is a major cost reducer.** Most attacker commands repeat across sessions; a Redis-backed cache keyed on `(normalised_command, cwd, env_hash)` cuts cost and latency dramatically.
5. **Capturing the transcript is at least as valuable as the deception.** The transcript corpus feeds analytics, TTP mining, blocklist generation, and (per the playbook plan) the learned playbook tier.

---

## 3. Design space

Six orthogonal dimensions to pick on; each implementation option in §4 is a coordinate in this space.

| Dimension | Choices | Notes |
|---|---|---|
| **Integration topology** | (a) Cowrie's built-in LLM backend, point `host` at STINGAR service; (b) custom Cowrie command-not-found hook in our overlay; (c) standalone Beelzebub alongside Cowrie; (d) sidecar HTTP proxy intercepts Cowrie's egress | Tradeoffs: upstream coupling, patch surface, deployment shape |
| **LLM provider** | (a) OpenAI / Anthropic cloud API; (b) local Ollama (Llama 3.x, CodeLlama); (c) hybrid -- local default, cloud fallback for complex queries | Cost, latency, data residency |
| **Session-context fidelity** | (a) command-only (stateless); (b) rolling-N history; (c) full virtual-OS state passed each call | Higher fidelity = larger prompts = more cost |
| **Caching** | (a) none; (b) per-host Redis cache; (c) shared cache across all sensors | Shared cache helps populate playbooks faster |
| **Rule layer** | (a) LLM-only; (b) rule-engine first, LLM fallback; (c) rule + LLM + post-process consistency checker | Hybrid wins per the literature |
| **Transcript pipeline** | (a) Cowrie logs only; (b) interpreter service emits structured event to apiarist/mellis; (c) full session capture into the corpus store from §5 of the playbook plan | This is what feeds Tier B/C in the strategic plan |

---

## 4. Implementation options (multiple, with trade-offs)

Five options, ordered roughly from "quickest spike" to "long-term architecturally correct". Pick one of the early options for Phase 1, plan toward Option 4/5 for production.

### 4.1 Option 1 -- Adopt Cowrie's built-in LLM backend with a STINGAR-controlled HTTP gateway

**Topology:** Stock Cowrie with `backend = llm`. The `host` + `path` settings in `[llm]` point at a **STINGAR-controlled HTTP service** that exposes an OpenAI-compatible `/v1/chat/completions` endpoint. The gateway can wrap any backend (OpenAI, Anthropic, Ollama, a local fine-tuned model) and add caching, prompt control, redaction, and logging.

**What we build:** one new microservice (Go or Python) implementing `/v1/chat/completions`, deployed alongside apiarist and mellis. Cowrie config gets two new lines.

**Pros:**

- **Fastest path to a working system** -- weeks, not months.
- Zero Cowrie patching; we ride upstream.
- Gateway pattern means we can later swap or upgrade the LLM without touching Cowrie deployments.
- Aligns with the "OpenAI-compatible API" lingua franca that all major LLM frameworks (Ollama, vLLM, text-generation-webui) already support.

**Cons:**

- Cowrie's LLM backend is marked **experimental**; we depend on upstream not deprecating or substantially changing it. Mitigated by pinning Cowrie SHA (we already do this -- see `stingar-honeypots/honeypots/cowrie/Dockerfile`).
- The 10-command rolling history is upstream-defined; richer session context (env, FS hash) requires either custom prompt augmentation in the gateway (limited) or moving to Option 2.
- Transcript capture is limited to whatever Cowrie logs; the structured "command + state-transition + response" tuple needed by the playbook distillation plan is not natively emitted. Workaround: the gateway logs both sides of every call.

**Effort:** **S** (1-3 weeks). Mostly the gateway service.

### 4.2 Option 2 -- Custom Cowrie command-not-found hook to a STINGAR microservice

**Topology:** Patch Cowrie's command dispatcher with a STINGAR overlay (precedent: the existing `cpppo_enip_patch.py` for conpot). When `cowrie/commands/` lookup misses, the hook builds a richer payload than Cowrie's stock LLM backend -- including the **simulated cwd, env, current user, virtual FS hash, full session command history, source IP, and HASSH fingerprint** -- and POSTs to a STINGAR service. The response includes stdout/stderr/exit_code **plus** optional FS deltas the hook applies to the session's VFS before returning to the attacker.

**What we build:** small Python patch in our cowrie overlay (matches the pattern already established in `stingar-honeypots/honeypots/conpot/plugins/`); same microservice as Option 1; a richer JSON schema for the call.

**Pros:**

- We define the protocol -- can include anything the playbook distillation pipeline needs to capture (state transitions, redacted prompt, model id, latency, FS delta).
- Stateful VFS updates ("attacker `mkdir foo` then `ls`") work cleanly because the hook applies deltas back into Cowrie's VFS layer.
- We get a clean "stop replying to known commands twice" boundary -- the LLM only sees genuinely unknown input, cutting cost vs. Option 1's "every command goes to LLM" mode.
- Survives upstream Cowrie's LLM backend being deprecated or rewritten.

**Cons:**

- More code in our overlay; more upgrade-test burden as Cowrie upstream evolves.
- Requires patching Cowrie's internals (the command dispatcher), which is a less stable interface than the `[honeypot]` config.

**Effort:** **M** (4-6 weeks). Mostly the overlay patch and protocol design; service work is the same as Option 1.

### 4.3 Option 3 -- Adopt Beelzebub alongside Cowrie

**Topology:** Add **Beelzebub** as a new honeypot in the STINGAR portfolio (alongside Cowrie, dionaea, conpot, amun, rdphoney). Two SSH honeypots in the fleet -- Cowrie unchanged for the well-known TTPs, Beelzebub for LLM-driven engagement. Different ports / different sensors; deployers choose per-site which to expose.

**What we build:** a new `stingar-honeypots/honeypots/beelzebub/` directory with Dockerfile, YAML service definitions, our existing Stingar output plugin pattern (Beelzebub emits to RabbitMQ or stdout; we wire it into fluentbit the same way as Cowrie); harness verification spec; release-notes entry.

**Pros:**

- **Beelzebub is actively maintained** (v3.6.7 Mar 2026). Cowrie's upstream cadence is sparser.
- Out-of-box LLM + Ollama support; YAML config is operator-friendly.
- Prometheus metrics, JA4H/HASSH fingerprinting already built in.
- Different fingerprint surface than Cowrie -- harder for attackers to ship a single tool that detects both.

**Cons:**

- New honeypot to onboard: Dockerfile, harness verification, telemetry mapping, release notes. Real engineering effort.
- Beelzebub is **low-interaction** architecturally (no VFS, no command implementations beyond regex → LLM). Loses some of Cowrie's existing capabilities.
- Does not, by itself, solve "extend Cowrie's vocabulary"; it adds a second sensor rather than enhancing the first.

**Effort:** **M-L** (6-10 weeks). Most of the effort is the harness-verified Dockerfile and STINGAR output wiring.

### 4.4 Option 4 -- Hybrid interpreter service with caching, rule layer, and playbook feedback

**Topology:** Build the interpreter service properly. Cowrie integration via Option 1 or 2 (either works); the gain here is on the **service side**. Architecture:

```text
Cowrie (unknown cmd) --HTTP--> Interpreter gateway
                                    |
                                    +-- 1. Normalise (canonicalise argv, env)
                                    +-- 2. Rule layer (busybox emulation, common typos, man-page lookups)
                                    +-- 3. Cache lookup (Redis, keyed on normalised cmd + cwd + env_hash)
                                    +-- 4. LLM fallback (Ollama local | OpenAI cloud per policy)
                                    +-- 5. Post-process (consistency check vs. session state)
                                    +-- 6. Emit transcript to playbook-corpus store
                                    +-- 7. Return response
```

**What we build:** the gateway service from Option 1, plus a rule registry, a Redis cache, a post-processor, and a Kafka/RabbitMQ producer that emits structured transcript records into the corpus store defined in [`PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md`](PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md) §2.3.

**Pros:**

- **Architecturally correct** per the 2024-2026 literature. Matches LLMHoney (hybrid dictionary + LLM), HoneyGPT (structured prompts + state), and the STINGAR strategic plan (corpus → playbook tier).
- Caching cuts LLM cost by an estimated 60-80 % for typical scanner traffic (most commands repeat).
- Local Ollama default + optional cloud LLM lets deployers tune for cost vs. quality vs. data residency.
- Transcript pipeline is first-class output, not a side effect -- feeds Tier B compilation directly.

**Cons:**

- Highest engineering effort of the five options.
- More moving parts to operate (LLM, cache, rule engine, transcript pipeline).
- Has to be designed and built; not a copy-from-Cowrie-upstream effort.

**Effort:** **L** (10-16 weeks). The right destination, but not the right starting point.

### 4.5 Option 5 -- Reuse apiarist as the interpreter endpoint

**Topology:** Add `POST /api/v2/honeypot/interpret` to apiarist (Python/Falcon, existing service). Cowrie's `[llm] host = http://apiarist:8000` config points at it. Apiarist proxies to whichever LLM backend STINGAR is using.

**Pros:**

- Zero new services to deploy. Apiarist is already in every STINGAR stack.
- Existing auth, logging, and ops procedures apply.

**Cons:**

- **Wrong layering.** Apiarist is the customer-facing API for the dashboard; mixing in honeypot LLM logic violates separation of concerns. Latency-sensitive honeypot calls compete with dashboard queries.
- Apiarist is Python/Falcon (not designed for high-throughput streaming responses). The LLM gateway should be Go or async Python.
- Couples honeypot vocabulary expansion to a service that has nothing to do with honeypots architecturally.

**Effort:** **S** (1-2 weeks), but tech debt cost is high.

**Recommendation:** **do not pursue Option 5** as anything more than a 1-week prototype. If we end up wanting an interpreter service, build it as its own microservice (Option 1 or 4). The apiarist endpoint is mentioned for completeness -- some teams will reach for it because it is "already there" -- but it is the wrong long-term home for this work.

### 4.6 Comparison summary

| | Effort | Cowrie patch surface | Session fidelity | Transcript fidelity | Production-ready today |
|---|---|---|---|---|---|
| **Opt 1** -- upstream LLM backend + STINGAR gateway | S | none | medium (10-cmd window) | medium (gateway logs) | yes, with caveats |
| **Opt 2** -- custom command-not-found hook | M | overlay patch | high | high | needs work |
| **Opt 3** -- adopt Beelzebub alongside | M-L | none | medium-high | medium-high | yes |
| **Opt 4** -- hybrid service + cache + corpus | L | depends | configurable | high | new build |
| **Opt 5** -- reuse apiarist | S | none | as Opt 1 | as Opt 1 | yes (not recommended) |

---

## 5. Recommended phasing

Three phases, ramping investment as confidence builds. Phases 1 and 2 are independent of the strategic [`PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md`](PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md); Phase 3 explicitly merges back into it.

### 5.1 Phase 1 -- Spike: prove the deception value (~1 sprint)

**Goal:** quantitative answer to "does an LLM-backed Cowrie engage attackers longer and produce more useful telemetry than stock Cowrie?"

**Approach:** **Option 1**. Stand up Cowrie with `backend = llm` in our overlay, point it at a vanilla Ollama instance running on the same VM (Llama 3.1 8B). Deploy to one VM in the verification cloud (same harness as `honeypot_verficiation_framework.md`). Mirror normal scanner traffic via the existing internet-exposed sensors.

**Measure:**

- Session duration distribution: LLM-backed vs. stock Cowrie (paired sensors, same time window).
- Commands per session: distribution and tail.
- "Disconnect immediately after first unknown command" rate: should drop.
- Per-session token cost (Ollama is "free" but we want the number for cloud-LLM cost projection).
- Latency p50/p95/p99 of unknown-command responses.
- Operator complaints / detection-by-attacker incidents (qualitative).

**Exit criteria:** decision to invest in Phase 2 (yes/no), backed by a written one-pager with the numbers.

### 5.2 Phase 2 -- STINGAR gateway service (~2-3 sprints)

**Goal:** ship a production-grade interpreter gateway -- still using Option 1's Cowrie integration -- that gives STINGAR control over the LLM behaviour, costs, and outputs.

**Approach:** new microservice (Go preferred; matches mellis, lower memory than Python). Exposes `/v1/chat/completions` as Cowrie expects. Adds:

- Per-deployment **prompt template** (STINGAR-themed Ubuntu 22.04 server, configurable hostname / institution / banner).
- **Redis cache** keyed on normalised prompt content (eliminates the long tail of repeat scanner commands).
- **Provider abstraction**: OpenAI, Anthropic, Ollama, vLLM, local fine-tuned model -- one of them at a time per deployment, configurable.
- **Structured transcript emission** to a Kafka/RabbitMQ topic that the corpus store (per playbook plan §2.3) will eventually consume; for now, just write JSONL to disk.
- **Rate limits + circuit breaker** so a misbehaving LLM provider (or a scanner attempting cost amplification) cannot DoS the gateway.
- **Audit logging** of every prompt + response, plus model id, latency, token count.

**Deployment artefacts:** `stingar-honeypots/honeypots/cowrie/` Dockerfile bump, `interpret/` directory in repo with the new service, harness verification spec, release notes.

**Exit criteria:** the LLM-backed Cowrie can be deployed by a non-engineer; runbook matches the rest of `docs/`.

### 5.3 Phase 3 -- Merge into the playbook distillation pipeline (~later release train)

**Goal:** make this production-LLM-honeypot the **Tier A** producer in the strategic plan. Transcripts flow into the corpus store; the corpus distils into versioned playbooks; the playbooks are served by a cheaper non-LLM core shell honeypot for scale.

**Approach:** drives the work in `PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md` §3+. The gateway from Phase 2 becomes the canonical Tier A; the playbook tier follows.

**Exit criteria:** matches the strategic plan's Phase exit criteria. Out of scope for this document.

---

## 6. Open questions and decisions needed

Decisions to make before Phase 1 starts:

| # | Question | Notes / leaning |
|---|---|---|
| 1 | Local LLM (Ollama / vLLM) or cloud API for Phase 1? | **Lean: local Ollama Llama 3.1 8B.** Lets us spike without an OpenAI bill, lower data-residency risk for university deployers. Cloud LLM is a Phase 2 provider option. |
| 2 | Which Cowrie SHA do we pin against? | Need to confirm the LLM backend is in a tagged release or pin against main. Same upgrade discipline as conpot (see `stingar-honeypots/honeypots/conpot/Dockerfile`). |
| 3 | Where does the interpreter service live in the repo? | New top-level directory next to `apiarist/` and `mellis/`. Suggested name: **`apiculus`** (Latin "little bee") to fit the existing apiarist/mellis/langstroth naming. Alternatives: `honeyterm`, `interp`, `shellpot`. |
| 4 | What language? | **Lean: Go.** Matches mellis; lower memory footprint than Python for a service that mostly proxies HTTP; OpenAI-compatible API has good Go SDK support. |
| 5 | What prompt template? | Start from Beelzebub's "act as Ubuntu Linux terminal" prompt + STINGAR additions (hostname, institution banner from `stingar.env`). Iterate based on Phase 1 measurements. |
| 6 | Default model size? | Llama 3.1 8B for local; gpt-4o-mini if a deployer chooses cloud. Both meet the 1-3 s latency budget. |
| 7 | How do we handle prompt injection from attackers? | A real risk: attackers may attempt to "break out" of the simulation prompt. Mitigations: short, deterministic system prompts; no tool/function-calling exposed; output length cap; pattern detector that flags suspected exploitation attempts so analysts can review. |
| 8 | What is the cost ceiling per sensor? | Need budget input. Helps decide if Ollama (sunk-cost GPU) or cloud (per-call) is preferred per deployment. |
| 9 | What gets logged / what is redacted? | Full prompts + responses to the audit log; surface IPs and IOCs go to the standard STINGAR event stream; potential PII in attacker payloads needs a redaction pass. |
| 10 | Should the interpreter inform the response with the **session's full virtual FS state**, or just history? | Start with history (matches upstream Cowrie). Move to FS state if we go Option 2 in Phase 3. |

---

## 7. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Cowrie's experimental LLM backend is removed or rewritten upstream | Medium | Medium | Pin SHA; maintain our own overlay patch (Option 2) as fallback |
| LLM hallucinates dangerous instructions (e.g. real exploit code in response) | Low | High | Short deterministic prompt; output length cap; post-process content filter; audit logging |
| Cost amplification attack (attacker scripts that loop millions of unique commands) | High | High | Rate limit per source IP; circuit breaker; cache; provider burst limits |
| Latency makes the honeypot detectable | Medium | Medium | Local Ollama path; cache hit rate; jitter known fast commands to match LLM latency |
| Prompt injection breaks the system prompt | Medium | Medium | System prompt isolation; output validators; periodic red-team review |
| Operator data leaks to cloud LLM provider | Low-Medium | High | Default to local; require explicit per-deployment opt-in for cloud LLM; data-processing addendum reviewed |
| Transcript corpus contains attacker payloads we should not store | Medium | Medium | Redaction pass; data retention policy; access controls aligned with `docs/dependency-track-setup.md` security posture |
| Cowrie session detected as LLM-backed via timing fingerprint | Medium | Medium | Same mitigation as latency risk; long-term: playbook tier handles fast-path commands deterministically |

---

## 8. References

| Source | What it covers |
|---|---|
| Cowrie LLM backend docs, <https://docs.cowrie.org/en/latest/LLM.html> | Upstream config, capabilities, limits |
| Sladić et al., shelLM, arXiv 2309.00155 | Cloud LLM SSH honeypot, expert evaluation |
| Wang et al., HoneyGPT, arXiv 2406.01882 | Structured prompts, chain-of-thought, state tracking |
| LLMHoney, arXiv 2509.01463 | Hybrid dictionary + LLM, 138-command evaluation |
| SoK: Honeypots and LLMs, arXiv 2510.25939 | Field survey and taxonomy |
| Otal & Canbaz, LLM Honeypot | Fine-tuning LLMs on Cowrie transcripts |
| Beelzebub, <https://github.com/beelzebub-labs/beelzebub> | Production-ready Go LLM honeypot framework |
| zgsec/beelzebub | Extended Beelzebub fork with MCP, Ollama API honeypot, JA4H/HASSH |
| Leviticus-Triage/llm-honeypot-intelligence | T-Pot + Beelzebub + Galah + Ollama caching proxy reference architecture |
| STINGAR `PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md` | Strategic tiering model this plan is a tactical slice of |
| STINGAR `ENRICHMENT_CATEGORIZATION_PLAN.md` | Broader enrichment roadmap consuming the transcript corpus |

---

## 9. Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-28 | Plan authored; no implementation work started. | Triggered by request to research and propose options. |
| (pending) | Phase 1 spike option selected. | See §6 decision matrix. |
| (pending) | Interpreter service name + language confirmed. | See §6 Q3/Q4. |

---

## Document control

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-05-28 | Initial plan. Reviewed the upstream Cowrie LLM backend, shelLM, LLMHoney, HoneyGPT, Beelzebub, and SoK survey; surveyed five concrete implementation options with trade-offs; recommended three-phase ramp (spike with Option 1 + Ollama, then Phase 2 STINGAR gateway, then Phase 3 merge into playbook distillation). Cross-linked to `PLAYBOOK_DISTILLATION_HONEYPOT_PLAN.md` as the strategic context. |

