# Blocking and Blackhole Logging Report

**Scope:** Where dropped/blocked packets get logged across two distinct enforcement layers -- the next-gen firewall (Part 1) and the edge router with blackhole routing support (Part 2).

**Default platforms:** Palo Alto Networks PAN-OS for the NGFW tier; Cisco IOS-XE for the edge-router tier. Equivalents for Fortinet, Cisco Firepower, Check Point, Juniper, and Arista are noted in each part.

**Context for STINGAR operators:** This document is the reference for "where do I see what my firewall / router actually blocked" -- the join key between STINGAR's threat-intel output (External Dynamic Lists, IDS/IPS rules, blocklists, potential future BGP-RTBH feed) and the enforcement evidence at each tier. When a customer feeds STINGAR intel into their NGFW *and/or* their edge router and wants to verify drops are happening, the queries and telemetry pipelines below produce that evidence.

---

# Part 1 -- Next-Gen Firewall (Palo Alto PAN-OS default)

---

## The four layers and where each writes

On a Palo Alto NGFW, "dropped packets" is not a single log type -- packets get dropped at four different layers and each writes to a different log. Knowing which layer is dropping is half the battle.

| Layer | What it catches | Where it logs |
|---|---|---|
| **Security policy** (`action: deny` / `drop` / `reset-*`) | Most operator-relevant denies. Includes anything an EDL/blocklist rule denies (relevant to STINGAR feed consumption). | Monitor -> Logs -> **Traffic** (with `action=deny` or `action=drop`) |
| **Threat prevention** (AV, anti-spyware, vulnerability, URL filter, WildFire, DNS sinkhole) | Packets dropped because content inspection caught something. | Monitor -> Logs -> **Threat** |
| **Zone protection / DoS protection / packet buffer protection** | Flood thresholds, malformed packets, frag attacks, ICMP/IP options drops, session-table exhaustion. | Monitor -> Logs -> **System** (events) + global counters; some types only via `show counter global` |
| **Data plane discards** (bad CRC, TTL=0, MTU, no-route, fragmentation needed) | Pre-policy infra drops. Never appear in Traffic logs because they never reached the policy engine. | `show counter global` only, unless you enable flow logging |

A policy `deny` writes a Traffic log; a zone-protection flood drop usually does not (it bumps a counter). This is the most common source of confusion.

---

## GUI -- quickest answer for an analyst

**Monitor -> Logs -> Traffic**, then filter:

```text
( action eq deny ) or ( action eq drop ) or ( action neq allow )
```

Useful column adds: `Action Source` (tells you which rule decided), `Session End Reason` (`policy-deny`, `threat`, `aged-out`, `tcp-rst-from-client`, etc.), and `Source Zone` / `Destination Zone`.

For Threat-driven drops: **Monitor -> Logs -> Threat**, with filter:

```text
( action eq drop ) or ( action eq reset-both ) or ( action eq block-ip ) or ( severity geq medium )
```

---

## CLI -- for ops/scripting

PAN-OS uses Boolean filter expressions on log subcommands. Operators are `eq`, `neq`, `geq`, `leq`, `contains`, `in`, joined by `and` / `or` / `not`.

### All policy-denied traffic, most recent first

```bash
show log traffic direction equal backward action equal deny
```

### Combine deny + drop + reset actions

```bash
show log traffic direction equal backward \
  query "( action eq deny ) or ( action eq drop ) or ( action eq reset-both ) or ( action eq reset-client ) or ( action eq reset-server )"
```

### Narrow by source IP and time

```bash
show log traffic direction equal backward \
  query "( addr.src in 198.51.100.0/24 ) and ( action eq deny ) and ( receive_time geq '2026/06/02 00:00:00' )"
```

### Threat drops in the last hour

```bash
show log threat direction equal backward \
  query "( action eq drop ) and ( receive_time geq '2026/06/02 13:00:00' )"
```

### The hidden one -- counters for everything the logs don't show

```bash
show counter global filter delta yes severity drop
show counter global filter aspect dfa packet severity drop
show counter global filter category flow severity drop
```

`delta yes` shows only counters that incremented since the last invocation -- the practical way to spot what is actively dropping. Useful counter names to look for:

| Counter | Means |
|---|---|
| `flow_policy_deny` | Policy-rule denies (matches Traffic logs) |
| `flow_dos_*` | DoS protection profile fired |
| `flow_no_session` | Session-table exhaustion |
| `flow_action_close` | TCP reset injected |
| `pkt_alloc_failure` | Packet buffer exhausted |
| `flow_fwd_l3_noroute` | No route for destination |
| `flow_fragmt_drop_*` | Fragmentation reassembly failure |
| `flow_meter_drop` | Aggregate bandwidth meter hit |

### Live tail of dropped traffic (PAN-OS 10.x+)

```bash
tail follow yes mp-log traffic
```

### Raw dataplane visibility -- heavy, only on test interfaces

```bash
debug dataplane packet-diag set log on
debug dataplane packet-diag set filter match source <ip>
debug dataplane packet-diag set log feature flow basic
debug dataplane packet-diag set filter on
# ... reproduce ...
debug dataplane packet-diag set log off
debug dataplane packet-diag aggregate-logs
less mp-log pan_packet_diag.log
```

Each `debug dataplane packet-diag` filter adds a small CPU cost on the data plane; remember to turn it off when you are done.

---

## XML API -- for collection / automation

Asynchronous job pattern: submit a query, get a `job` id, poll for the result. Useful for piping into a SIEM or ad-hoc analysis when syslog is not set up.

### Submit (URL-encoded)

```bash
curl -k "https://<fw>/api/?type=log&log-type=traffic&key=<API_KEY>&nlogs=500&query=(action eq deny) or (action eq drop)"
```

Response gives `<job>NNNN</job>`. Poll:

```bash
curl -k "https://<fw>/api/?type=log&action=get&job-id=NNNN&key=<API_KEY>"
```

`log-type` accepts: `traffic`, `threat`, `system`, `config`, `hipmatch`, `url`, `data`, `wildfire`, `globalprotect`.

---

## Continuous collection -- the real answer for "logs about which packets were dropped"

If you actually want a running stream of drops (rather than ad-hoc lookups), set up **Log Forwarding** to a syslog/SIEM destination:

1. **Device -> Server Profiles -> Syslog** -- define your collector (e.g. Elastic, Splunk, fluentd).
2. **Objects -> Log Forwarding** -- create a profile with match-list entries like:
   - `(action eq deny) or (action eq drop)` -> forward to syslog
3. **Apply the Log Forwarding profile** to each security policy rule (Policies -> Security -> \<rule\> -> Actions -> Log Forwarding).
4. **Device -> Log Settings** -- for System and Threat logs, attach the same syslog server.

Once that is flowing into your SIEM, you can query "all drops in the last hour" with standard SIEM filter logic, e.g. `action: ("deny" OR "drop" OR "reset-both")`.

### STINGAR-EDL correlation

When the firewall denies a flow because the destination/source IP was in your STINGAR EDL, the Traffic log entry's `Rule` column shows the rule name and `Action` is `deny`. To correlate STINGAR-detected attackers with what the firewall actually blocked, filter on `Rule eq "<your-edl-rule-name>"` in either the Traffic log or the SIEM query -- that is the join key between STINGAR's blocklist export and PAN-OS's enforcement evidence.

---

## Equivalent concepts on other NGFW vendors

| Vendor | Closest equivalent | Where |
|---|---|---|
| **Fortinet FortiGate** | `execute log filter` then `execute log display`; or `diag debug flow` for dataplane | CLI / FortiAnalyzer / syslog |
| **Cisco Firepower (FTD/FMC)** | "Connection Events" with `action: Block`; access-control event log | FMC GUI -> Analysis -> Connections / FMC syslog |
| **Check Point** | SmartConsole -> Logs & Monitor -> Action: `drop` / `reject`; `fw log` on CLI | SmartView / `fw log -f` |
| **Juniper SRX** | `show security policies hit-count`; `set security policies default-policy deny-all log` | `show log <name>` / syslog |

All four have the same conceptual split (policy-level vs. inspection-level vs. infra-level drops) -- only the command syntax and log file names differ.

---

---

# Part 2 -- Edge Router Blackhole Routing (Cisco IOS-XE default)

## Why BHR is silent by default

RTBH / BHR drops work by installing a route whose next-hop is a discard interface -- `Null0` on Cisco, `dsc`/`discard` on Juniper, `null0` on Arista. The discard interface is implemented in the forwarding ASIC (or in a fast software path) and is deliberately stateless: no logging, no rate-limiting, no ICMP unreachables, no flow tracking. That property is what lets a single edge router blackhole multi-gigabit DDoS traffic without melting.

This is also what makes "where did the blackholed traffic go?" a non-trivial question. Per-packet syslog at edge-router line rate would saturate any log pipeline within seconds, so the platforms do not even offer it.

Three ways to recover visibility, in increasing order of fidelity:

| Approach | Granularity | Performance cost | Where it logs |
|---|---|---|---|
| Interface counters on the discard interface | Packets/bytes total only | None | `show interface Null0` (and SNMP MIB) |
| Routing-event syslog (BGP-triggered blackhole add/remove) | "A blackhole for X.X.X.X was installed at HH:MM" | None | Syslog |
| **Flow telemetry (NetFlow / IPFIX / sFlow)** | **Per-flow: src/dst/port/proto/bytes/duration with egress = discard** | **Sampled, ~1-2 % CPU** | **Flow collector** |
| ACL logging with `log-input` instead of `Null0` | Per-packet, full detail | Significant -- sub-Gbps only | Syslog |
| Port mirror / SPAN to IDS | Full packet payloads | Bandwidth of mirror | IDS / sensor (not the router) |

The middle one -- flow telemetry -- is what every production network actually uses to answer "what did we blackhole?". Specifics by vendor below.

---

## Cisco IOS / IOS-XE / IOS-XR

### Counters (always available, zero config)

```bash
show interface Null0
show ip route 192.0.2.1               # confirm route -> Null0
show ip cef Null0 detail              # FIB-level: prefix count + hit counters
show cef drop                         # aggregate drop counters by reason
```

`show cef drop` is the closest thing to a built-in "blackhole report" -- it bins drops by reason (`No_route`, `No_adj`, `RP_Drop`, `Encap_fail`, etc.) and includes the `Null0` bucket.

### BGP RTBH event logs

If the blackhole was installed via BGP (typical pattern: trigger router announces the prefix with community `65535:666` per RFC 7999), the install/withdraw events go to syslog automatically:

```text
Jun  3 10:14:21 edge1 %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Up
Jun  3 10:14:32 edge1 %BGP_SESSION-6-NEIGHBOR_UPDATE: ... prefix 192.0.2.1/32 community 65535:666
```

To capture these reliably, ensure `logging buffered`, `logging host <syslog-server>`, and `logging trap informational` are configured. This gives you the *when* and *what prefix* -- not the *what hit it*. For that you need NetFlow.

### NetFlow / Flexible NetFlow on Null0 -- the real answer

Configure flow ingress on every interface where traffic could enter and head for the blackhole, plus a flow exporter pointing at your collector:

```cisco
flow exporter STINGAR-COLLECTOR
 destination 10.20.30.40
 transport udp 2055
 export-protocol netflow-v9
 template data timeout 60

flow monitor INGRESS-MON
 exporter STINGAR-COLLECTOR
 record netflow ipv4 original-input
 cache timeout active 60

interface GigabitEthernet0/0/0
 ip flow monitor INGRESS-MON input
```

On the collector side, the dropped flows are the ones where `egress_interface_snmp_index` resolves to `Null0` -- every modern collector (Akvorado, ElastiFlow, nfdump, Kentik) can filter on that. The query reads as "all flows whose output interface is the discard interface, in the last N minutes."

Newer IOS-XE (16.6+) and IOS-XR also support **direct flow monitoring on Null0 in egress direction**, which is cleaner:

```cisco
interface Null0
 ip flow monitor BLACKHOLE-MON output
```

The exported records on `BLACKHOLE-MON` are *exactly* the blackholed traffic. No collector-side filtering needed.

### ACL-logged variant (low-bandwidth deployments only)

Instead of routing the prefix to `Null0`, write an ACL that matches and logs it:

```cisco
ip access-list extended BLACKHOLE-INTEL
 deny ip any host 192.0.2.1 log-input
 permit ip any any

interface GigabitEthernet0/0/0
 ip access-group BLACKHOLE-INTEL in
```

`log-input` gives you source IP, MAC, ingress interface, packet count -- full per-flow detail in syslog. Avoid above ~1 Gbps; the CPU-punted logging path will overwhelm the route processor.

---

## Juniper JunOS

JunOS implements BHR slightly differently -- most operators use firewall filters with `discard` actions rather than null-route entries, because firewall filters run at line rate in the Trio/Express ASICs and natively support a `syslog` action:

```junos
firewall {
    family inet {
        filter STINGAR-BHR {
            term blackhole {
                from {
                    destination-address {
                        192.0.2.1/32;
                    }
                }
                then {
                    count blackhole-hits;
                    log;        /* PFE log buffer; capped, not unbounded */
                    syslog;     /* to RE syslog; rate-limit aggressively */
                    discard;
                }
            }
            term default { then accept; }
        }
    }
}
interfaces ge-0/0/0 { unit 0 { family inet { filter { input STINGAR-BHR; } } } }
```

For RTBH installed via BGP, the route goes to the discard interface:

```junos
routing-options {
    static {
        route 192.0.2.1/32 discard;
    }
}
```

### Capturing the events

- `show firewall filter STINGAR-BHR` -- counter + per-term hit count
- `show route forwarding-table destination 192.0.2.1` -- confirm discard
- **Inline-JFlow (Junos's IPFIX)** -- production-grade flow export, equivalent to Cisco's Flexible NetFlow. Configure under `services flow-monitoring version-ipfix`.
- **sFlow** -- sampled ingress flows; cheaper than Inline-JFlow but lower fidelity. Configure under `protocols sflow`.

Per-packet `syslog` on a firewall filter is rate-limited by default (`forwarding-options sampling`) -- do not disable that limit unless you really know your traffic profile.

---

## Arista EOS

Closest analogue: `Null0` interface, with sFlow as the standard telemetry path.

```eos
ip route 192.0.2.1/32 Null0
sflow source-interface Management1
sflow destination 10.20.30.40
sflow run
```

```bash
show interface Null0 counters
show ip route 192.0.2.1
```

Per-flow detail comes from the sFlow stream, not from EOS syslog. EOS also supports streaming telemetry via gNMI/OpenConfig (`TerminAttr`) if you would rather feed a time-series store directly.

---

## What this means architecturally

Three deployment patterns covering the realistic options:

### 1. Production-scale: BGP-RTBH + NetFlow (recommended)

```text
                      announces /32 with
                      community 65535:666
   [Trigger router] -------------------->  [Edge router 1, 2, ... n]
   (STINGAR-fed,                                |
    or operator-                                | installs route -> Null0
    triggered)                                  |
                                                v
                                       attacker traffic dropped
                                                |
                                                | NetFlow/IPFIX on
                                                | ingress + Null0
                                                v
                                      [Flow collector / SIEM]
                                       (filter: egress = Null0)
                                                |
                                                v
                                   "what got blackholed" report
```

Pros: line-rate, scales to multi-Tbps; the collector becomes the single pane of glass for all drops across all edges.

Cons: requires a flow collector (Akvorado / ElastiFlow / nfdump / Kentik); blackhole events are visible in flow data with a 1-2 minute lag (the flow cache timeout).

### 2. Mid-scale: ACL logging instead of Null0

Use it when total blackholed bandwidth is under ~500 Mbps. Pros: per-packet detail in normal syslog, no extra collector. Cons: hard ceiling on throughput before the route processor's CPU pegs.

### 3. High-fidelity forensics: blackhole + SPAN mirror

Mirror the same flows to an out-of-band IDS / Zeek / honeypot before they hit the blackhole. The production drop still happens at line rate; the mirror gives you full payload capture for the subset of traffic you care about.

---

## Roadmap candidate: STINGAR BGP-RTBH feed

The IDS/IPS Rules feature shipped in v2.3 covers the **Suricata / Snort signature** consumption pattern. A natural next-tier integration is **router-level enforcement** via BGP:

- A new feed exporter that emits STINGAR's blocklist as a BGP UPDATE stream tagged with the BLACKHOLE community (RFC 7999 `65535:666`), suitable for ingestion by an operator's trigger router.
- Or flat-file prefix-list output customers can pull into their own iBGP infrastructure.

This would extend STINGAR's enforcement reach from "host-level firewalls" (the EDL / IDS path) into "network-edge blackholing" (the RTBH path) -- a meaningful step for customers who run their own AS and want to drop attacker traffic before it ever reaches their edge firewalls. Reciprocally, those customers can feed NetFlow data from their edge routers back into the STINGAR EFK stack to close the loop and quantify "what was blackholed by STINGAR-fed intel."

Track on `Roadmap/roadmap.md` as a v2.4+ candidate.

---

## Related STINGAR work

- `Roadmap/roadmap.md` -- master backlog; the IDS/IPS Rules feature shipped in v2.3 is what feeds Suricata/Snort signatures into firewalls and IDS sensors. Drops triggered by those signatures land in the **Threat** log (PAN-OS) or equivalent on other platforms.
- `Releases/RELEASE_NOTES_2.3.md` -- IDS/IPS Rules feed endpoint (`GET /api/v2/ids-rules/feed?format=suricata|snort`).
- `Roadmap/blackhole_logging_report.md` -- standalone version of Part 2 above; the same content presented without the NGFW context for readers who want only the edge-router story.
- The Log Forwarding -> syslog -> fluentd -> Elasticsearch path described in Part 1, and the NetFlow -> collector -> Elasticsearch path described in Part 2, both terminate in the same `stingar-efk` stack STINGAR already uses for honeypot events. A customer who wires up both gets unified visibility across honeypot detections, NGFW drops, and edge-router blackholes in one place.

