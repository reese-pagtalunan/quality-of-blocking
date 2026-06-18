# Edge Router Blackhole (BHR/RTBH) Logging Report

**Default platform:** Cisco IOS-XE (with equivalents for Juniper JunOS and Arista EOS at the end).

**Scope:** This document is the focused single-topic version of Part 2 of `Roadmap/blocking_and_blackhole_logging_report.md`. It answers exactly one question: when an edge router blackholes attacker traffic (typically via BGP-triggered RTBH with the RFC 7999 `BLACKHOLE` community `65535:666`), can we get logs back -- and if so, where from? For the NGFW-tier equivalent (Palo Alto / Fortinet / Cisco Firepower / Check Point / Juniper SRX), see the combined report.

**Context for STINGAR operators:** customers who run their own AS may want to drop attacker traffic at the network edge (line-rate, before it reaches any firewall) using BGP-RTBH driven by STINGAR's blocklist. This is the operational reference for closing the loop on "did the router actually drop what we told it to drop, and how much did it drop?"

---

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

- `Roadmap/blocking_and_blackhole_logging_report.md` -- the combined report; this file is Part 2 of that document, lifted out for readers who only need the edge-router view.
- `Roadmap/roadmap.md` -- master backlog; the IDS/IPS Rules feature shipped in v2.3 is the closest precedent for a BGP-RTBH feed.
- `Releases/RELEASE_NOTES_2.3.md` -- IDS/IPS Rules feed endpoint (`GET /api/v2/ids-rules/feed?format=suricata|snort`); the BGP-RTBH feed would live alongside it as a new format.
- The NetFlow -> collector -> Elasticsearch path described above terminates in the same `stingar-efk` stack STINGAR already uses for honeypot events; a customer who wires up edge-router flow export gets unified visibility across honeypot detections, NGFW drops, and edge-router blackholes in one Elasticsearch.


