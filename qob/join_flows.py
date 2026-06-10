"""Correlate flow telemetry with the BHR blocked-IP list (Option 1, §5).

Deployment is SOURCE-BASED RTBH, so the attacker is the flow *source*. For each
flow we:

1. take the attacker IP from ``flow.src_addr``;
2. find a block entry that contains it and is active at the flow's start time;
3. if matched, add ``packets * sampling_rate`` / ``bytes * sampling_rate`` to the
   ``(ip, window)`` bucket;
4. attach the block's ``indicator_id``.

Duplicate observations of the same flow seen on multiple routers are deduped
before summing. Sampling is accepted for v1 (counts are scaled and tagged
``estimated_sampled``); exactness is a later refinement.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from .models import (
    ACCURACY_EXACT,
    ACCURACY_SAMPLED,
    BlockEntry,
    FlowRecord,
    ImpactCount,
)

DEFAULT_WINDOW_SECONDS = 300


class BlockedSet:
    """Indexed lookup of blocked entries by source IP and time."""

    def __init__(self, entries: list[BlockEntry]):
        self._host_index: dict[str, list[BlockEntry]] = defaultdict(list)
        self._net_entries: list[BlockEntry] = []
        for entry in entries:
            if entry.network.num_addresses == 1:
                self._host_index[str(entry.network.network_address)].append(entry)
            else:
                self._net_entries.append(entry)

    def match(self, ip: str, when: datetime) -> BlockEntry | None:
        """Return the first block entry covering `ip` and active at `when`."""
        for entry in self._host_index.get(str(ip_address(ip)), ()):
            if entry.active_at(when):
                return entry
        for entry in self._net_entries:
            if entry.contains(ip) and entry.active_at(when):
                return entry
        return None


def align_window(when: datetime, window_seconds: int) -> datetime:
    epoch = int(when.astimezone(timezone.utc).timestamp())
    start = epoch - (epoch % window_seconds)
    return datetime.fromtimestamp(start, tz=timezone.utc)


def dedupe_flows(flows: list[FlowRecord]) -> list[FlowRecord]:
    """Keep one flow per identity (drop duplicates seen on multiple routers)."""
    seen: set[tuple] = set()
    out: list[FlowRecord] = []
    for flow in flows:
        key = flow.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(flow)
    return out


def correlate(
    flows: list[FlowRecord],
    blocked: BlockedSet,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    dedupe: bool = True,
) -> list[ImpactCount]:
    """Aggregate dropped traffic per (blocked source IP, time window)."""
    if dedupe:
        flows = dedupe_flows(flows)

    buckets: dict[tuple[str, datetime], ImpactCount] = {}
    for flow in flows:
        entry = blocked.match(flow.src_addr, flow.start)
        if entry is None:
            continue

        window_start = align_window(flow.start, window_seconds)
        key = (flow.src_addr, window_start)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = ImpactCount(
                ip=flow.src_addr,
                window_start=window_start,
                window_end=window_start + timedelta(seconds=window_seconds),
                indicator_id=entry.indicator_id,
                sampling_rate=flow.sampling_rate,
            )
            buckets[key] = bucket

        scale = max(flow.sampling_rate, 1)
        bucket.raw_hits += flow.packets
        bucket.raw_bytes += flow.bytes
        bucket.bh_hits += flow.packets * scale
        bucket.bh_bytes += flow.bytes * scale
        bucket.flows += 1
        if scale > 1:
            bucket.sampling_rate = scale
            bucket.accuracy = ACCURACY_SAMPLED
        elif bucket.flows == 1:
            bucket.accuracy = ACCURACY_EXACT

    return sorted(buckets.values(), key=lambda b: (b.ip, b.window_start))
