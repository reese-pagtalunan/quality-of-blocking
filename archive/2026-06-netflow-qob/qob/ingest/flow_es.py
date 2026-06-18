"""Elasticsearch flow source (e.g. ElastiFlow) for the QoB measurement plane.

When the collector ships decoded NetFlow/IPFIX/sFlow into Elasticsearch
(ElastiFlow being the batteries-included option), we don't pull raw flows into
Python — we push the aggregation INTO Elasticsearch and read back small
per-(ip, window) buckets. This scales far better than CSV replay at attack
volume and reuses the cluster you already run for STINGAR/Cowrie.

Design notes:
* The blocked-IP list (the join key) still comes from BHR via ``bhr_list`` — ES
  holds flows, BHR holds the ground truth of who is blocked and when.
* We filter flows to blocked sources using ES ``term`` queries on the ``ip``
  field, which natively understands CIDR (so ``/32`` and wider both work).
* Sampling: we sum the *raw* packet/byte counts per window and take the
  ``max`` sampling interval in that window as the rate, then scale in Python —
  this avoids ES runtime scripts and mirrors the CSV path's semantics.
* Active-window filtering: ES sums every doc in the time range, so we post-
  filter each bucket through ``BlockedSet.match(ip, window_start)`` to honor
  per-IP block start/end and attach the right ``indicator_id``.

The ES client is injected (any object with a ``.search(index=, body=)`` method),
so this module is fully testable against a fake client without a live cluster.

Known limitation (vs the CSV path): multi-router duplicate flows are summed,
not deduped — ES aggregation can't easily drop duplicate observations of the
same flow seen on several exporters. Handle this upstream (dedupe at the
collector, or key on a unique flow id / ElastiFlow flow hash) before trusting
absolute counts. Relative ranking is unaffected if duplication is uniform.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..models import (
    ACCURACY_EXACT,
    ACCURACY_SAMPLED,
    BlockEntry,
    ImpactCount,
)
from ..join_flows import BlockedSet

DEFAULT_INDEX = "elastiflow-flow-*"


@dataclass(frozen=True)
class EsFieldMap:
    """Field names in the ES flow index. Defaults match ElastiFlow's schema."""

    src_ip: str = "source.ip"
    dst_ip: str = "destination.ip"
    packets: str = "flow.packets"
    bytes: str = "flow.bytes"
    sampling: str = "flow.sampling_interval"
    timestamp: str = "@timestamp"


# Default = ElastiFlow schema.
ELASTIFLOW_FIELD_MAP = EsFieldMap()

# Chosen pipeline (see plan §3.1): goflow2 → Fluentd → Elasticsearch.
# These are goflow2's native JSON keys (Fluentd passes them through and sets
# @timestamp from time_flow_start_ns). NOTE: map `src_addr` as ES `ip` type in
# the index template so CIDR `term` filtering and the `terms` agg work; else use
# `src_addr.keyword` here (exact match, fine for /32 blocks).
GOFLOW2_FIELD_MAP = EsFieldMap(
    src_ip="src_addr",
    dst_ip="dst_addr",
    packets="packets",
    bytes="bytes",
    sampling="sampling_rate",
    timestamp="@timestamp",
)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def block_time_range(entries: list[BlockEntry]) -> tuple[datetime, datetime]:
    """Min block_start .. max block_end (open-ended blocks extend to now)."""
    now = datetime.now(timezone.utc)
    starts = [e.block_start for e in entries if e.block_start]
    ends = [e.block_end or now for e in entries]
    start = min(starts) if starts else now - timedelta(days=1)
    end = max(ends) if ends else now
    return start, end


class EsFlowSource:
    """Query an ES flow index and return per-(ip, window) ImpactCounts."""

    def __init__(
        self,
        client,
        index: str = DEFAULT_INDEX,
        fields: EsFieldMap = ELASTIFLOW_FIELD_MAP,
        max_ips: int = 10_000,
    ):
        self.client = client
        self.index = index
        self.f = fields
        self.max_ips = max_ips

    def build_agg_body(
        self,
        entries: list[BlockEntry],
        start: datetime,
        end: datetime,
        window_seconds: int,
    ) -> dict:
        # CIDR-aware source filter: one term per blocked network. ES `ip` fields
        # match CIDR in a term query, so /32 and wider both work.
        should = [{"term": {self.f.src_ip: str(e.network)}} for e in entries]
        return {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {self.f.timestamp: {"gte": _iso(start), "lt": _iso(end)}}},
                        {"bool": {"should": should, "minimum_should_match": 1}},
                    ]
                }
            },
            "aggs": {
                "by_ip": {
                    "terms": {"field": self.f.src_ip, "size": self.max_ips},
                    "aggs": {
                        "by_window": {
                            "date_histogram": {
                                "field": self.f.timestamp,
                                "fixed_interval": f"{window_seconds}s",
                            },
                            "aggs": {
                                "packets": {"sum": {"field": self.f.packets}},
                                "bytes": {"sum": {"field": self.f.bytes}},
                                "sampling": {"max": {"field": self.f.sampling}},
                            },
                        }
                    },
                }
            },
        }

    def aggregate(
        self,
        entries: list[BlockEntry],
        start: datetime,
        end: datetime,
        window_seconds: int = 300,
    ) -> list[ImpactCount]:
        body = self.build_agg_body(entries, start, end, window_seconds)
        resp = self.client.search(index=self.index, body=body)
        return parse_agg_response(resp, BlockedSet(entries), window_seconds)


def parse_agg_response(
    resp: dict,
    blocked: BlockedSet,
    window_seconds: int,
) -> list[ImpactCount]:
    """Turn an ES date_histogram response into active, scaled ImpactCounts."""
    out: list[ImpactCount] = []
    aggs = resp.get("aggregations") or {}
    ip_buckets = (aggs.get("by_ip") or {}).get("buckets") or []
    for ip_bucket in ip_buckets:
        ip = ip_bucket["key"]
        for w in (ip_bucket.get("by_window") or {}).get("buckets") or []:
            # date_histogram bucket key is epoch milliseconds.
            window_start = datetime.fromtimestamp(w["key"] / 1000, tz=timezone.utc)

            entry = blocked.match(ip, window_start)
            if entry is None:  # window outside this IP's active block period
                continue

            raw_hits = int((w.get("packets") or {}).get("value") or 0)
            raw_bytes = int((w.get("bytes") or {}).get("value") or 0)
            if raw_hits == 0 and raw_bytes == 0:
                continue

            rate = int((w.get("sampling") or {}).get("value") or 1) or 1
            out.append(
                ImpactCount(
                    ip=ip,
                    window_start=window_start,
                    window_end=window_start + timedelta(seconds=window_seconds),
                    bh_hits=raw_hits * rate,
                    bh_bytes=raw_bytes * rate,
                    raw_hits=raw_hits,
                    raw_bytes=raw_bytes,
                    flows=int(w.get("doc_count") or 0),
                    sampling_rate=rate,
                    accuracy=ACCURACY_SAMPLED if rate > 1 else ACCURACY_EXACT,
                    indicator_id=entry.indicator_id,
                )
            )
    return sorted(out, key=lambda b: (b.ip, b.window_start))
