"""Redis store for QoB counts (the lean, 7-day-TTL serving layer).

Why Redis instead of Elasticsearch for these counts (plan §3.1):
* We only need per-IP packet/byte counts for ~7 days — not raw flow.
* Aggregating AT INGEST means the flow firehose never touches the ES cluster
  (protects both disk AND indexing load).
* Per-key TTL == "useless after a week" for free.
* Redis is already in the stack (hpfeeds-bhr uses it).

This module reuses the join/window/sampling logic from ``join_flows.correlate``
(single source of truth) and writes the resulting per-(ip, day) ImpactCounts as
Redis counters + a ranking sorted set.

The Redis client is injected (any object exposing the redis-py methods used
here), so this is fully testable against a fake in-memory client.

Key schema (prefix default ``qob``):
    qob:hits:{ip}:{YYYYMMDD}   INCRBY  (packets * sampling_rate)   + TTL
    qob:bytes:{ip}:{YYYYMMDD}  INCRBY  (bytes  * sampling_rate)    + TTL
    qob:rank:{YYYYMMDD}        ZINCRBY by hits, member=ip          + TTL
    qob:meta:{ip}              HSET indicator_id                   + TTL
    qob:seen:{flowhash}        SET NX EX (optional dedupe guard)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..join_flows import correlate
from ..models import BlockEntry, FlowRecord, ImpactCount  # noqa: F401 (re-export friendly)

DEFAULT_PREFIX = "qob"
# 8 days so a rolling 7-day sum always includes a full 7th day before expiry.
DEFAULT_TTL_DAYS = 8


def _day(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y%m%d")


def _as_str(v) -> str:
    return v.decode() if isinstance(v, (bytes, bytearray)) else str(v)


@dataclass
class RedisQobStore:
    client: object
    prefix: str = DEFAULT_PREFIX
    ttl_days: int = DEFAULT_TTL_DAYS

    @property
    def ttl_seconds(self) -> int:
        return self.ttl_days * 86400

    # --- write side ------------------------------------------------------
    def record_counts(self, counts: list[ImpactCount]) -> None:
        """Additively write per-(ip, day) counters + ranking with TTL."""
        ttl = self.ttl_seconds
        for c in counts:
            day = _day(c.window_start)
            hk = f"{self.prefix}:hits:{c.ip}:{day}"
            bk = f"{self.prefix}:bytes:{c.ip}:{day}"
            rk = f"{self.prefix}:rank:{day}"

            self.client.incrby(hk, c.bh_hits)
            self.client.expire(hk, ttl)
            self.client.incrby(bk, c.bh_bytes)
            self.client.expire(bk, ttl)
            self.client.zincrby(rk, c.bh_hits, c.ip)
            self.client.expire(rk, ttl)
            if c.indicator_id:
                mk = f"{self.prefix}:meta:{c.ip}"
                self.client.hset(mk, "indicator_id", c.indicator_id)
                self.client.expire(mk, ttl)

    def seen_flow(self, flow: FlowRecord, guard_seconds: int = 120) -> bool:
        """Cross-batch dedupe guard for multi-router duplicates.

        Returns True if this flow identity is NEW (should be counted), False if
        it was already seen within guard_seconds. Single-exporter setups can
        skip this; multi-router setups should gate counting on it.
        """
        key = f"{self.prefix}:seen:{abs(hash(flow.dedupe_key()))}"
        return bool(self.client.set(key, 1, nx=True, ex=guard_seconds))

    # --- read side (serving) --------------------------------------------
    def ip_total(self, ip: str, days: int = 7) -> dict:
        now = datetime.now(timezone.utc)
        hits = bytes_ = 0
        for i in range(days):
            day = (now - timedelta(days=i)).strftime("%Y%m%d")
            h = self.client.get(f"{self.prefix}:hits:{ip}:{day}")
            b = self.client.get(f"{self.prefix}:bytes:{ip}:{day}")
            hits += int(h) if h else 0
            bytes_ += int(b) if b else 0
        return {"ip": ip, "days": days, "bh_hits": hits, "bh_bytes": bytes_}

    def top(self, n: int = 10, days: int = 7) -> list[tuple[str, int]]:
        """Top-N source IPs by hits over the last `days` (merged in Python)."""
        now = datetime.now(timezone.utc)
        merged: dict[str, float] = {}
        for i in range(days):
            day = (now - timedelta(days=i)).strftime("%Y%m%d")
            pairs = self.client.zrange(
                f"{self.prefix}:rank:{day}", 0, -1, desc=True, withscores=True
            )
            for member, score in pairs:
                merged[_as_str(member)] = merged.get(_as_str(member), 0) + score
        ranked = sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:n]
        return [(ip, int(score)) for ip, score in ranked]


def ingest_flows(
    flows: list[FlowRecord],
    blocked,
    store: RedisQobStore,
    window_seconds: int = 86400,
    dedupe: bool = True,
) -> list[ImpactCount]:
    """Join flows ⋈ blocked set, aggregate per (ip, window), write to Redis.

    `window_seconds` defaults to a day so the Redis buckets line up with the
    7-day TTL retention. Returns the counts written (handy for inspection/tests).
    """
    counts = correlate(flows, blocked, window_seconds=window_seconds, dedupe=dedupe)
    store.record_counts(counts)
    return counts
