"""Core data models for the QoB measurement plane.

These are intentionally lightweight (stdlib only) so Phase 1 can run on
captured fixtures without external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network, _BaseNetwork

ACCURACY_EXACT = "exact_unsampled"
ACCURACY_SAMPLED = "estimated_sampled"


def parse_ts(value: str | datetime) -> datetime:
    """Parse an ISO-8601 timestamp (accepts a trailing 'Z') as timezone-aware UTC."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class FlowRecord:
    """A single normalized flow record exported by an RTBH-handling router.

    `sampling_rate` is the exporter's 1:N rate (1 == unsampled). Packet/byte
    counts are raw (as reported); the correlator scales them by sampling_rate.
    """

    start: datetime
    end: datetime
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    proto: str
    packets: int
    bytes: int
    sampling_rate: int = 1
    device_id: str = ""

    def dedupe_key(self) -> tuple:
        """Identity of a flow independent of which router reported it.

        Used to drop duplicate observations of the same flow seen on multiple
        routers (asymmetric/ECMP paths) before summing.
        """
        return (
            self.src_addr,
            self.dst_addr,
            self.src_port,
            self.dst_port,
            self.proto,
            self.start.isoformat(),
            self.end.isoformat(),
        )


@dataclass(frozen=True)
class BlockEntry:
    """An entry from the BHR blocked-IP list (the join key / ground truth)."""

    network: _BaseNetwork
    indicator_id: str
    source: str = ""
    why: str = ""
    block_start: datetime | None = None
    block_end: datetime | None = None
    ident: str = ""

    def contains(self, ip: str) -> bool:
        return ip_address(ip) in self.network

    def active_at(self, when: datetime) -> bool:
        if self.block_start is not None and when < self.block_start:
            return False
        if self.block_end is not None and when >= self.block_end:
            return False
        return True

    @classmethod
    def from_row(cls, row: dict) -> "BlockEntry":
        def _opt_ts(key: str) -> datetime | None:
            val = (row.get(key) or "").strip()
            return parse_ts(val) if val else None

        return cls(
            network=ip_network(row["cidr"].strip(), strict=False),
            indicator_id=(row.get("indicator_id") or "").strip(),
            source=(row.get("source") or "").strip(),
            why=(row.get("why") or "").strip(),
            block_start=_opt_ts("added"),
            block_end=_opt_ts("removed"),
            ident=(row.get("ident") or "").strip(),
        )


@dataclass
class ImpactCount:
    """Aggregated per-IP, per-window drop counts feeding QoB `impact_score`."""

    ip: str
    window_start: datetime
    window_end: datetime
    bh_hits: int = 0
    bh_bytes: int = 0
    raw_hits: int = 0
    raw_bytes: int = 0
    flows: int = 0
    sampling_rate: int = 1
    accuracy: str = ACCURACY_SAMPLED
    indicator_id: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "window_start": self.window_start.isoformat().replace("+00:00", "Z"),
            "window_end": self.window_end.isoformat().replace("+00:00", "Z"),
            "bh_hits": self.bh_hits,
            "bh_bytes": self.bh_bytes,
            "raw_hits": self.raw_hits,
            "raw_bytes": self.raw_bytes,
            "flows": self.flows,
            "sampling_rate": self.sampling_rate,
            "accuracy": self.accuracy,
            "indicator_id": self.indicator_id,
        }
