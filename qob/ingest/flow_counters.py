"""Parse flow telemetry from the collector into normalized FlowRecords.

Phase 1 reads a normalized CSV (the schema we emit from the collector or hand
to tests). A column-name mapping for ``nfdump -o csv`` output is included so a
real nfcapd export can be ingested by aliasing its native field names.

Normalized CSV headers:
    start,end,src,dst,src_port,dst_port,proto,packets,bytes,sampling_rate,device
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..models import FlowRecord, parse_ts

# nfdump -o csv field names → our normalized keys.
NFDUMP_FIELD_MAP = {
    "ts": "start",
    "te": "end",
    "sa": "src",
    "da": "dst",
    "sp": "src_port",
    "dp": "dst_port",
    "pr": "proto",
    "ipkt": "packets",
    "ibyt": "bytes",
}


def _canonicalize(row: dict) -> dict:
    out: dict = {}
    for key, value in row.items():
        if key is None:
            continue
        k = key.strip().lower()
        canon = NFDUMP_FIELD_MAP.get(k, k)
        if canon not in out:
            out[canon] = value
    return out


def _row_to_flow(row: dict) -> FlowRecord:
    canon = _canonicalize(row)
    return FlowRecord(
        start=parse_ts(canon["start"]),
        end=parse_ts(canon.get("end") or canon["start"]),
        src_addr=canon["src"].strip(),
        dst_addr=(canon.get("dst") or "").strip(),
        src_port=int(canon.get("src_port") or 0),
        dst_port=int(canon.get("dst_port") or 0),
        proto=(canon.get("proto") or "").strip().upper(),
        packets=int(canon.get("packets") or 0),
        bytes=int(canon.get("bytes") or 0),
        sampling_rate=int(canon.get("sampling_rate") or 1),
        device_id=(canon.get("device") or "").strip(),
    )


def from_rows(rows) -> list[FlowRecord]:
    flows: list[FlowRecord] = []
    for row in rows:
        if not (row.get("src") or row.get("sa")):
            continue
        flows.append(_row_to_flow(row))
    return flows


def load_flows_csv(path: str | Path) -> list[FlowRecord]:
    with open(path, newline="", encoding="utf-8") as fh:
        return from_rows(csv.DictReader(fh))
