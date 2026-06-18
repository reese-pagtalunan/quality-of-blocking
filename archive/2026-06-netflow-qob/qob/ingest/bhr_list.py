"""Load a blocked-IP list (the join key for QoB).

This is simply a CSV or JSON file that answers: *which IPs are blocked, when,
and which detection caused it?* QoB joins NetFlow against these rows — only
flows from a listed source IP during an active block window count toward
``bh_hits`` / ``bh_bytes``.

The module name ``bhr_list`` is historical. The file is **not** defined by BHR
(the Black Hole Router). In production it might be a STINGAR export, a Splunk
CSV snapshot, a captured ``publist.csv``, or any file with the expected columns.

Supported formats:

* CSV — headers like ``cidr,indicator_id,source,why,added,removed,ident``
  (extra columns ignored; optional columns tolerated).
* JSON — a list of objects, or an object with a ``"results"`` / ``"blocks"`` /
  ``"data"`` list.

Phase 1 reads local paths only. A future ``poll`` can fetch a remote URL and
hand the parsed rows to :func:`from_rows`.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..models import BlockEntry

# Map alternative column names onto our canonical row keys.
FIELD_ALIASES = {
    "cidr": "cidr",
    "block": "cidr",
    "ip": "cidr",
    "indicator_id": "indicator_id",
    "indicator": "indicator_id",
    "source": "source",
    "why": "why",
    "comment": "why",
    "added": "added",
    "added_at": "added",
    "time": "added",
    "removed": "removed",
    "removed_at": "removed",
    "unblock_at": "removed",
    "ident": "ident",
    "who": "ident",
}


def _canonicalize(row: dict) -> dict:
    out: dict = {}
    for key, value in row.items():
        if key is None:
            continue
        canon = FIELD_ALIASES.get(key.strip().lower())
        if canon and canon not in out:
            out[canon] = value
    return out


def from_rows(rows) -> list[BlockEntry]:
    entries: list[BlockEntry] = []
    for row in rows:
        canon = _canonicalize(row)
        if not canon.get("cidr"):
            continue
        entries.append(BlockEntry.from_row(canon))
    return entries


def load_csv(path: str | Path) -> list[BlockEntry]:
    with open(path, newline="", encoding="utf-8") as fh:
        return from_rows(csv.DictReader(fh))


def load_json(path: str | Path) -> list[BlockEntry]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("results") or data.get("blocks") or data.get("data") or []
    return from_rows(data)


def load_blocklist(path: str | Path) -> list[BlockEntry]:
    """Auto-detect CSV vs JSON by file extension."""
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return load_json(path)
    return load_csv(path)
