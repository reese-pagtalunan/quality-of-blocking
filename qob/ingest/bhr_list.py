"""Load the BHR blocked-IP list (the authoritative join key).

Supports two replay/production sources:

* CSV  — e.g. BHR's ``/bhr/publist.csv`` feed, or a captured snapshot. Expected
  headers: ``cidr,indicator_id,source,why,added,removed,ident`` (extra columns
  ignored; missing optional columns tolerated).
* JSON — e.g. the ``/bhr/api/query_limited`` endpoint, a list of objects or an
  object with a ``"results"``/``"blocks"`` list.

For Phase 1 we read from local files. A future ``poll`` can fetch the live
endpoint and hand the parsed rows to :func:`from_rows`.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..models import BlockEntry

# Map alternative field names (BHR API / publist) onto our canonical row keys.
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
