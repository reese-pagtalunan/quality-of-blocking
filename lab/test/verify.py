#!/usr/bin/env python3
"""Query Elasticsearch for the lab test source and report flow-derived counts,
reusing the production code path (qob.ingest.flow_es).

This demonstrates flow_es.py against a REAL NetFlow stream (not fixtures), and
is what you run before/after the RTBH block in the A/B test.

Usage:
    python lab/test/verify.py --es-url http://localhost:9200 \
        --src 10.0.1.66 --minutes 10

Requires:  pip install -e '.[es]'   (the elasticsearch client)
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network

# Make the repo importable when run directly from lab/test/.
sys.path.insert(0, __import__("os").path.abspath(
    __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "..")
))

from qob.ingest.flow_es import GOFLOW2_FIELD_MAP, EsFlowSource  # noqa: E402
from qob.models import BlockEntry  # noqa: E402
from qob.scoring import impact_score  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Verify lab flow counts via Elasticsearch.")
    p.add_argument("--es-url", default="http://localhost:9200")
    p.add_argument("--src", default="10.0.1.66", help="Test source IP to look for")
    p.add_argument("--index", default="qob-flow-*")
    p.add_argument("--minutes", type=int, default=10, help="Look-back window")
    p.add_argument("--window", type=int, default=60, help="Aggregation bucket seconds")
    p.add_argument("--label", default="", help="Optional label printed with results (e.g. 'phase A')")
    args = p.parse_args(argv)

    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        print("Install the elasticsearch client: pip install -e '.[es]'", file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=args.minutes)

    # Treat the test source as "blocked" for the whole look-back so every recent
    # flow counts — we just want to see whether ES has flow for it at all.
    entry = BlockEntry(
        network=ip_network(f"{args.src}/32"),
        indicator_id="lab",
        block_start=start,
        block_end=None,
    )

    client = Elasticsearch(args.es_url)
    # goflow2 → Fluentd → ES, so use goflow2's field names.
    source = EsFlowSource(client, index=args.index, fields=GOFLOW2_FIELD_MAP)
    counts = source.aggregate([entry], start, now, window_seconds=args.window)

    tag = f" [{args.label}]" if args.label else ""
    total = sum(c.bh_hits for c in counts)
    print(f"=== flow for {args.src} in last {args.minutes}m{tag} ===")
    if not counts:
        print("  (no flow records found for this source)")
    for c in counts:
        print(
            f"  {c.window_start.isoformat()}  hits={c.bh_hits}  bytes={c.bh_bytes}"
            f"  flows={c.flows}  sampling={c.sampling_rate}  score={impact_score(c):.1f}"
        )
    print(f"  TOTAL hits={total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
