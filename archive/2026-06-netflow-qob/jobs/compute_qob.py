"""Phase 1 CLI: correlate flows with a blocked-IP list and emit QoB rows.

Two flow sources:

* csv (default) — replay captured/normalized flow CSV (great for tests, no infra):
    python -m jobs.compute_qob --source csv \
        --blocklist tests/fixtures/publist.csv \
        --flows tests/fixtures/flows.csv --window 3600

* es — aggregate flows straight out of Elasticsearch / ElastiFlow:
    python -m jobs.compute_qob --source es \
        --blocklist tests/fixtures/publist.csv \
        --es-url https://es.example.edu:9200 \
        --es-index 'elastiflow-flow-*' --window 300
"""

from __future__ import annotations

import argparse
import json
import sys

from qob.ingest import bhr_list
from qob.scoring import ImpactWeights, impact_score


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compute per-IP QoB impact from flows.")
    parser.add_argument("--source", choices=["csv", "es"], default="csv", help="Flow source")
    parser.add_argument("--blocklist", required=True, help="BHR blocked-IP list (CSV or JSON)")
    parser.add_argument("--window", type=int, default=300, help="Window size in seconds")
    parser.add_argument("--out", default="-", help="Output JSONL path ('-' for stdout)")

    csv_grp = parser.add_argument_group("csv source")
    csv_grp.add_argument("--flows", help="Normalized flow CSV from the collector")
    csv_grp.add_argument("--no-dedupe", action="store_true", help="Disable multi-router flow dedupe")

    es_grp = parser.add_argument_group("es source")
    es_grp.add_argument("--es-url", help="Elasticsearch URL")
    es_grp.add_argument("--es-index", default="elastiflow-flow-*", help="Flow index pattern")
    es_grp.add_argument("--es-api-key", help="ES API key (optional)")
    es_grp.add_argument("--from", dest="time_from", help="Range start ISO (default: min block start)")
    es_grp.add_argument("--to", dest="time_to", help="Range end ISO (default: max block end / now)")
    return parser


def _counts_from_csv(args, entries):
    from qob.ingest import flow_counters
    from qob.join_flows import BlockedSet, correlate

    if not args.flows:
        raise SystemExit("--flows is required when --source csv")
    flows = flow_counters.load_flows_csv(args.flows)
    counts = correlate(flows, BlockedSet(entries), window_seconds=args.window, dedupe=not args.no_dedupe)
    return counts, len(flows)


def _counts_from_es(args, entries):
    from qob.ingest.flow_es import EsFlowSource, block_time_range
    from qob.models import parse_ts

    if not args.es_url:
        raise SystemExit("--es-url is required when --source es")
    try:
        from elasticsearch import Elasticsearch
    except ImportError as exc:  # pragma: no cover - depends on optional dep
        raise SystemExit("Install the 'elasticsearch' package to use --source es") from exc

    kwargs = {"api_key": args.es_api_key} if args.es_api_key else {}
    client = Elasticsearch(args.es_url, **kwargs)

    default_start, default_end = block_time_range(entries)
    start = parse_ts(args.time_from) if args.time_from else default_start
    end = parse_ts(args.time_to) if args.time_to else default_end

    source = EsFlowSource(client, index=args.es_index)
    counts = source.aggregate(entries, start, end, window_seconds=args.window)
    return counts, None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    entries = bhr_list.load_blocklist(args.blocklist)
    if args.source == "csv":
        counts, n_flows = _counts_from_csv(args, entries)
    else:
        counts, n_flows = _counts_from_es(args, entries)

    weights = ImpactWeights()
    out = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    try:
        for count in counts:
            row = count.to_dict()
            row["impact_score"] = round(impact_score(count, weights), 4)
            out.write(json.dumps(row) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()

    flows_msg = f"{n_flows} flows" if n_flows is not None else f"ES:{args.es_index}"
    print(
        f"[qob] source={args.source} {len(entries)} block entries, {flows_msg} -> {len(counts)} impact rows",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
