#!/usr/bin/env python3
"""Read the QoB counts the consumer wrote into Redis and report them.

Reuses the production read path (qob.ingest.flow_redis.RedisQobStore) against the
REAL pipeline (goflow2 → consumer → Redis), so this is what you run before/after
the RTBH block in the A/B test.

Usage:
    python lab/test/verify.py --redis-host localhost --src 10.0.1.66 --label "phase A"

Requires:  pip install -e '.[redis]'   (the redis client)
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

# Make the repo importable when run directly from lab/test/.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from qob.ingest.flow_redis import RedisQobStore  # noqa: E402
from qob.models import ImpactCount  # noqa: E402
from qob.scoring import impact_score  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Verify lab flow counts via Redis.")
    p.add_argument("--redis-host", default=os.environ.get("REDIS_HOST", "localhost"))
    p.add_argument("--redis-port", type=int, default=int(os.environ.get("REDIS_PORT", "6379")))
    p.add_argument("--src", default="10.0.1.66", help="Test source IP to look for")
    p.add_argument("--days", type=int, default=7, help="Rolling window of daily buckets")
    p.add_argument("--label", default="", help="Optional label printed with results")
    args = p.parse_args(argv)

    try:
        import redis
    except ImportError:
        print("Install the redis client: pip install -e '.[redis]'", file=sys.stderr)
        return 2

    client = redis.Redis(host=args.redis_host, port=args.redis_port)
    store = RedisQobStore(client)

    total = store.ip_total(args.src, days=args.days)
    tag = f" [{args.label}]" if args.label else ""
    print(f"=== QoB counts for {args.src} (last {args.days}d){tag} ===")
    if total["bh_hits"] == 0:
        print("  (no counts in Redis for this source yet)")
    else:
        now = datetime.now(timezone.utc)
        score = impact_score(ImpactCount(
            ip=args.src, window_start=now, window_end=now,
            bh_hits=total["bh_hits"], bh_bytes=total["bh_bytes"],
        ))
        print(f"  bh_hits={total['bh_hits']}  bh_bytes={total['bh_bytes']}  score={score:.1f}")

    top = store.top(n=5, days=args.days)
    if top:
        print("  -- top sources by dropped packets --")
        for ip, hits in top:
            print(f"     {ip:<18} {hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
