#!/usr/bin/env python3
"""Lab consumer: goflow2 JSON file -> qob.flow_redis -> Redis.

This is the lab stand-in for the production consumer described in plan §3.1.
It tails the JSON file goflow2 writes, parses each record, joins it against the
BHR blocked set (a static CSV here instead of a live BHR feed), and writes
per-(ip, day) counters into Redis with a TTL.

Env (set in topology.clab.yml):
  REDIS_HOST, REDIS_PORT, FLOW_FILE, BLOCKLIST, WINDOW
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, "/app")

import redis  # noqa: E402

from qob.ingest.bhr_list import load_blocklist  # noqa: E402
from qob.ingest.flow_counters import flow_from_goflow2  # noqa: E402
from qob.ingest.flow_redis import RedisQobStore, ingest_flows  # noqa: E402
from qob.join_flows import BlockedSet  # noqa: E402

FLOW_FILE = os.environ.get("FLOW_FILE", "/var/log/goflow2/flows.json")
BLOCKLIST = os.environ.get("BLOCKLIST", "/app/lab/consumer/blocklist.csv")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
WINDOW = int(os.environ.get("WINDOW", "86400"))

FLUSH_EVERY = 200      # records
FLUSH_SECONDS = 2.0


def main() -> None:
    entries = load_blocklist(BLOCKLIST)
    blocked = BlockedSet(entries)
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
    store = RedisQobStore(client)
    print(
        f"[consumer] blocklist={len(entries)} entries; "
        f"tailing {FLOW_FILE} -> redis {REDIS_HOST}:{REDIS_PORT}",
        flush=True,
    )

    while not os.path.exists(FLOW_FILE):
        print(f"[consumer] waiting for {FLOW_FILE} ...", flush=True)
        time.sleep(1)

    with open(FLOW_FILE, encoding="utf-8") as fh:
        buf = []
        last = time.time()
        while True:
            line = fh.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        obj = json.loads(line)
                        if obj.get("src_addr"):
                            buf.append(flow_from_goflow2(obj))
                    except (ValueError, KeyError):
                        pass
            else:
                time.sleep(0.5)

            due = len(buf) >= FLUSH_EVERY or (buf and time.time() - last > FLUSH_SECONDS)
            if due:
                counts = ingest_flows(buf, blocked, store, window_seconds=WINDOW)
                matched = sum(c.bh_hits for c in counts)
                if counts:
                    print(
                        f"[consumer] flushed {len(buf)} flows -> "
                        f"{len(counts)} (ip,day) counts, {matched} hits",
                        flush=True,
                    )
                buf = []
                last = time.time()


if __name__ == "__main__":
    main()
