"""Phase 2 stub: scheduled collector reader.

In production this reads rotated nfcapd files (or a goflow2/Kafka stream),
normalizes them via qob.ingest.flow_counters, fetches the current blocked-IP
list via qob.ingest.bhr_list, correlates, and writes idempotent rows to the
QoB store keyed by (ip, window_start, device).

For Phase 1 the correlation logic is exercised offline by jobs/compute_qob.py
against captured fixtures; this module is intentionally a placeholder.
"""

from __future__ import annotations

import time

POLL_INTERVAL_SECONDS = 300  # 5 min, matches plan-netflow-counting.md §3


def run_forever() -> None:  # pragma: no cover - operational loop
    raise NotImplementedError(
        "Phase 2: wire nfcapd/goflow2 source + BHR list fetch + idempotent store writes."
    )


if __name__ == "__main__":  # pragma: no cover
    while True:
        run_forever()
        time.sleep(POLL_INTERVAL_SECONDS)
