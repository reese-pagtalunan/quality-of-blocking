from pathlib import Path

from qob.ingest import bhr_list, flow_counters
from qob.join_flows import BlockedSet, correlate, dedupe_flows
from qob.models import ACCURACY_SAMPLED

FIXTURES = Path(__file__).parent / "fixtures"
WINDOW = 3600  # 1h windows make the fixture buckets easy to reason about


def _correlate():
    entries = bhr_list.load_blocklist(FIXTURES / "publist.csv")
    flows = flow_counters.load_flows_csv(FIXTURES / "flows.csv")
    counts = correlate(flows, BlockedSet(entries), window_seconds=WINDOW)
    return {(c.ip, c.window_start.isoformat()): c for c in counts}


def test_dedupe_drops_duplicate_router_observation():
    flows = flow_counters.load_flows_csv(FIXTURES / "flows.csv")
    assert len(flows) == 8
    assert len(dedupe_flows(flows)) == 7  # rtr1/rtr2 duplicate collapsed


def test_expected_impact_rows():
    by_key = _correlate()
    # Two windows for 185.x, one each for 203.x and 198.x -> 4 rows.
    assert len(by_key) == 4


def test_source_match_sums_within_window_and_scales_sampling():
    by_key = _correlate()
    # 185.12.34.56 window 00:00-01:00: flows of 5 and 3 packets (dup dropped).
    c = by_key[("185.12.34.56", "2026-06-10T00:00:00+00:00")]
    assert c.flows == 2
    assert c.raw_hits == 8
    assert c.bh_hits == 8 * 1000
    assert c.bh_bytes == (300 + 180) * 1000
    assert c.accuracy == ACCURACY_SAMPLED
    assert c.indicator_id == "ind-0001"


def test_open_ended_block_is_active():
    by_key = _correlate()
    # 203.0.113.50 has no 'removed' time -> still active.
    c = by_key[("203.0.113.50", "2026-06-10T01:00:00+00:00")]
    assert c.bh_hits == 10 * 1000


def test_excludes_unblocked_source():
    by_key = _correlate()
    assert not any(ip == "8.8.8.8" for ip, _ in by_key)


def test_excludes_flow_after_block_removed():
    by_key = _correlate()
    # 198.51.100.10 block ends 06:00; the 07:00 flow must be excluded,
    # the 03:00 flow included.
    assert ("198.51.100.10", "2026-06-10T03:00:00+00:00") in by_key
    assert ("198.51.100.10", "2026-06-10T07:00:00+00:00") not in by_key
