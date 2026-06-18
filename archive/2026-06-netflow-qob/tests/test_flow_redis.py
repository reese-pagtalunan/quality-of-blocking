from datetime import datetime, timezone
from pathlib import Path

from qob.ingest import bhr_list, flow_counters
from qob.ingest.flow_redis import RedisQobStore, ingest_flows
from qob.join_flows import BlockedSet
from qob.models import ImpactCount

FIXTURES = Path(__file__).parent / "fixtures"


class FakeRedis:
    """Minimal in-memory stand-in for the redis-py methods we use."""

    def __init__(self):
        self.kv = {}
        self.z = {}
        self.h = {}
        self.ttl = {}

    def incrby(self, k, n):
        self.kv[k] = int(self.kv.get(k, 0)) + int(n)
        return self.kv[k]

    def get(self, k):
        v = self.kv.get(k)
        return None if v is None else str(v).encode()

    def set(self, k, v, nx=False, ex=None):
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        if ex:
            self.ttl[k] = ex
        return True

    def expire(self, k, t):
        self.ttl[k] = t
        return True

    def zincrby(self, k, amount, member):
        d = self.z.setdefault(k, {})
        d[member] = d.get(member, 0) + amount
        return d[member]

    def zrange(self, k, start, end, desc=False, withscores=False):
        d = self.z.get(k, {})
        items = sorted(d.items(), key=lambda kv: kv[1], reverse=desc)
        sl = items[start:] if end == -1 else items[start : end + 1]
        return [(m, float(s)) for m, s in sl] if withscores else [m for m, _ in sl]

    def hset(self, k, f, v):
        self.h.setdefault(k, {})[f] = v
        return 1


def _store():
    return RedisQobStore(FakeRedis())


def test_record_counts_writes_scaled_counters_and_ttl():
    store = _store()
    ws = datetime(2026, 6, 11, tzinfo=timezone.utc)
    store.record_counts([
        ImpactCount(ip="185.12.34.56", window_start=ws, window_end=ws,
                    bh_hits=8000, bh_bytes=480000, indicator_id="ind-0001"),
    ])
    r = store.client
    assert r.kv["qob:hits:185.12.34.56:20260611"] == 8000
    assert r.kv["qob:bytes:185.12.34.56:20260611"] == 480000
    assert r.z["qob:rank:20260611"]["185.12.34.56"] == 8000
    assert r.h["qob:meta:185.12.34.56"]["indicator_id"] == "ind-0001"
    # TTL applied (~8 days)
    assert r.ttl["qob:hits:185.12.34.56:20260611"] == 8 * 86400


def test_counters_are_additive_across_batches():
    store = _store()
    ws = datetime(2026, 6, 11, tzinfo=timezone.utc)
    c = ImpactCount(ip="9.9.9.9", window_start=ws, window_end=ws, bh_hits=100, bh_bytes=10)
    store.record_counts([c])
    store.record_counts([c])
    assert store.client.kv["qob:hits:9.9.9.9:20260611"] == 200


def test_ingest_flows_from_fixtures_reuses_join_logic():
    entries = bhr_list.load_blocklist(FIXTURES / "publist.csv")
    flows = flow_counters.load_flows_csv(FIXTURES / "flows.csv")
    store = _store()
    # daily buckets; flows are dated 2026-06-10
    counts = ingest_flows(flows, BlockedSet(entries), store, window_seconds=86400)

    # 185.x: 8+3 packets (dup dropped) +2 packets all land in the same DAY now
    assert store.client.kv["qob:hits:185.12.34.56:20260610"] == (8 + 2) * 1000
    # unblocked source never counted
    assert "qob:hits:8.8.8.8:20260610" not in store.client.kv
    # expired-block flow (198.x @ 07:00) excluded; 03:00 counted
    assert store.client.kv["qob:hits:198.51.100.10:20260610"] == 4 * 1000
    assert any(c.ip == "203.0.113.50" for c in counts)


def test_top_ranking_merges_days():
    store = _store()
    ws = datetime.now(timezone.utc)
    store.record_counts([
        ImpactCount(ip="1.1.1.1", window_start=ws, window_end=ws, bh_hits=500, bh_bytes=1),
        ImpactCount(ip="2.2.2.2", window_start=ws, window_end=ws, bh_hits=999, bh_bytes=1),
    ])
    top = store.top(n=1, days=7)
    assert top[0][0] == "2.2.2.2"
    assert top[0][1] == 999


def test_seen_flow_guard_dedupes():
    store = _store()
    flows = flow_counters.load_flows_csv(FIXTURES / "flows.csv")
    f = flows[0]
    assert store.seen_flow(f) is True     # first time -> new
    assert store.seen_flow(f) is False    # second time -> already seen


def test_goflow2_json_parser():
    obj = {
        "time_flow_start_ns": 1_780_000_000_000_000_000,
        "time_flow_end_ns": 1_780_000_000_500_000_000,
        "src_addr": "185.12.34.56",
        "dst_addr": "10.0.2.66",
        "src_port": 40001,
        "dst_port": 22,
        "proto": "TCP",
        "packets": 5,
        "bytes": 300,
        "sampling_rate": 1000,
        "sampler_address": "172.20.20.11",
    }
    fr = flow_counters.flow_from_goflow2(obj)
    assert fr.src_addr == "185.12.34.56"
    assert fr.packets == 5 and fr.bytes == 300
    assert fr.sampling_rate == 1000
    assert fr.start.tzinfo is not None
