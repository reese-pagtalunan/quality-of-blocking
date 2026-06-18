from datetime import datetime, timezone
from pathlib import Path

from qob.ingest import bhr_list
from qob.ingest.flow_es import ELASTIFLOW_FIELD_MAP, EsFlowSource
from qob.models import ACCURACY_SAMPLED

FIXTURES = Path(__file__).parent / "fixtures"
WINDOW = 3600


def _ms(y, mo, d, h):
    return int(datetime(y, mo, d, h, tzinfo=timezone.utc).timestamp() * 1000)


class FakeEsClient:
    """Records the query body and returns a canned aggregation response."""

    def __init__(self, response):
        self.response = response
        self.last_index = None
        self.last_body = None

    def search(self, index=None, body=None):
        self.last_index = index
        self.last_body = body
        return self.response


def _canned_response():
    def window(ts_ms, packets, byts, sampling, docs):
        return {
            "key": ts_ms,
            "doc_count": docs,
            "packets": {"value": float(packets)},
            "bytes": {"value": float(byts)},
            "sampling": {"value": float(sampling)},
        }

    return {
        "aggregations": {
            "by_ip": {
                "buckets": [
                    {
                        "key": "185.12.34.56",
                        "by_window": {"buckets": [window(_ms(2026, 6, 10, 0), 8, 480, 1000, 2)]},
                    },
                    {
                        "key": "198.51.100.10",
                        "by_window": {
                            "buckets": [
                                window(_ms(2026, 6, 10, 3), 4, 240, 1000, 1),  # active
                                window(_ms(2026, 6, 10, 7), 9, 540, 1000, 1),  # after unblock
                            ]
                        },
                    },
                ]
            }
        }
    }


def _aggregate():
    entries = bhr_list.load_blocklist(FIXTURES / "publist.csv")
    client = FakeEsClient(_canned_response())
    source = EsFlowSource(client, index="elastiflow-flow-*")
    start = datetime(2026, 6, 10, tzinfo=timezone.utc)
    end = datetime(2026, 6, 11, tzinfo=timezone.utc)
    counts = source.aggregate(entries, start, end, window_seconds=WINDOW)
    return {(c.ip, c.window_start.isoformat()): c for c in counts}, client


def test_query_body_uses_cidr_terms_and_window_interval():
    _, client = _aggregate()
    body = client.last_body
    assert body["size"] == 0
    should = body["query"]["bool"]["filter"][1]["bool"]["should"]
    cidrs = {t["term"][ELASTIFLOW_FIELD_MAP.src_ip] for t in should}
    assert "185.12.34.56/32" in cidrs
    hist = body["aggs"]["by_ip"]["aggs"]["by_window"]["date_histogram"]
    assert hist["fixed_interval"] == "3600s"


def test_sampling_is_scaled_and_indicator_attached():
    by_key, _ = _aggregate()
    c = by_key[("185.12.34.56", "2026-06-10T00:00:00+00:00")]
    assert c.raw_hits == 8
    assert c.bh_hits == 8 * 1000
    assert c.bh_bytes == 480 * 1000
    assert c.flows == 2
    assert c.accuracy == ACCURACY_SAMPLED
    assert c.indicator_id == "ind-0001"


def test_inactive_window_is_dropped():
    by_key, _ = _aggregate()
    assert ("198.51.100.10", "2026-06-10T03:00:00+00:00") in by_key
    assert ("198.51.100.10", "2026-06-10T07:00:00+00:00") not in by_key
