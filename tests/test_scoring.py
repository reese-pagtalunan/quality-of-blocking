from datetime import datetime, timezone

from qob.models import ImpactCount
from qob.scoring import ImpactWeights, impact_score


def _count(hits: int, byts: int) -> ImpactCount:
    ws = datetime(2026, 6, 10, tzinfo=timezone.utc)
    return ImpactCount(ip="185.12.34.56", window_start=ws, window_end=ws, bh_hits=hits, bh_bytes=byts)


def test_impact_increases_with_hits():
    low = impact_score(_count(10, 1000))
    high = impact_score(_count(100, 1000))
    assert high > low


def test_bytes_are_log_capped():
    # 1000x the bytes should NOT produce a 1000x score jump (log cap).
    small = impact_score(_count(0, 1_000), ImpactWeights(w_hits=0, w_bytes=1))
    big = impact_score(_count(0, 1_000_000), ImpactWeights(w_hits=0, w_bytes=1))
    assert big < small * 3


def test_zero_counts_score_zero():
    assert impact_score(_count(0, 0)) == 0.0
