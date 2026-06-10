"""Minimal QoB impact scoring.

Phase 1 only implements `impact_score` (the BH "add" component from plan.md
§3.3). Evidence / confirmation / persistence / penalty components are stubbed
for later phases. Weights are passed in so they can move to config later.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import log1p

from .models import ImpactCount


@dataclass(frozen=True)
class ImpactWeights:
    w_hits: float = 1.0
    w_bytes: float = 1.0  # applied to log1p(bytes) to cap heavy-hitters


def impact_score(count: ImpactCount, weights: ImpactWeights = ImpactWeights()) -> float:
    """f(bh_hits, bh_bytes) with a log cap on bytes (plan.md §3.3)."""
    return weights.w_hits * count.bh_hits + weights.w_bytes * log1p(count.bh_bytes)
