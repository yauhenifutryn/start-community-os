"""Conservative statistical disclosure controls for published report cells."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class SafeCell:
    key: str
    count: int | None
    status: str


@dataclass(frozen=True)
class DistributionResult:
    cells: tuple[SafeCell, ...]
    threshold: int
    total_published: bool


@dataclass(frozen=True)
class CrossTabResult:
    withheld: bool
    threshold: int
    reason: str | None = None


def effective_k(eligible_count: int, *, sensitive: bool = False, k: int | None = None) -> int:
    """Return the configured floor, escalating small or sensitive populations."""
    if k is not None:
        if k < 5:
            raise ValueError("publication threshold cannot be below 5")
        return k
    return 10 if sensitive or eligible_count < 50 else 5


def safe_distribution(
    groups: Mapping[str, set[int]], *, eligible_count: int,
    sensitive: bool = False, k: int | None = None,
) -> DistributionResult:
    """Suppress small cells plus one complement so totals cannot reveal a lone cell."""
    threshold = effective_k(eligible_count, sensitive=sensitive, k=k)
    counts = {key: len(members) for key, members in groups.items()}
    suppressed = {key for key, count in counts.items() if count < threshold}
    if suppressed and len(suppressed) == 1 and len(counts) > 1:
        candidates = [(count, key) for key, count in counts.items() if key not in suppressed]
        if candidates:
            suppressed.add(min(candidates)[1])
    cells = tuple(
        SafeCell(key, None if key in suppressed else count,
                 "primary" if count < threshold else "complementary" if key in suppressed else "published")
        for key, count in sorted(counts.items())
    )
    return DistributionResult(cells, threshold, not bool(suppressed))


def safe_crosstab(
    cells: Mapping[tuple[str, str], set[int]], *, eligible_count: int,
    sensitive: bool = False, k: int | None = None,
) -> CrossTabResult:
    """Withhold an entire cross-tab if any cell is unsafe.

    This intentionally sacrifices detail instead of attempting fragile partial release.
    """
    threshold = effective_k(eligible_count, sensitive=sensitive, k=k)
    if any(len(members) < threshold for members in cells.values()):
        return CrossTabResult(True, threshold, "sub_threshold_cross_tab")
    return CrossTabResult(False, threshold)
