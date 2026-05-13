"""
Online statistics via Welford's algorithm.
Computes mean, variance, and std in a single pass with O(1) memory —
no list of values is ever stored.
"""

__slots__ = ("n", "_mean", "_M2", "total", "min_val", "max_val")


class RunningStats:
    __slots__ = ("n", "_mean", "_M2", "total", "min_val", "max_val")

    def __init__(self) -> None:
        self.n: int = 0
        self._mean: float = 0.0
        self._M2: float = 0.0
        self.total: float = 0.0
        self.min_val: float = float("inf")
        self.max_val: float = float("-inf")

    def update(self, x: float) -> None:
        self.n += 1
        self.total += x
        if x < self.min_val:
            self.min_val = x
        if x > self.max_val:
            self.max_val = x
        delta = x - self._mean
        self._mean += delta / self.n
        self._M2 += delta * (x - self._mean)

    @property
    def mean(self) -> float:
        return self._mean if self.n > 0 else 0.0

    @property
    def variance(self) -> float:
        return self._M2 / self.n if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return self.variance**0.5

    @property
    def safe_min(self) -> float:
        return self.min_val if self.n > 0 else 0.0

    @property
    def safe_max(self) -> float:
        return self.max_val if self.n > 0 else 0.0
