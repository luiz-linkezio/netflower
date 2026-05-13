import pytest
from netflower._stats import RunningStats


def test_empty():
    rs = RunningStats()
    assert rs.n == 0
    assert rs.mean == 0.0
    assert rs.variance == 0.0
    assert rs.std == 0.0
    assert rs.safe_min == 0.0
    assert rs.safe_max == 0.0


def test_single_value():
    rs = RunningStats()
    rs.update(5.0)
    assert rs.n == 1
    assert rs.mean == 5.0
    assert rs.total == 5.0
    assert rs.min_val == 5.0
    assert rs.max_val == 5.0
    assert rs.variance == 0.0
    assert rs.std == 0.0


def test_known_sequence():
    # Population: [2,4,4,4,5,5,7,9] → mean=5, std=2
    rs = RunningStats()
    for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]:
        rs.update(v)
    assert rs.n == 8
    assert rs.mean == pytest.approx(5.0)
    assert rs.std == pytest.approx(2.0)
    assert rs.safe_min == 2.0
    assert rs.safe_max == 9.0


def test_total():
    rs = RunningStats()
    for v in [1.0, 2.0, 3.0]:
        rs.update(v)
    assert rs.total == 6.0


def test_monotone_sequence():
    rs = RunningStats()
    for v in range(1, 6):
        rs.update(float(v))
    assert rs.mean == pytest.approx(3.0)
    assert rs.safe_min == 1.0
    assert rs.safe_max == 5.0
