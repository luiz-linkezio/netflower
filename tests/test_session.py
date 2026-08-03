from netflower._session import FlowSession
from netflower._constants import TCP_FIN, TCP_ACK, TCP_RST


class _Writer:
    def __init__(self):
        self.rows = []

    def write(self, row):
        self.rows.append(row)


def _make(timeout=10.0):
    w = _Writer()
    return FlowSession(w, flow_timeout=timeout), w


def test_single_flow_two_packets():
    sess, w = _make()
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40)
    sess.process(1.1, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 80, 20, 60)
    sess.flush_all()
    assert len(w.rows) == 1
    assert w.rows[0]["tot_fwd_pkts"] == 2


def test_bidirectional_same_flow():
    sess, w = _make()
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40)
    sess.process(1.1, "2.2.2.2", "1.1.1.1", 80, 1000, 6, 80, 20, 60)
    sess.flush_all()
    assert len(w.rows) == 1
    assert w.rows[0]["tot_fwd_pkts"] == 1
    assert w.rows[0]["tot_bwd_pkts"] == 1


def test_two_distinct_flows():
    sess, w = _make()
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40)
    sess.process(1.1, "3.3.3.3", "4.4.4.4", 2000, 443, 6, 60, 20, 40)
    sess.flush_all()
    assert len(w.rows) == 2


def test_flow_timeout_creates_new_flow():
    sess, w = _make(timeout=10.0)
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40)
    # 100s gap — exceeds 10s timeout, so first flow is flushed and a new one starts
    sess.process(101.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 80, 20, 60)
    sess.flush_all()
    assert len(w.rows) == 2


def test_gc_evicts_expired_flows():
    sess, w = _make(timeout=10.0)
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40)
    sess.gc(100.0)
    assert len(w.rows) == 1


def test_active_timeout_splits_long_lived_flow():
    w = _Writer()
    sess = FlowSession(w, flow_timeout=100.0, active_timeout=5.0)
    # packets every 1s — never idle, but total duration exceeds active_timeout
    for i in range(8):
        sess.process(1.0 + i, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40)
    sess.flush_all()
    assert len(w.rows) == 2


def test_gc_evicts_flows_exceeding_active_timeout():
    w = _Writer()
    sess = FlowSession(w, flow_timeout=100.0, active_timeout=5.0)
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40)
    # idle for only 6s (< 100s idle timeout) but flow is older than 5s
    sess.gc(7.0)
    assert len(w.rows) == 1


def test_single_fin_does_not_evict_flow():
    """One-sided FIN must not close the flow — the other side's FIN/ACK
    would otherwise be split into a spurious new flow (CICFlowMeter waits
    for FIN from both directions)."""
    sess, w = _make()
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40, flags=0)
    sess.process(1.1, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 40, 20, 0, flags=TCP_FIN)
    assert len(w.rows) == 0
    sess.flush_all()
    assert len(w.rows) == 1


def test_fin_in_both_directions_evicts_flow():
    sess, w = _make()
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40, flags=0)
    sess.process(1.1, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 40, 20, 0,
                 flags=TCP_FIN | TCP_ACK)
    sess.process(1.2, "2.2.2.2", "1.1.1.1", 80, 1000, 6, 40, 20, 0,
                 flags=TCP_FIN | TCP_ACK)
    assert len(w.rows) == 1
    sess.flush_all()
    assert len(w.rows) == 1  # nothing left to flush


def test_tcp_rst_evicts_flow_immediately():
    sess, w = _make()
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 40, flags=0)
    sess.process(1.1, "2.2.2.2", "1.1.1.1", 80, 1000, 6, 40, 20, 0, flags=TCP_RST)
    assert len(w.rows) == 1


def test_udp_flow():
    sess, w = _make()
    sess.process(1.0, "1.1.1.1", "8.8.8.8", 53001, 53, 17, 60, 8, 52)
    sess.process(1.1, "8.8.8.8", "1.1.1.1", 53, 53001, 17, 80, 8, 72)
    sess.flush_all()
    assert len(w.rows) == 1
    assert w.rows[0]["protocol"] == 17
