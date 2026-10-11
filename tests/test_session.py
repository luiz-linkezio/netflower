from netflower._session import FlowSession
from netflower._constants import TCP_FIN, TCP_SYN, TCP_ACK, TCP_RST


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


_A = ("1.1.1.1", "2.2.2.2", 1000, 80, 6, 60, 20, 0)
_B = ("2.2.2.2", "1.1.1.1", 80, 1000, 6, 60, 20, 0)


def _close_with_fins(sess, t=1.0):
    sess.process(t, *_A, flags=TCP_SYN)
    sess.process(t + 0.1, *_A, flags=TCP_FIN | TCP_ACK)
    sess.process(t + 0.2, *_B, flags=TCP_FIN | TCP_ACK)


def test_final_ack_of_a_teardown_does_not_start_a_flow():
    sess, w = _make()
    _close_with_fins(sess)
    sess.process(1.3, *_A, flags=TCP_ACK)
    sess.flush_all()
    assert len(w.rows) == 1
    assert w.rows[0]["tot_fwd_pkts"] == 2


def test_packets_after_rst_do_not_start_a_flow():
    sess, w = _make()
    sess.process(1.0, *_A, flags=TCP_SYN)
    sess.process(1.1, *_B, flags=TCP_RST | TCP_ACK)
    sess.process(1.2, *_B, flags=TCP_RST)
    sess.process(1.3, *_A, flags=TCP_ACK)
    sess.flush_all()
    assert len(w.rows) == 1


def test_syn_after_a_teardown_starts_a_flow():
    sess, w = _make()
    _close_with_fins(sess)
    sess.process(1.3, *_A, flags=TCP_SYN)
    sess.process(1.4, *_A, flags=TCP_ACK)
    sess.flush_all()
    assert len(w.rows) == 2
    assert w.rows[1]["tot_fwd_pkts"] == 2


def test_syn_ack_after_a_teardown_does_not_start_a_flow():
    sess, w = _make()
    _close_with_fins(sess)
    sess.process(1.3, *_B, flags=TCP_SYN | TCP_ACK)
    sess.flush_all()
    assert len(w.rows) == 1


def test_packet_after_the_linger_starts_a_flow():
    sess, w = _make()
    _close_with_fins(sess)
    sess.process(1.2 + 1.5, *_A, flags=TCP_ACK)
    sess.flush_all()
    assert len(w.rows) == 2


def test_gc_forgets_closed_connections_after_the_linger():
    sess, w = _make()
    _close_with_fins(sess)
    sess.gc(5.0)
    assert sess._closed == {}


def test_close_linger_zero_keeps_leftovers_as_flows():
    w = _Writer()
    sess = FlowSession(w, flow_timeout=10.0, close_linger=0)
    _close_with_fins(sess)
    sess.process(1.3, *_A, flags=TCP_ACK)
    sess.flush_all()
    assert len(w.rows) == 2


def test_udp_has_no_leftover_rule():
    sess, w = _make()
    sess.process(1.0, "1.1.1.1", "2.2.2.2", 1000, 53, 17, 60, 8, 52)
    sess.gc(100.0)
    sess.process(100.1, "1.1.1.1", "2.2.2.2", 1000, 53, 17, 60, 8, 52)
    sess.flush_all()
    assert len(w.rows) == 2


def test_duration_cap_keeps_the_orientation():
    w = _Writer()
    sess = FlowSession(w, flow_timeout=100.0, active_timeout=5.0)
    sess.process(1.0, *_A)
    for i in range(1, 5):
        sess.process(1.0 + i, *_B)
    # first packet past the cap comes from the responder
    sess.process(7.0, *_B)
    sess.process(8.0, *_A)
    sess.flush_all()
    assert len(w.rows) == 2
    assert [row["src_ip"] for row in w.rows] == ["1.1.1.1", "1.1.1.1"]
    assert (w.rows[1]["tot_fwd_pkts"], w.rows[1]["tot_bwd_pkts"]) == (1, 1)


def test_duration_cap_keeps_the_orientation_when_gc_cut_the_flow():
    w = _Writer()
    sess = FlowSession(w, flow_timeout=100.0, active_timeout=5.0)
    sess.process(1.0, *_A)
    sess.process(6.0, *_B)
    sess.gc(6.5)
    assert len(w.rows) == 1
    sess.process(7.0, *_B)
    sess.flush_all()
    assert w.rows[1]["src_ip"] == "1.1.1.1"
    assert (w.rows[1]["tot_fwd_pkts"], w.rows[1]["tot_bwd_pkts"]) == (0, 1)


def test_gc_and_packet_cut_a_capped_flow_alike():
    def run(with_gc):
        w = _Writer()
        sess = FlowSession(w, flow_timeout=20.0, active_timeout=5.0)
        for i, (t, pkt) in enumerate([(1.0, _A), (3.0, _B), (6.5, _B), (7.0, _A), (40.0, _B)]):
            sess.process(t, *pkt)
            if with_gc:
                sess.gc(t + 0.2)
        sess.flush_all()
        return [(r["src_ip"], r["tot_fwd_pkts"], r["tot_bwd_pkts"]) for r in w.rows]

    assert run(with_gc=True) == run(with_gc=False)


def test_idle_timeout_gives_the_orientation_to_the_sender():
    w = _Writer()
    sess = FlowSession(w, flow_timeout=10.0, active_timeout=5.0)
    sess.process(1.0, *_A)
    sess.process(50.0, *_B)
    sess.flush_all()
    assert [row["src_ip"] for row in w.rows] == ["1.1.1.1", "2.2.2.2"]


def test_key_for_matches_process():
    w = _Writer()
    sess = FlowSession(w, flow_timeout=100.0, active_timeout=5.0)
    assert sess.key_for(1.0, *_A[:5]) == (6, "1.1.1.1", "2.2.2.2", 1000, 80)
    sess.process(1.0, *_A, flags=TCP_SYN)
    assert sess.key_for(1.1, *_B[:5]) == (6, "1.1.1.1", "2.2.2.2", 1000, 80)
    sess.process(1.1, *_B, flags=TCP_RST)
    assert sess.key_for(1.2, *_A[:5], flags=TCP_ACK) is None
    assert sess.key_for(1.2, *_B[:5], flags=TCP_SYN) == (6, "2.2.2.2", "1.1.1.1", 80, 1000)
