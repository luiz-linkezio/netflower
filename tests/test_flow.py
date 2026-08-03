import pytest
from netflower._flow import Flow
from netflower._constants import FORWARD, BACKWARD, TCP_SYN, TCP_ACK, TCP_PSH


def _flow(ts=0.0):
    return Flow("192.168.1.1", "10.0.0.1", 12345, 80, 6, ts)


def test_identity_fields():
    f = _flow()
    d = f.to_dict()
    assert d["src_ip"] == "192.168.1.1"
    assert d["dst_ip"] == "10.0.0.1"
    assert d["src_port"] == 12345
    assert d["dst_port"] == 80
    assert d["protocol"] == 6


def test_single_forward_packet():
    f = _flow(ts=1.0)
    f.add_packet(FORWARD, pkt_len=60, header_len=20, payload_len=40, timestamp=1.0)
    d = f.to_dict()
    assert d["tot_fwd_pkts"] == 1
    assert d["tot_bwd_pkts"] == 0
    assert d["totlen_fwd_pkts"] == 60
    assert d["fwd_pkt_len_max"] == 60
    assert d["fwd_pkt_len_min"] == 60


def test_bidirectional_counts():
    f = _flow(ts=1.0)
    f.add_packet(FORWARD, 100, 20, 80, 1.0, TCP_SYN)
    f.add_packet(BACKWARD, 60, 20, 40, 1.1, TCP_SYN | TCP_ACK)
    f.add_packet(FORWARD, 200, 20, 180, 1.2, TCP_ACK)
    d = f.to_dict()
    assert d["tot_fwd_pkts"] == 2
    assert d["tot_bwd_pkts"] == 1
    assert d["syn_flag_cnt"] == 2
    assert d["ack_flag_cnt"] == 2
    assert d["flow_duration"] == pytest.approx(0.2)


def test_to_dict_field_count():
    f = _flow(ts=1.0)
    f.add_packet(FORWARD, 60, 20, 40, 1.0)
    assert len(f.to_dict()) == 82


def test_fwd_act_data_pkts():
    f = _flow(ts=1.0)
    f.add_packet(FORWARD, 60, 20, 0, 1.0)   # no payload
    f.add_packet(FORWARD, 80, 20, 60, 1.1)  # has payload
    assert f.to_dict()["fwd_act_data_pkts"] == 1


def test_init_win_sizes():
    f = _flow(ts=1.0)
    f.add_packet(FORWARD, 60, 20, 40, 1.0, TCP_SYN, window=8192)
    f.add_packet(BACKWARD, 60, 20, 40, 1.1, TCP_SYN | TCP_ACK, window=4096)
    d = f.to_dict()
    assert d["init_fwd_win_byts"] == 8192
    assert d["init_bwd_win_byts"] == 4096


def test_rates_zero_duration():
    f = _flow(ts=5.0)
    f.add_packet(FORWARD, 60, 20, 40, 5.0)
    d = f.to_dict()
    assert d["flow_byts_s"] == 0.0
    assert d["flow_pkts_s"] == 0.0


def test_psh_flag_counted_per_direction():
    f = _flow(ts=1.0)
    f.add_packet(FORWARD, 100, 20, 80, 1.0, TCP_PSH)
    f.add_packet(BACKWARD, 60, 20, 40, 1.1, TCP_PSH)
    d = f.to_dict()
    assert d["fwd_psh_flags"] == 1
    assert d["bwd_psh_flags"] == 1
    assert d["psh_flag_cnt"] == 2


def test_down_up_ratio():
    f = _flow(ts=1.0)
    f.add_packet(FORWARD, 60, 20, 40, 1.0)
    f.add_packet(FORWARD, 60, 20, 40, 1.1)
    f.add_packet(BACKWARD, 60, 20, 40, 1.2)
    d = f.to_dict()
    assert d["down_up_ratio"] == pytest.approx(0.5)
