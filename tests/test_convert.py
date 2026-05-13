import csv
import socket
import struct

import pytest

from netflower import convert_pcap_to_csv

# ── pcap / packet builders ────────────────────────────────────────────────────

_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic (little-endian, microsecond timestamps)
    2, 4,        # version
    0, 0,        # timezone, sigfigs
    65535,       # snaplen
    1,           # link type: Ethernet
)


def _pcap_record(ts: float, data: bytes) -> bytes:
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _write_pcap(path, packets):
    with open(path, "wb") as fh:
        fh.write(_PCAP_GLOBAL_HEADER)
        for ts, data in packets:
            fh.write(_pcap_record(ts, data))


def _tcp_pkt(src_ip, dst_ip, sport, dport, flags=0x02, payload=b"", window=65535):
    tcp = struct.pack("!HHIIBBHHH",
        sport, dport, 0, 0,
        0x50,    # data offset = 5 words = 20 bytes
        flags,
        window, 0, 0,
    ) + payload
    ip_len = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_len, 0, 0,
        64, 6, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    eth = struct.pack("!6s6sH",
        b'\xaa\xbb\xcc\xdd\xee\xff',
        b'\x00\x11\x22\x33\x44\x55',
        0x0800,
    )
    return eth + ip + tcp


def _udp_pkt(src_ip, dst_ip, sport, dport, payload=b"data"):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip_len = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_len, 0, 0,
        64, 17, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    eth = struct.pack("!6s6sH",
        b'\xaa\xbb\xcc\xdd\xee\xff',
        b'\x00\x11\x22\x33\x44\x55',
        0x0800,
    )
    return eth + ip + udp


# ── tests ─────────────────────────────────────────────────────────────────────

def test_empty_pcap_returns_zero(tmp_path):
    pcap = tmp_path / "empty.pcap"
    out = tmp_path / "out.csv"
    _write_pcap(str(pcap), [])
    assert convert_pcap_to_csv(str(pcap), str(out)) == 0


def test_single_tcp_flow(tmp_path):
    pcap = tmp_path / "tcp.pcap"
    out = tmp_path / "out.csv"
    pkts = [
        (1000.0, _tcp_pkt("192.168.1.1", "10.0.0.1", 5000, 80, flags=0x02)),
        (1000.1, _tcp_pkt("10.0.0.1", "192.168.1.1", 80, 5000, flags=0x12)),
        (1000.2, _tcp_pkt("192.168.1.1", "10.0.0.1", 5000, 80, flags=0x01)),  # FIN
    ]
    _write_pcap(str(pcap), pkts)
    n = convert_pcap_to_csv(str(pcap), str(out))
    assert n == 1


def test_output_csv_columns(tmp_path):
    pcap = tmp_path / "tcp.pcap"
    out = tmp_path / "out.csv"
    pkts = [(1000.0, _tcp_pkt("1.1.1.1", "2.2.2.2", 100, 200, flags=0x01))]
    _write_pcap(str(pcap), pkts)
    convert_pcap_to_csv(str(pcap), str(out))
    with open(out) as fh:
        reader = csv.DictReader(fh)
        list(reader)
        assert "src_ip" in reader.fieldnames
        assert "protocol" in reader.fieldnames
        assert len(reader.fieldnames) == 82


def test_two_independent_flows(tmp_path):
    pcap = tmp_path / "two.pcap"
    out = tmp_path / "out.csv"
    pkts = [
        (1000.0, _tcp_pkt("1.1.1.1", "2.2.2.2", 100, 80, flags=0x01)),
        (1000.1, _tcp_pkt("3.3.3.3", "4.4.4.4", 200, 443, flags=0x01)),
    ]
    _write_pcap(str(pcap), pkts)
    n = convert_pcap_to_csv(str(pcap), str(out))
    assert n == 2


def test_udp_flow(tmp_path):
    pcap = tmp_path / "udp.pcap"
    out = tmp_path / "out.csv"
    pkts = [
        (2000.0, _udp_pkt("192.168.1.1", "8.8.8.8", 53001, 53, b"query")),
        (2000.1, _udp_pkt("8.8.8.8", "192.168.1.1", 53, 53001, b"response")),
    ]
    _write_pcap(str(pcap), pkts)
    n = convert_pcap_to_csv(str(pcap), str(out))
    assert n >= 1
    with open(out) as fh:
        row = list(csv.DictReader(fh))[0]
    assert row["protocol"] == "17"


def test_flow_values_in_csv(tmp_path):
    pcap = tmp_path / "vals.pcap"
    out = tmp_path / "out.csv"
    pkts = [
        (1000.0, _tcp_pkt("10.0.0.1", "10.0.0.2", 9000, 80, flags=0x02, payload=b"x" * 100)),
        (1000.5, _tcp_pkt("10.0.0.2", "10.0.0.1", 80, 9000, flags=0x01)),
    ]
    _write_pcap(str(pcap), pkts)
    convert_pcap_to_csv(str(pcap), str(out))
    with open(out) as fh:
        row = list(csv.DictReader(fh))[0]
    assert row["src_ip"] == "10.0.0.1"
    assert row["dst_port"] == "80"
    assert float(row["flow_duration"]) == pytest.approx(0.5)


# ── parallelism ───────────────────────────────────────────────────────────────

def _multi_flow_pcap(tmp_path):
    """Write a pcap with 4 distinct flows and return its path."""
    pcap = tmp_path / "multi.pcap"
    pkts = [
        (1000.0, _tcp_pkt("1.1.1.1", "2.2.2.2", 100, 80, flags=0x01)),
        (1000.1, _tcp_pkt("3.3.3.3", "4.4.4.4", 200, 443, flags=0x01)),
        (1000.2, _tcp_pkt("5.5.5.5", "6.6.6.6", 300, 22, flags=0x01)),
        (1000.3, _tcp_pkt("7.7.7.7", "8.8.8.8", 400, 8080, flags=0x01)),
    ]
    _write_pcap(str(pcap), pkts)
    return pcap


def test_parallel_same_row_count_as_single(tmp_path):
    pcap = _multi_flow_pcap(tmp_path)
    out1 = tmp_path / "single.csv"
    out2 = tmp_path / "parallel.csv"
    n1 = convert_pcap_to_csv(str(pcap), str(out1), n_jobs=1)
    n2 = convert_pcap_to_csv(str(pcap), str(out2), n_jobs=2)
    assert n1 == n2


def test_parallel_n_jobs_minus_one(tmp_path):
    pcap = _multi_flow_pcap(tmp_path)
    out = tmp_path / "out.csv"
    n = convert_pcap_to_csv(str(pcap), str(out), n_jobs=-1)
    assert n == 4


def test_parallel_output_has_correct_columns(tmp_path):
    pcap = _multi_flow_pcap(tmp_path)
    out = tmp_path / "out.csv"
    convert_pcap_to_csv(str(pcap), str(out), n_jobs=2)
    with open(out) as fh:
        reader = csv.DictReader(fh)
        list(reader)
        assert len(reader.fieldnames) == 82


def test_n_jobs_zero_raises(tmp_path):
    pcap = tmp_path / "x.pcap"
    _write_pcap(str(pcap), [])
    with pytest.raises(ValueError):
        convert_pcap_to_csv(str(pcap), str(tmp_path / "out.csv"), n_jobs=0)
