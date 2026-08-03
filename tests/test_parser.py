import socket
import dpkt
import dpkt.ethernet
import dpkt.ip
import dpkt.tcp
import dpkt.udp
import dpkt.icmp
from netflower._parser import _parse_packet


def _make_tcp_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                     sport=1234, dport=80, flags=0, win=65535, payload=b"hello"):
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport,
        flags=flags, win=win,
        off=5,
        data=payload,
    )
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=6,
        data=tcp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b'\x00' * 6,
        dst=b'\xff' * 6,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _make_udp_packet(src_ip="1.1.1.1", dst_ip="8.8.8.8",
                     sport=53001, dport=53, payload=b"query"):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = 8 + len(payload)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=17,
        data=udp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b'\x00' * 6,
        dst=b'\xff' * 6,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def test_tcp_packet_parsed():
    buf = _make_tcp_packet(flags=0x02, win=8192, payload=b"data")
    result = _parse_packet(buf)
    assert result is not None
    src_ip, dst_ip, src_port, dst_port, proto, pkt_len, hdr_len, pay_len, flags, win = result
    assert src_ip == "1.1.1.1"
    assert dst_ip == "2.2.2.2"
    assert src_port == 1234
    assert dst_port == 80
    assert proto == 6
    assert flags == 0x02
    assert win == 8192
    assert pay_len == 4


def test_tcp_header_len():
    # Standard TCP header without options: off=5 words -> 20 bytes
    buf = _make_tcp_packet(payload=b"data")
    result = _parse_packet(buf)
    hdr_len = result[6]
    assert hdr_len == 20


def test_udp_packet_parsed():
    buf = _make_udp_packet(payload=b"query")
    result = _parse_packet(buf)
    assert result is not None
    _, _, sport, dport, proto, _, hdr_len, pay_len, flags, win = result
    assert proto == 17
    assert hdr_len == 8
    assert flags == 0
    assert win == -1
    assert pay_len == 5


def test_non_ip_returns_none():
    eth = dpkt.ethernet.Ethernet(
        src=b'\x00' * 6,
        dst=b'\xff' * 6,
        type=0x0806,  # ARP
        data=b'\x00' * 28,
    )
    assert _parse_packet(bytes(eth)) is None


def test_icmp_returns_none():
    icmp = dpkt.icmp.ICMP(type=8, code=0, data=b'')
    ip = dpkt.ip.IP(
        src=socket.inet_aton("1.1.1.1"),
        dst=socket.inet_aton("2.2.2.2"),
        p=1,
        data=icmp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b'\x00' * 6,
        dst=b'\xff' * 6,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    assert _parse_packet(bytes(eth)) is None
