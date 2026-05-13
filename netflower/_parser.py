import socket
import dpkt
import dpkt.ethernet
import dpkt.ip
import dpkt.tcp
import dpkt.udp


def _parse_packet(buf: bytes):
    """
    Parse an Ethernet frame and return fields needed by FlowSession.

    Returns None if the packet is not IPv4 TCP/UDP.

    Return tuple:
        (src_ip, dst_ip, src_port, dst_port, protocol,
         pkt_len, header_len, payload_len, flags, window)
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None

    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        return None

    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    pkt_len = len(ip)

    transport = ip.data
    if isinstance(transport, dpkt.tcp.TCP):
        src_port = transport.sport
        dst_port = transport.dport
        protocol = 6
        flags = transport.flags
        window = transport.win
        header_len = (transport.off & 0xF0) >> 2
        payload_len = len(transport.data)
    elif isinstance(transport, dpkt.udp.UDP):
        src_port = transport.sport
        dst_port = transport.dport
        protocol = 17
        flags = 0
        window = -1
        header_len = 8
        payload_len = len(transport.data)
    else:
        return None

    return (
        src_ip, dst_ip, src_port, dst_port, protocol,
        pkt_len, header_len, payload_len, flags, window,
    )
