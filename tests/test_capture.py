import ctypes
import sys
import pytest


def test_pkthdr_struct_layout_matches_platform():
    """PktHdr must match the C pcap_pkthdr layout for the current platform."""
    from netflower._libpcap import PktHdr

    if sys.platform == "darwin":
        # macOS 64-bit: suseconds_t is int (4 bytes)
        expected_size = 20
        expected_offsets = {
            "ts_sec":  0,
            "ts_usec": 8,
            "caplen":  12,
            "len":     16,
        }
    else:
        # Linux 64-bit: both tv_sec and tv_usec are long (8 bytes)
        expected_size = 24
        expected_offsets = {
            "ts_sec":  0,
            "ts_usec": 8,
            "caplen":  16,
            "len":     20,
        }

    assert ctypes.sizeof(PktHdr) == expected_size, (
        f"PktHdr size {ctypes.sizeof(PktHdr)} != expected {expected_size}; "
        "struct layout mismatch will cause segfaults on live capture"
    )
    for field, expected_offset in expected_offsets.items():
        actual = getattr(PktHdr, field).offset
        assert actual == expected_offset, (
            f"PktHdr.{field} offset {actual} != expected {expected_offset}"
        )


def test_libpcap_loads():
    from netflower._libpcap import _lib
    assert _lib is not None


def test_libpcap_has_required_symbols():
    from netflower._libpcap import (
        pcap_open_live, pcap_loop, pcap_breakloop, pcap_close,
        pcap_dump_open, pcap_dump, pcap_dump_close,
        PcapHandler, PcapDumper, PktHdr,
    )
    assert pcap_open_live is not None
    assert pcap_loop is not None


def test_callback_writer_calls_on_flow():
    from netflower._capture import CallbackWriter

    received = []
    writer = CallbackWriter(on_flow=received.append)
    writer.write({"flow_duration": 1.5, "tot_fwd_pkts": 3})
    assert len(received) == 1
    assert received[0]["flow_duration"] == 1.5


def test_callback_writer_multiple_flows():
    from netflower._capture import CallbackWriter

    received = []
    writer = CallbackWriter(on_flow=received.append)
    writer.write({"flow_duration": 1.0})
    writer.write({"flow_duration": 2.0})
    assert len(received) == 2


def test_capture_handle_start_stop(monkeypatch):
    from netflower import _capture as cap_mod

    calls = []

    def fake_open_live(device, snaplen, promisc, to_ms, errbuf):
        calls.append(("open", device))
        return ctypes.c_void_p(1)

    def fake_loop(handle, cnt, callback, user):
        calls.append(("loop",))
        return 0

    def fake_breakloop(handle):
        calls.append(("breakloop",))

    def fake_close(handle):
        calls.append(("close",))

    monkeypatch.setattr(cap_mod, "pcap_open_live", fake_open_live)
    monkeypatch.setattr(cap_mod, "pcap_loop", fake_loop)
    monkeypatch.setattr(cap_mod, "pcap_breakloop", fake_breakloop)
    monkeypatch.setattr(cap_mod, "pcap_close", fake_close)

    from netflower._capture import CaptureHandle
    handle = CaptureHandle(
        interface=b"eth0",
        on_flow=[].append,
        idle_timeout=30.0,
        flow_timeout=120.0,
        save_pcap=False,
        pcap_dir=None,
    )
    handle.start()
    handle.stop()

    assert ("open", b"eth0") in calls
    assert ("loop",) in calls
    assert ("breakloop",) in calls
    assert ("close",) in calls


def test_capture_handle_context_manager(monkeypatch):
    from netflower import _capture as cap_mod

    monkeypatch.setattr(cap_mod, "pcap_open_live", lambda *a: ctypes.c_void_p(1))
    monkeypatch.setattr(cap_mod, "pcap_loop", lambda *a: 0)
    monkeypatch.setattr(cap_mod, "pcap_breakloop", lambda *a: None)
    monkeypatch.setattr(cap_mod, "pcap_close", lambda *a: None)

    from netflower._capture import CaptureHandle
    with CaptureHandle(b"eth0", on_flow=lambda f: None,
                       idle_timeout=30.0, flow_timeout=120.0,
                       save_pcap=False, pcap_dir=None) as h:
        h.start()


def test_save_pcap_requires_pcap_dir():
    from netflower._capture import CaptureHandle
    with pytest.raises(ValueError, match="pcap_dir"):
        CaptureHandle(b"eth0", on_flow=lambda f: None,
                      idle_timeout=30.0, flow_timeout=120.0,
                      save_pcap=True, pcap_dir=None)
