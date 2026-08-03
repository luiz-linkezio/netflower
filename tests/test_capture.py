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
    for symbol in (
        pcap_open_live, pcap_loop, pcap_breakloop, pcap_close,
        pcap_dump_open, pcap_dump, pcap_dump_close,
        PcapHandler, PcapDumper, PktHdr,
    ):
        assert symbol is not None


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


def test_capture_session_honors_both_timeouts(monkeypatch):
    """idle_timeout must drive idle expiry; flow_timeout is the absolute cap."""
    from netflower import _capture as cap_mod

    monkeypatch.setattr(cap_mod, "pcap_open_live", lambda *a: ctypes.c_void_p(1))
    monkeypatch.setattr(cap_mod, "pcap_loop", lambda *a: 0)
    monkeypatch.setattr(cap_mod, "pcap_breakloop", lambda *a: None)
    monkeypatch.setattr(cap_mod, "pcap_close", lambda *a: None)

    from netflower._capture import CaptureHandle
    handle = CaptureHandle(b"eth0", on_flow=lambda f: None,
                           idle_timeout=30.0, flow_timeout=120.0,
                           save_pcap=False, pcap_dir=None)
    handle.start()
    try:
        assert handle._session._timeout == 30.0
        assert handle._session._active_timeout == 120.0
    finally:
        handle.stop()


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


def test_save_pcap_buffers_header_copy(monkeypatch, tmp_path):
    """Buffered headers must be copies — libpcap reuses its pkthdr memory
    between callbacks, so storing a view would corrupt every dumped packet."""
    from netflower import _capture as cap_mod
    from netflower._libpcap import PktHdr
    from test_parser import _make_tcp_packet

    monkeypatch.setattr(cap_mod, "pcap_open_live", lambda *a: ctypes.c_void_p(1))
    monkeypatch.setattr(cap_mod, "pcap_loop", lambda *a: 0)
    monkeypatch.setattr(cap_mod, "pcap_breakloop", lambda *a: None)
    monkeypatch.setattr(cap_mod, "pcap_close", lambda *a: None)
    monkeypatch.setattr(cap_mod, "pcap_dump_open", lambda *a: None)

    from netflower._capture import CaptureHandle
    handle = CaptureHandle(b"eth0", on_flow=lambda f: None,
                           idle_timeout=30.0, flow_timeout=120.0,
                           save_pcap=True, pcap_dir=str(tmp_path))
    handle.start()
    try:
        pkt = _make_tcp_packet()
        hdr = PktHdr(ts_sec=100, ts_usec=0, caplen=len(pkt), len=len(pkt))
        buf = ctypes.create_string_buffer(pkt, len(pkt))
        handle._callback(None, ctypes.pointer(hdr), ctypes.cast(buf, ctypes.c_void_p))

        # Simulate libpcap overwriting its header buffer after the callback
        hdr.ts_sec = 999

        [packets] = handle._writer._buffers.values()
        buffered_hdr, _ = packets[0]
        assert buffered_hdr.ts_sec == 100
    finally:
        handle.stop()


def test_stop_does_not_close_handle_while_thread_running(monkeypatch):
    """pcap_close on a handle still in use by pcap_loop is a use-after-free."""
    import threading
    from netflower import _capture as cap_mod

    release = threading.Event()
    closed = []

    monkeypatch.setattr(cap_mod, "pcap_open_live", lambda *a: ctypes.c_void_p(1))
    monkeypatch.setattr(cap_mod, "pcap_loop", lambda *a: release.wait())
    monkeypatch.setattr(cap_mod, "pcap_breakloop", lambda *a: None)
    monkeypatch.setattr(cap_mod, "pcap_close", lambda *a: closed.append(True))

    from netflower._capture import CaptureHandle
    handle = CaptureHandle(b"eth0", on_flow=lambda f: None,
                           idle_timeout=30.0, flow_timeout=120.0,
                           save_pcap=False, pcap_dir=None)
    handle._JOIN_TIMEOUT = 0.1
    handle.start()
    try:
        with pytest.warns(RuntimeWarning, match="did not exit"):
            handle.stop()
        assert closed == []
    finally:
        release.set()
        handle._thread.join(timeout=5)


def test_save_pcap_requires_pcap_dir():
    from netflower._capture import CaptureHandle
    with pytest.raises(ValueError, match="pcap_dir"):
        CaptureHandle(b"eth0", on_flow=lambda f: None,
                      idle_timeout=30.0, flow_timeout=120.0,
                      save_pcap=True, pcap_dir=None)
