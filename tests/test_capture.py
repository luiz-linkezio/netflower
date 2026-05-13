import ctypes
import pytest


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


def test_pcapflower_import_emits_deprecation_warning():
    import importlib
    import sys
    for key in list(sys.modules.keys()):
        if key.startswith("pcapflower"):
            del sys.modules[key]
    with pytest.warns(DeprecationWarning, match="netflower"):
        importlib.import_module("pcapflower")


def test_pcapflower_stub_reexports_convert():
    import importlib
    import sys
    import warnings
    for key in list(sys.modules.keys()):
        if key.startswith("pcapflower"):
            del sys.modules[key]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pcapflower = importlib.import_module("pcapflower")
    assert hasattr(pcapflower, "convert_pcap_to_csv")
    assert hasattr(pcapflower, "capture_live")
