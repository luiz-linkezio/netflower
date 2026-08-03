"""
Live packet capture using system libpcap via ctypes.

Usage:
    from netflower import capture_live

    handle = capture_live("eth0", on_flow=lambda flow: print(flow), idle_timeout=30)
    handle.start()
    # ... do work ...
    handle.stop()
"""

import ctypes
import threading
import warnings

from ._libpcap import (
    PcapHandler_cb, PktHdr,
    pcap_open_live, pcap_loop, pcap_breakloop, pcap_close,
    pcap_dump_open, pcap_dump, pcap_dump_close,
)
from ._parser import _parse_packet
from ._session import FlowSession
from ._constants import FLOW_TIMEOUT


class CallbackWriter:
    """Writer that calls on_flow(dict) instead of writing to a CSV file."""

    def __init__(self, on_flow: callable) -> None:
        self._on_flow = on_flow

    def write(self, flow_dict: dict) -> None:
        self._on_flow(flow_dict)


class _PcapSavingWriter:
    """
    Wraps on_flow callable. When a flow is emitted, also dumps its raw packets
    to a .pcap file in pcap_dir before clearing the buffer.
    """

    def __init__(self, on_flow: callable, pcap_dir: str, pcap_handle) -> None:
        self._on_flow = on_flow
        self._pcap_dir = pcap_dir
        self._pcap_handle = pcap_handle
        # flow_key -> list of (PktHdr, bytes)
        self._buffers: dict[tuple, list] = {}

    def write(self, flow_dict: dict) -> None:
        key = (
            flow_dict.get("protocol"),
            flow_dict.get("src_ip"),
            flow_dict.get("dst_ip"),
            flow_dict.get("src_port"),
            flow_dict.get("dst_port"),
        )
        packets = self._buffers.pop(key, [])
        if packets:
            ts_us = int(flow_dict.get("timestamp", 0) * 1_000_000)
            fname = (
                f"{self._pcap_dir}/"
                f"{flow_dict.get('src_ip')}-{flow_dict.get('src_port')}-"
                f"{flow_dict.get('dst_ip')}-{flow_dict.get('dst_port')}-"
                f"{flow_dict.get('protocol')}-{ts_us}.pcap"
            ).encode()
            dumper = pcap_dump_open(self._pcap_handle, fname)
            if dumper:
                for hdr, data in packets:
                    pcap_dump(dumper, ctypes.byref(hdr), data)
                pcap_dump_close(dumper)
        self._on_flow(flow_dict)

    def buffer_packet(self, key: tuple, hdr: PktHdr, data: bytes) -> None:
        if key not in self._buffers:
            self._buffers[key] = []
        self._buffers[key].append((hdr, data))


class CaptureHandle:
    """
    Handle returned by capture_live(). Controls start/stop of capture thread.

    Parameters
    ----------
    interface:    Network interface name as bytes (e.g. b"eth0").
    on_flow:      Callable receiving a flow dict when a flow completes.
    idle_timeout: Seconds of inactivity before a flow is emitted.
    flow_timeout: Absolute max flow duration before forced emit.
    save_pcap:    If True, save raw packets of each completed flow to pcap_dir.
    pcap_dir:     Directory path for .pcap files. Required when save_pcap=True.
    """

    _GC_INTERVAL = 1000
    _JOIN_TIMEOUT = 5.0

    def __init__(
        self,
        interface: bytes,
        on_flow: callable,
        idle_timeout: float,
        flow_timeout: float,
        save_pcap: bool,
        pcap_dir: str | None,
    ) -> None:
        if save_pcap and pcap_dir is None:
            raise ValueError("pcap_dir is required when save_pcap=True")
        self._interface = interface
        self._on_flow = on_flow
        self._idle_timeout = idle_timeout
        self._flow_timeout = flow_timeout
        self._save_pcap = save_pcap
        self._pcap_dir = pcap_dir
        self._handle = None
        self._thread: threading.Thread | None = None
        self._session = None
        self._writer = None
        self._callback = None

    def start(self) -> None:
        errbuf = ctypes.create_string_buffer(256)
        self._handle = pcap_open_live(self._interface, 65535, 1, 1000, errbuf)
        if not self._handle:
            raise RuntimeError(f"pcap_open_live failed: {errbuf.value.decode()}")

        if self._save_pcap:
            self._writer = _PcapSavingWriter(self._on_flow, self._pcap_dir, self._handle)
        else:
            self._writer = CallbackWriter(self._on_flow)

        self._session = FlowSession(
            self._writer, self._idle_timeout, active_timeout=self._flow_timeout
        )
        self._pkt_counter = 0

        @PcapHandler_cb
        def _callback(user, pkthdr_p, pkt_data):
            hdr = pkthdr_p.contents
            ts = hdr.ts_sec + hdr.ts_usec / 1_000_000
            buf = ctypes.string_at(pkt_data, hdr.caplen)
            parsed = _parse_packet(buf)
            if parsed is None:
                return
            src_ip, dst_ip, src_port, dst_port, proto, pkt_len, hdr_len, pay_len, flags, win = parsed
            if self._save_pcap:
                fwd_key = (proto, src_ip, dst_ip, src_port, dst_port)
                bwd_key = (proto, dst_ip, src_ip, dst_port, src_port)
                key = fwd_key if (fwd_key in self._session._flows
                                  or bwd_key not in self._session._flows) else bwd_key
                # libpcap reuses the pkthdr buffer after the callback returns,
                # so buffer a copy rather than a view into that memory
                self._writer.buffer_packet(key, PktHdr.from_buffer_copy(hdr), buf)
            self._session.process(ts, src_ip, dst_ip, src_port, dst_port,
                                  proto, pkt_len, hdr_len, pay_len, flags, win)
            self._pkt_counter += 1
            if self._pkt_counter % self._GC_INTERVAL == 0:
                self._session.gc(ts)

        # Keep reference to prevent ctypes GC
        self._callback = _callback

        self._thread = threading.Thread(
            target=pcap_loop,
            args=(self._handle, -1, self._callback, None),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._handle:
            pcap_breakloop(self._handle)
        if self._thread:
            self._thread.join(timeout=self._JOIN_TIMEOUT)
            if self._thread.is_alive():
                # Closing the handle while pcap_loop still uses it would be a
                # use-after-free; leak it instead and let the caller retry.
                warnings.warn(
                    "capture thread did not exit within "
                    f"{self._JOIN_TIMEOUT}s; pcap handle left open",
                    RuntimeWarning,
                )
                return
        if self._session:
            self._session.flush_all()
        if self._handle:
            pcap_close(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop()


def capture_live(
    interface: str,
    on_flow: callable,
    idle_timeout: float = 30.0,
    flow_timeout: float = FLOW_TIMEOUT,
    save_pcap: bool = False,
    pcap_dir: str | None = None,
) -> CaptureHandle:
    """
    Capture live packets from a network interface and emit completed flows.

    Requires root or CAP_NET_RAW privilege.

    Parameters
    ----------
    interface:    Network interface name (e.g. "eth0").
    on_flow:      Called with a flow dict (82 fields) when a flow completes.
                  Same column names as convert_pcap_to_csv output.
    idle_timeout: Seconds of inactivity before a flow is emitted (default 30).
    flow_timeout: Absolute max flow duration in seconds (default 120).
    save_pcap:    Save raw packets of each completed flow to a .pcap file.
    pcap_dir:     Directory for .pcap files. Required when save_pcap=True.

    Returns
    -------
    CaptureHandle — call .start() to begin capture, .stop() to end.

    Example
    -------
    >>> handle = capture_live("eth0", on_flow=lambda f: print(f["flow_duration"]))
    >>> handle.start()
    >>> import time; time.sleep(60)
    >>> handle.stop()
    """
    return CaptureHandle(
        interface=interface.encode() if isinstance(interface, str) else interface,
        on_flow=on_flow,
        idle_timeout=idle_timeout,
        flow_timeout=flow_timeout,
        save_pcap=save_pcap,
        pcap_dir=pcap_dir,
    )
