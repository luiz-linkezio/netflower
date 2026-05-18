"""
Minimal ctypes binding to libpcap.

Only the subset needed for live capture and pcap dumping is exposed.
Requires libpcap installed on the system:
  Linux:  apt install libpcap-dev  (or libpcap is usually already present)
  macOS:  brew install libpcap  (or use system libpcap)
"""

import ctypes
import ctypes.util
import sys


def _load_libpcap():
    for name in ("libpcap.so.1", "libpcap.so", "libpcap.dylib"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    found = ctypes.util.find_library("pcap")
    if found:
        try:
            return ctypes.CDLL(found)
        except OSError:
            pass
    raise ImportError(
        "libpcap not found. Install it with:\n"
        "  Linux:  sudo apt install libpcap-dev\n"
        "  macOS:  brew install libpcap"
    )


_lib = _load_libpcap()

# --- Types ------------------------------------------------------------------

PcapHandler = ctypes.c_void_p
PcapDumper  = ctypes.c_void_p


# suseconds_t is int (4 bytes) on macOS, long (8 bytes) on Linux 64-bit.
_suseconds_t = ctypes.c_int32 if sys.platform == "darwin" else ctypes.c_long

class PktHdr(ctypes.Structure):
    _fields_ = [
        ("ts_sec",  ctypes.c_long),
        ("ts_usec", _suseconds_t),
        ("caplen",  ctypes.c_uint32),
        ("len",     ctypes.c_uint32),
    ]


# Callback type for pcap_loop: void handler(u_char *user, pkthdr *h, u_char *bytes)
PcapHandler_cb = ctypes.CFUNCTYPE(
    None,
    ctypes.c_char_p,          # user data (unused, pass NULL)
    ctypes.POINTER(PktHdr),   # packet header
    ctypes.c_char_p,          # packet data
)

# --- Function bindings ------------------------------------------------------

pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype  = PcapHandler
pcap_open_live.argtypes = [
    ctypes.c_char_p,   # device
    ctypes.c_int,      # snaplen
    ctypes.c_int,      # promisc
    ctypes.c_int,      # to_ms
    ctypes.c_char_p,   # errbuf (256 bytes)
]

pcap_loop = _lib.pcap_loop
pcap_loop.restype  = ctypes.c_int
pcap_loop.argtypes = [
    PcapHandler,       # handle
    ctypes.c_int,      # cnt (-1 = infinite)
    PcapHandler_cb,    # callback
    ctypes.c_char_p,   # user data
]

pcap_breakloop = _lib.pcap_breakloop
pcap_breakloop.restype  = None
pcap_breakloop.argtypes = [PcapHandler]

pcap_close = _lib.pcap_close
pcap_close.restype  = None
pcap_close.argtypes = [PcapHandler]

pcap_dump_open = _lib.pcap_dump_open
pcap_dump_open.restype  = PcapDumper
pcap_dump_open.argtypes = [PcapHandler, ctypes.c_char_p]

pcap_dump = _lib.pcap_dump
pcap_dump.restype  = None
pcap_dump.argtypes = [
    PcapDumper,
    ctypes.POINTER(PktHdr),
    ctypes.c_char_p,
]

pcap_dump_close = _lib.pcap_dump_close
pcap_dump_close.restype  = None
pcap_dump_close.argtypes = [PcapDumper]
