<p align="center">
  <img src="assets/icon.png" alt="netflower" width="128" />
</p>

<h1 align="center">netflower</h1>

<p align="center">High-performance network flow extractor for edge devices.</p>

**netflower** extracts bidirectional network flows — either from a live interface or from `.pcap` / `.pcapng` files — and produces **82 features** compatible with the [CICFlowMeter](https://www.unb.ca/cic/research/applications.html) feature set.

## Features

- **Live capture** — capture flows in real time from a network interface; flows are emitted only when complete (TCP FIN/RST or idle timeout), never cut by an arbitrary boundary
- **PCAP flows to CSV** — convert `.pcap` / `.pcapng` files to flow-based CSV, with optional parallel processing
- **Edge-optimized** — `dpkt` for packet parsing (~10–25x faster than Scapy on ARM), Welford's online algorithm for O(1) memory per flow, batch-buffered CSV output
- **No extra pip dependencies** for live capture — libpcap is accessed via `ctypes`

## Installation

```bash
pip install netflower
```

Live capture requires libpcap on the system:

```bash
# Linux
sudo apt install libpcap-dev

# macOS
brew install libpcap
```

## Usage

### Live capture

Captures packets from a network interface and emits each completed flow via callback.

```python
from netflower import capture_live

def on_flow(flow: dict):
    print(
        f"{flow['src_ip']}:{flow['src_port']} -> "
        f"{flow['dst_ip']}:{flow['dst_port']} | "
        f"duration={flow['flow_duration']:.3f}s  "
        f"pkts={flow['tot_fwd_pkts'] + flow['tot_bwd_pkts']}"
    )

handle = capture_live("eth0", on_flow=on_flow)
handle.start()

# ... rest of your program ...

handle.stop()
```

As a context manager:

```python
import time
with capture_live("eth0", on_flow=on_flow) as handle:
    handle.start()
    time.sleep(60)
```

Save the raw packets of each completed flow to individual `.pcap` files:

```python
handle = capture_live(
    "eth0",
    on_flow=on_flow,
    save_pcap=True,
    pcap_dir="/tmp/flows",
)
handle.start()
```

> **Note:** live capture requires root or `CAP_NET_RAW` privilege.

### PCAP flows to CSV

Converts a `.pcap` or `.pcapng` file into a flow-based CSV.

```python
from netflower import convert_pcap_to_csv

# Single-process
n = convert_pcap_to_csv("capture.pcap", "flows.csv")
print(f"Extracted {n} flows")

# Parallel -- use all available CPUs
n = convert_pcap_to_csv("capture.pcap", "flows.csv", n_jobs=-1)
```

## API

### `capture_live(interface, on_flow, **kwargs) -> CaptureHandle`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `interface` | -- | Network interface name (e.g. `"eth0"`) |
| `on_flow` | -- | Callable receiving a flow `dict` when a flow completes |
| `idle_timeout` | `30.0` | Seconds of inactivity before a flow is emitted |
| `flow_timeout` | `120.0` | Absolute max flow duration before forced emit |
| `save_pcap` | `False` | Save raw packets of each completed flow to a `.pcap` file |
| `pcap_dir` | `None` | Directory for `.pcap` files (required when `save_pcap=True`) |

`CaptureHandle` exposes `.start()`, `.stop()`, and context manager support.

### `convert_pcap_to_csv(input_path, output_path, **kwargs) -> int`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `input_path` | -- | Path to `.pcap` or `.pcapng` file |
| `output_path` | -- | Path for the output `.csv` (created or overwritten) |
| `flow_timeout` | `120.0` | Seconds of inactivity before a flow is evicted |
| `gc_interval` | `1000` | Run idle-flow GC every N packets |
| `buffer_rows` | `500` | Rows buffered in memory before flushing to disk |
| `n_jobs` | `1` | Worker processes. `-1` uses all available CPUs |

Returns the number of flow rows written.

## Architecture

Both APIs share the same internal pipeline:

```
Packet source
    |
    v
_parser.py          parse Ethernet/IP/TCP/UDP frame
                    discard non-IPv4-TCP/UDP packets
    |
    v
FlowSession         hash table of active flows
                    route each packet to the correct Flow
                    (forward or backward direction)
    |
    v
Flow                accumulate statistics incrementally -- O(1) per packet,
                    O(1) memory (Welford's online algorithm, no lists stored)
    |
    v  on timeout / FIN / RST / flush_all
Writer              emit the 82-feature dict
```

### Live capture internals

`capture_live` wraps libpcap via `ctypes` (no compiled extension required):

1. **`pcap_open_live`** opens the interface in promiscuous mode (`snaplen=65535`, `to_ms=1000`).
2. A `PcapHandler_cb` C-callable is registered and `pcap_loop(-1, ...)` is launched in a **daemon thread**.
3. Each callback invocation reads raw bytes with `ctypes.string_at(pkt_data, hdr.caplen)` and forwards the packet to `FlowSession`.
4. **Garbage collection** runs every 1 000 packets (`session.gc(ts)`) to evict flows that exceeded `flow_timeout`.
5. `handle.stop()` calls `pcap_breakloop` (thread-safe), waits for the thread (timeout 5 s), flushes remaining flows, and closes the handle.

When `save_pcap=True`, a `_PcapSavingWriter` buffers raw `(PktHdr, bytes)` per flow key and writes a dedicated `.pcap` file via `pcap_dump_open / pcap_dump / pcap_dump_close` at the moment each flow is emitted.

### PCAP converter internals

**Single-process mode (`n_jobs=1`):** packets are read sequentially via `dpkt`, parsed, and fed directly into a `FlowSession` -> `CsvWriter` chain.

**Parallel mode (`n_jobs > 1`):**

```
main process
  reads packets sequentially
  routes each packet by hash(bidirectional_key) % n_jobs
       |              |              |
       v              v              v
  worker 0       worker 1  ...  worker N-1
  FlowSession    FlowSession    FlowSession
  temp_0.csv     temp_1.csv     temp_N.csv
       |              |              |
       +——————————————+——————————————+
                      |
                 _merge_csvs
                      |
                 flows.csv
```

The routing hash is **bidirectionally deterministic** — `min(a,b), max(a,b), proto` — so forward and backward packets of the same flow always land on the same worker. GC messages are broadcast to all workers every `gc_interval` packets.

### Key constants

| Constant | Value | Role |
|----------|-------|------|
| `FLOW_TIMEOUT` | 120 s | Inactivity window that closes a flow |
| `ACTIVE_TIMEOUT` | 5 s | Gap that ends an active period |
| `CLUMP_TIMEOUT` | 1 s | Gap that starts a new subflow |
| `BULK_BOUND` | 4 pkts | Minimum packets to register a bulk transfer |
| `CSV_BUFFER_ROWS` | 500 | Rows buffered before a disk write |

## Flow features

Both APIs produce the same **82 features** per flow:

| Category | Features |
|----------|----------|
| Identity | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `timestamp` |
| Duration & rates | `flow_duration`, `flow_byts_s`, `flow_pkts_s`, `fwd_pkts_s`, `bwd_pkts_s` |
| Packet counts | `tot_fwd_pkts`, `tot_bwd_pkts`, `totlen_fwd_pkts`, `totlen_bwd_pkts` |
| Packet length stats | `fwd_pkt_len_{max,min,mean,std}`, `bwd_pkt_len_{max,min,mean,std}`, `pkt_len_{max,min,mean,std,var}` |
| IAT stats | `flow_iat_{mean,max,min,std}`, `fwd_iat_{tot,max,min,mean,std}`, `bwd_iat_{tot,max,min,mean,std}` |
| TCP flags | `fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `ece`, `cwr` flag counts (+ per-direction PSH/URG) |
| Window | `init_fwd_win_byts`, `init_bwd_win_byts` |
| Segment | `fwd_seg_size_min`, `fwd_seg_size_avg`, `bwd_seg_size_avg`, `fwd_act_data_pkts` |
| Bulk | `fwd/bwd_byts_b_avg`, `fwd/bwd_pkts_b_avg`, `fwd/bwd_blk_rate_avg` |
| Subflow | `subflow_fwd_pkts`, `subflow_fwd_byts`, `subflow_bwd_pkts`, `subflow_bwd_byts` |
| Active/idle | `active_{max,min,mean,std}`, `idle_{max,min,mean,std}` |
| Misc | `down_up_ratio`, `pkt_size_avg` |

## Supported formats

- **pcap** -- standard libpcap format
- **pcapng** -- next-generation capture format

Only **IPv4 TCP and UDP** flows are extracted; other protocols are silently skipped.

## License

MIT -- see [LICENSE](LICENSE).
