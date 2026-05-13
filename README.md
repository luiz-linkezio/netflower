<p align="center">
  <img src="assets/icon.png" alt="netflower" width="128" />
</p>

<h1 align="center">netflower</h1>

<p align="center">High-performance network flow extractor for edge devices.</p>

**netflower** extracts bidirectional network flows — either from a live interface or from `.pcap` / `.pcapng` files — and produces 82 features compatible with the [CICFlowMeter](https://www.unb.ca/cic/research/applications.html) feature set.

## Features

- **Live capture** — capture flows in real time from a network interface; flows are emitted only when complete (TCP FIN/RST or idle timeout), never cut by an arbitrary boundary
- **PCAP flows to CSV** — convert `.pcap` / `.pcapng` files to flow-based CSV, with optional parallel processing
- **Edge-optimized** — `dpkt` for packet parsing (~10–25× faster than Scapy on ARM), Welford's online algorithm for O(1) memory per flow, batch-buffered CSV output
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

Captures packets from a network interface and emits each flow the moment it completes.

```python
from netflower import capture_live

def on_flow(flow):
    print(flow["src_ip"], flow["dst_ip"], flow["flow_duration"])

handle = capture_live("eth0", on_flow=on_flow)
handle.start()

# ... rest of your program ...

handle.stop()
```

As a context manager:

```python
with capture_live("eth0", on_flow=on_flow) as handle:
    handle.start()
    import time; time.sleep(60)
```

> **Note:** live capture requires root or `CAP_NET_RAW` privilege.

### PCAP flows to CSV

Converts a `.pcap` or `.pcapng` file into a flow-based CSV.

```python
from netflower import convert_pcap_to_csv

n = convert_pcap_to_csv("capture.pcap", "flows.csv")
print(f"Extracted {n} flows")

# Parallel — use all available CPUs
n = convert_pcap_to_csv("capture.pcap", "flows.csv", n_jobs=-1)
```

## API

### `capture_live(interface, on_flow, **kwargs) → CaptureHandle`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `interface` | — | Network interface name (e.g. `"eth0"`) |
| `on_flow` | — | Callable receiving a flow `dict` when a flow completes |
| `idle_timeout` | `30.0` | Seconds of inactivity before a flow is emitted |
| `flow_timeout` | `120.0` | Absolute max flow duration before forced emit |
| `save_pcap` | `False` | Save raw packets of each completed flow to a `.pcap` file |
| `pcap_dir` | `None` | Directory for `.pcap` files (required when `save_pcap=True`) |

`CaptureHandle` exposes `.start()`, `.stop()`, and context manager support.

### `convert_pcap_to_csv(input_path, output_path, **kwargs) → int`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `input_path` | — | Path to `.pcap` or `.pcapng` file |
| `output_path` | — | Path for the output `.csv` (created or overwritten) |
| `flow_timeout` | `120.0` | Seconds of inactivity before a flow is evicted |
| `gc_interval` | `1000` | Run idle-flow GC every N packets |
| `buffer_rows` | `500` | Rows buffered in memory before flushing to disk |
| `n_jobs` | `1` | Worker processes. `-1` uses all available CPUs |

Returns the number of flow rows written.

## Flow features

Both APIs produce the same **82 features** per flow:

- Flow identity: source/destination IP, port, protocol, timestamp
- Duration, bytes/s, and packets/s (forward, backward, combined)
- Packet length statistics (mean, std, min, max, variance)
- Inter-arrival time statistics (flow, forward, backward)
- TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
- Active/idle period statistics
- Bulk transfer metrics (forward and backward)
- Subflow metrics
- Initial TCP window sizes

## Supported formats

- **pcap** — standard libpcap format
- **pcapng** — next-generation capture format

Only **IPv4 TCP and UDP** flows are extracted; other protocols are silently skipped.

## License

MIT — see [LICENSE](LICENSE).
