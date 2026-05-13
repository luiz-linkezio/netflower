<p align="center">
  <img src="assets/icon.png" alt="netflower" width="128" />
</p>

<h1 align="center">netflower</h1>

<p align="center">High-performance network flow extractor with live capture support for edge devices.</p>

Converts live network traffic or `.pcap` / `.pcapng` captures into bidirectional flow features compatible with the [CICFlowMeter](https://www.unb.ca/cic/research/applications.html) feature set — using a fraction of the memory and CPU.

## Why netflower?

| | CICFlowMeter | netflower |
|---|---|---|
| Packet parser | Scapy | dpkt |
| Memory per flow | O(n packets) | O(1) — Welford's online algorithm |
| Output buffering | ? | Batched (1 syscall/500 rows) |
| Parallelism | ✗ | ✓ — `n_jobs` parameter |
| pcapng support | ✗ | ✓ |
| Live capture | ✗ | ✓ — `capture_live` |

## Installation

```bash
pip install netflower
```

Live capture requires libpcap installed on the system:

```bash
# Linux
sudo apt install libpcap-dev

# macOS
brew install libpcap
```

## Quick start

### Batch mode — PCAP file to CSV

```python
from netflower import convert_pcap_to_csv

n = convert_pcap_to_csv("capture.pcap", "flows.csv")
print(f"Extracted {n} flows")

# Use all available CPUs
n = convert_pcap_to_csv("capture.pcap", "flows.csv", n_jobs=-1)
```

### Live capture

```python
from netflower import capture_live

def on_flow(flow):
    print(flow["flow_duration"], flow["tot_fwd_pkts"])

handle = capture_live("eth0", on_flow=on_flow, idle_timeout=30)
handle.start()

# ... do other work ...

handle.stop()
```

Or as a context manager:

```python
with capture_live("eth0", on_flow=on_flow) as handle:
    handle.start()
    import time; time.sleep(60)
```

> **Note:** Live capture requires root or `CAP_NET_RAW` privilege.

## API

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

### `capture_live(interface, on_flow, **kwargs) → CaptureHandle`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `interface` | — | Network interface name (e.g. `"eth0"`) |
| `on_flow` | — | Callable receiving a flow `dict` when a flow completes |
| `idle_timeout` | `30.0` | Seconds of inactivity before a flow is emitted |
| `flow_timeout` | `120.0` | Absolute max flow duration before forced emit |
| `save_pcap` | `False` | Save raw packets of each completed flow to a `.pcap` file |
| `pcap_dir` | `None` | Directory for `.pcap` files (required when `save_pcap=True`) |

Returns a `CaptureHandle` with `.start()` and `.stop()` methods.

Flow completion triggers:
- TCP FIN or RST seen in any direction
- No packet for `idle_timeout` seconds
- Flow alive for more than `flow_timeout` seconds

The `on_flow` callback receives the same 82-field `dict` as `convert_pcap_to_csv` output — same column names, same feature semantics.

## Output features

Each flow contains **82 features** covering:

- Flow identity: source/destination IP, port, protocol, timestamp
- Duration, bytes/s, and packets/s (forward, backward, combined)
- Packet length statistics (mean, std, min, max, variance)
- Inter-arrival time statistics (flow, forward, backward)
- TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
- Active/idle period statistics
- Bulk transfer metrics (forward and backward)
- Subflow metrics
- Initial TCP window sizes

## Supported input formats

- **pcap** — standard libpcap format
- **pcapng** — next-generation capture format

Only **IPv4 TCP and UDP** flows are extracted; other protocols are silently skipped.

## License

MIT — see [LICENSE](LICENSE).
