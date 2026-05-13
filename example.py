"""
Usage examples for netflower.

Install:
    pip install netflower

Live capture (requires root or CAP_NET_RAW):
    python example.py live eth0

PCAP to CSV:
    python example.py pcap capture.pcap [output.csv]
"""

import sys
import time


def example_live(interface: str) -> None:
    from netflower import capture_live

    def on_flow(flow):
        print(
            f"{flow['src_ip']}:{flow['src_port']} -> "
            f"{flow['dst_ip']}:{flow['dst_port']} | "
            f"duration={flow['flow_duration']:.3f}s  "
            f"pkts={flow['tot_fwd_pkts'] + flow['tot_bwd_pkts']}"
        )

    print(f"Capturing on {interface!r} — Ctrl+C to stop\n")
    handle = capture_live(interface, on_flow=on_flow)
    handle.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        handle.stop()


def example_pcap(input_path: str, output_path: str) -> None:
    from netflower import convert_pcap_to_csv

    t0 = time.perf_counter()
    n_flows = convert_pcap_to_csv(input_path, output_path)
    elapsed = time.perf_counter() - t0
    print(f"Wrote {n_flows} flows to {output_path!r} in {elapsed:.2f}s")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "live":
        if len(sys.argv) < 3:
            print("Usage: python example.py live <interface>")
            sys.exit(1)
        example_live(sys.argv[2])

    elif mode == "pcap":
        if len(sys.argv) < 3:
            print("Usage: python example.py pcap <input.pcap> [output.csv]")
            sys.exit(1)
        input_path = sys.argv[2]
        output_path = sys.argv[3] if len(sys.argv) > 3 else "flows.csv"
        example_pcap(input_path, output_path)

    else:
        print(__doc__)
        sys.exit(1)
