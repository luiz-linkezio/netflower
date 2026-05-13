"""
Main conversion pipeline: PCAP → FlowSession → CSV.

Supports both pcap and pcapng formats.
Packets are streamed one by one; no packet objects are retained after processing.

Parallelism strategy (n_jobs > 1):
  The main process reads packets sequentially and routes each one to a worker
  subprocess based on a deterministic hash of the bidirectional flow key.
  Each worker owns a disjoint subset of flows and writes to a temp CSV.
  Temp CSVs are merged into the final output after all workers finish.
"""

import os
import tempfile
from multiprocessing import Process, Queue
from typing import Iterator

import dpkt
import dpkt.pcapng

from ._session import FlowSession
from ._writer import CsvWriter
from ._parser import _parse_packet
from ._constants import FLOW_TIMEOUT, CSV_BUFFER_ROWS


def _open_pcap(path: str):
    """Return an iterable of (timestamp, raw_bytes) from a pcap or pcapng file."""
    with open(path, "rb") as fh:
        magic = fh.read(4)

    if magic == b"\x0a\x0d\x0d\x0a":
        return _iter_pcapng(path)
    return _iter_pcap(path)


def _iter_pcap(path: str) -> Iterator[tuple[float, bytes]]:
    with open(path, "rb") as fh:
        yield from dpkt.pcap.Reader(fh)


def _iter_pcapng(path: str) -> Iterator[tuple[float, bytes]]:
    with open(path, "rb") as fh:
        yield from dpkt.pcapng.Reader(fh)


def _route(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int, n_jobs: int) -> int:
    """Return the worker index for a bidirectional flow (order-independent)."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a > b:
        a, b = b, a
    return hash((a, b, proto)) % n_jobs


def _worker(task_queue: Queue, result_queue: Queue, output_path: str,
            flow_timeout: float, buffer_rows: int) -> None:
    """Subprocess: drain task_queue, track flows, write CSV to output_path."""
    with CsvWriter(output_path, buffer_rows) as writer:
        session = FlowSession(writer, flow_timeout)
        while True:
            item = task_queue.get()
            if item is None:
                break
            kind = item[0]
            if kind == "pkt":
                _, ts, src_ip, dst_ip, src_port, dst_port, proto, pkt_len, hdr_len, pay_len, flags, win = item
                session.process(ts, src_ip, dst_ip, src_port, dst_port, proto,
                                pkt_len, hdr_len, pay_len, flags, win)
            elif kind == "gc":
                session.gc(item[1])
        session.flush_all()
    result_queue.put(writer.row_count)


def _merge_csvs(sources: list[str], output_path: str) -> None:
    import csv

    header_written = False
    fieldnames = None
    with open(output_path, "w", newline="", buffering=1 << 16) as out_fh:
        out_writer = None
        for src in sources:
            if not os.path.exists(src) or os.path.getsize(src) == 0:
                continue
            with open(src, "r", newline="") as in_fh:
                reader = csv.DictReader(in_fh)
                if not header_written:
                    fieldnames = reader.fieldnames
                    out_writer = csv.DictWriter(out_fh, fieldnames=fieldnames)
                    out_writer.writeheader()
                    header_written = True
                for row in reader:
                    out_writer.writerow(row)


def convert_pcap_to_csv(
    input_path: str,
    output_path: str,
    flow_timeout: float = FLOW_TIMEOUT,
    gc_interval: int = 1000,
    buffer_rows: int = CSV_BUFFER_ROWS,
    n_jobs: int = 1,
) -> int:
    """
    Convert a PCAP (or pcapng) file into a flow-based CSV file.

    Each row in the output CSV represents one bidirectional network flow and
    contains 82 features compatible with the CICFlowMeter feature set.

    Parameters
    ----------
    input_path:   Path to the input .pcap or .pcapng file.
    output_path:  Path for the output .csv file (created or overwritten).
    flow_timeout: Seconds of inactivity before a flow is flushed (default 120).
    gc_interval:  Run idle-flow garbage collection every N packets (default 1000).
    buffer_rows:  Rows buffered in memory before a disk write (default 500).
    n_jobs:       Number of worker processes (default 1).
                  -1 uses all available CPUs.

    Returns
    -------
    Number of flow rows written to the CSV.
    """
    if n_jobs == 0:
        raise ValueError("n_jobs=0 is invalid. Use n_jobs=1 for single-process or n_jobs=-1 for all CPUs.")
    if n_jobs == -1:
        n_jobs = os.cpu_count() or 1
    elif n_jobs < -1:
        n_jobs = max(1, (os.cpu_count() or 1) + n_jobs + 1)

    if n_jobs == 1:
        return _convert_single(input_path, output_path, flow_timeout, gc_interval, buffer_rows)
    return _convert_parallel(input_path, output_path, flow_timeout, gc_interval, buffer_rows, n_jobs)


def _convert_single(
    input_path: str,
    output_path: str,
    flow_timeout: float,
    gc_interval: int,
    buffer_rows: int,
) -> int:
    with CsvWriter(output_path, buffer_rows) as writer:
        session = FlowSession(writer, flow_timeout)
        pkt_counter = 0
        last_ts = 0.0

        for ts, buf in _open_pcap(input_path):
            parsed = _parse_packet(buf)
            if parsed is None:
                continue

            src_ip, dst_ip, src_port, dst_port, proto, pkt_len, hdr_len, pay_len, flags, win = parsed
            session.process(ts, src_ip, dst_ip, src_port, dst_port, proto,
                            pkt_len, hdr_len, pay_len, flags, win)

            pkt_counter += 1
            last_ts = ts

            if pkt_counter % gc_interval == 0:
                session.gc(last_ts)

        session.flush_all()

    return writer.row_count


def _convert_parallel(
    input_path: str,
    output_path: str,
    flow_timeout: float,
    gc_interval: int,
    buffer_rows: int,
    n_jobs: int,
) -> int:
    tmp_dir = tempfile.mkdtemp(prefix="netflower_")
    tmp_files = [os.path.join(tmp_dir, f"worker_{i}.csv") for i in range(n_jobs)]
    task_queues = [Queue(maxsize=2000) for _ in range(n_jobs)]
    result_queue: Queue = Queue()

    workers = [
        Process(
            target=_worker,
            args=(task_queues[i], result_queue, tmp_files[i], flow_timeout, buffer_rows),
            daemon=True,
        )
        for i in range(n_jobs)
    ]
    for w in workers:
        w.start()

    try:
        pkt_counter = 0
        last_ts = 0.0

        for ts, buf in _open_pcap(input_path):
            parsed = _parse_packet(buf)
            if parsed is None:
                continue

            src_ip, dst_ip, src_port, dst_port, proto, pkt_len, hdr_len, pay_len, flags, win = parsed
            wid = _route(src_ip, dst_ip, src_port, dst_port, proto, n_jobs)
            task_queues[wid].put((
                "pkt", ts, src_ip, dst_ip, src_port, dst_port, proto,
                pkt_len, hdr_len, pay_len, flags, win,
            ))

            pkt_counter += 1
            last_ts = ts

            if pkt_counter % gc_interval == 0:
                for q in task_queues:
                    q.put(("gc", last_ts))

        for q in task_queues:
            q.put(None)

        for w in workers:
            w.join()
            if w.exitcode != 0:
                raise RuntimeError(f"Worker process exited with code {w.exitcode}")

    except Exception:
        for q in task_queues:
            try:
                q.put_nowait(None)
            except Exception:
                pass
        for w in workers:
            w.terminate()
        raise

    total = sum(result_queue.get() for _ in range(n_jobs))
    _merge_csvs(tmp_files, output_path)

    for f in tmp_files:
        try:
            os.unlink(f)
        except OSError:
            pass
    try:
        os.rmdir(tmp_dir)
    except OSError:
        pass

    return total
