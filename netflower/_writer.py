"""
Buffered CSV writer.

Rows are accumulated in a list and written to disk in batches to avoid
the per-row flush() cost that CICFlowMeter pays on every flow.
"""

import csv
import io
from ._constants import CSV_BUFFER_ROWS


class CsvWriter:
    def __init__(self, output_path: str, buffer_rows: int = CSV_BUFFER_ROWS) -> None:
        self._path = output_path
        self._buffer_rows = buffer_rows
        self._buf: list[dict] = []
        self._header_written = False
        self._fh = open(output_path, "w", newline="", buffering=1 << 16)
        self._writer: csv.DictWriter | None = None
        self.row_count = 0

    def write(self, row: dict) -> None:
        if not self._header_written:
            self._writer = csv.DictWriter(self._fh, fieldnames=list(row.keys()))
            self._writer.writeheader()
            self._header_written = True

        self._buf.append(row)
        if len(self._buf) >= self._buffer_rows:
            self._flush_buffer()

    def _flush_buffer(self) -> None:
        if self._buf and self._writer:
            self._writer.writerows(self._buf)
            self.row_count += len(self._buf)
            self._buf.clear()

    def close(self) -> None:
        self._flush_buffer()
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
