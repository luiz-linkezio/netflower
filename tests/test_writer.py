import csv
from netflower._writer import CsvWriter


def _row(i=0):
    return {"a": i, "b": i * 2, "c": f"val{i}"}


def test_writes_header_and_rows(tmp_path):
    out = tmp_path / "out.csv"
    with CsvWriter(str(out), buffer_rows=10) as w:
        w.write(_row(0))
        w.write(_row(1))
    with open(out) as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2
    assert rows[0]["a"] == "0"
    assert rows[1]["b"] == "2"


def test_buffer_flush_on_threshold(tmp_path):
    out = tmp_path / "out.csv"
    with CsvWriter(str(out), buffer_rows=3) as w:
        for i in range(7):
            w.write(_row(i))
    with open(out) as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 7


def test_row_count(tmp_path):
    out = tmp_path / "out.csv"
    with CsvWriter(str(out), buffer_rows=5) as w:
        for i in range(12):
            w.write(_row(i))
    assert w.row_count == 12


def test_empty_writer_produces_no_rows(tmp_path):
    out = tmp_path / "out.csv"
    with CsvWriter(str(out)) as w:
        pass
    assert w.row_count == 0
    assert out.read_text() == ""


def test_context_manager_flushes_on_exit(tmp_path):
    out = tmp_path / "out.csv"
    with CsvWriter(str(out), buffer_rows=100) as w:
        for i in range(5):
            w.write(_row(i))
    # buffer_rows=100 so nothing flushed mid-loop; __exit__ must flush
    with open(out) as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 5
