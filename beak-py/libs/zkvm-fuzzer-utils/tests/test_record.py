from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.record import (
    Record,
    micro_ops_deltas_by_step,
    micro_ops_entries,
    record_from_exec_status,
)

MOCK_STDOUT = """
...
<record>{"context": "abc", "status": "start"}</record>
<record>{"context": "abc", "status": "ok", "time": "100s", "output": "ok"}</record>
<record>{"context": "micro_ops", "step": 0, "pc": 0, "instruction": "ADD", "assembly": "add x0, x0, x0", "chips": [{"chip": "ChipA", "delta": 2, "height": 2}]}</record>
<record>{"context": "micro_ops", "step": 1, "pc": 4, "instruction": "SUB", "assembly": "sub x1, x1, x1", "chips": [{"chip": "ChipA", "delta": 1, "height": 3}, {"chip": "ChipB", "delta": 5, "height": 5}]}</record>
<record>{"context": "xyz", "status": "start"}</record>
<record>{"context": "xyz", "status": "error", "time": "123"}</record>
...
"""

MOCK_STDERR = """
...
thread 'main' panicked at src/main.rs:3:5:
pan
ic
stack backtrace:
   0: __rustc::rust_begin_unwind
...

thread 'main' panicked at src/main.rs:3:5:
pan
ic-2
stack backtrace:
   0: __rustc::rust_begin_unwind
...
"""


def test_empty_record():
    # check robustness

    mock_exec = ExecStatus("no-command", "", "", None, None, -1, -1)
    empty_record = Record([], [], mock_exec)

    assert empty_record.get_entry_by_context("abc") is None
    assert empty_record.get_last_entry() is None
    assert empty_record.panics == []
    assert not empty_record.has_panicked()


def test_record():

    mock_exec = ExecStatus("no-command", MOCK_STDOUT, MOCK_STDERR, None, None, -1, -1)
    record = record_from_exec_status(mock_exec)

    assert len(record.entries) == 6
    assert record.has_panicked()
    assert len(record.panics) > 0

    assert record.entries[0].entries.get("time", None) is None
    assert record.entries[0].entries.get("output", None) is None
    assert record.entries[0].context == "abc"
    assert record.entries[0].entries.get("status", None) == "start"

    assert record.entries[1].entries.get("time", None) == "100s"
    assert record.entries[1].entries.get("output", None) == "ok"
    assert record.entries[1].context == "abc"
    assert record.entries[1].entries.get("status", None) == "ok"

    assert record.entries[2].context == "micro_ops"
    assert record.entries[2].entries.get("step") == 0

    assert record.entries[3].context == "micro_ops"
    assert record.entries[3].entries.get("step") == 1

    assert record.entries[4].entries.get("time", None) is None
    assert record.entries[4].entries.get("output", None) is None
    assert record.entries[4].context == "xyz"
    assert record.entries[4].entries.get("status", None) == "start"

    assert record.entries[5].entries.get("time", None) == "123"
    assert record.entries[5].entries.get("output", None) is None
    assert record.entries[5].context == "xyz"
    assert record.entries[5].entries.get("status", None) == "error"

    assert record.entries[1] == record.get_entry_by_context("abc")
    assert record.entries[5] == record.get_entry_by_context("xyz")
    assert record.entries[5] == record.get_last_entry()
    assert record.get_entries_by_context("micro_ops") == [record.entries[2], record.entries[3]]

    micro_entries = micro_ops_entries(record)
    assert len(micro_entries) == 2
    assert micro_entries[0]["instruction"] == "ADD"

    by_step = micro_ops_deltas_by_step(record)
    assert by_step[0] == {"ChipA": 2}
    assert by_step[1] == {"ChipA": 1, "ChipB": 5}

    assert len(record.panics) == 2
    assert record.panics[0].context == "xyz"
    assert record.panics[1].context == "xyz"

    # NOTE: panic parsing is tested in other tests
