import re
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------- #
#                               Rust Panic Parser                              #
# ---------------------------------------------------------------------------- #


@dataclass
class RustPanicInfo:
    thread: str
    file_dir: Path
    file_name: str
    file_line: int
    file_column: int
    message: str

    @property
    def file_path(self) -> Path:
        return self.file_dir / self.file_name

    @property
    def full_location(self) -> str:
        return f"{self.file_dir}/{self.file_name}:{self.file_line}:{self.file_column}"


# -------------------------- Common Library Sources -------------------------- #


def parse_panic_info(msg: str) -> list[RustPanicInfo]:
    """
    This function tries to detect the common rust panic format inside of a string.
    It parses each occurrence and returns a list of `RustPanicInfo` objects
    summarizing them.
    """
    summaries: list[RustPanicInfo] = []
    pattern = re.compile(
        r"thread '(.+?)' panicked at ([^\n\r\t]+?)/([^/\n\r\t]+?):([0-9]+):([0-9]+):\n"
        r"(.+?)\n"
        r"((note: run with `RUST_BACKTRACE=)|(stack backtrace:))",
        flags=re.DOTALL | re.MULTILINE,
    )
    for re_match in re.finditer(pattern, msg):
        summaries.append(
            RustPanicInfo(
                thread=re_match.group(1),
                file_dir=Path(re_match.group(2)),  # trusts that rust reports it in path format
                file_name=re_match.group(3),
                file_line=int(re_match.group(4)),  # can be casted based on regex format
                file_column=int(re_match.group(5)),  # can be casted based on regex format
                message=re_match.group(6),
            )
        )
    return summaries


# -------------------------- Common Library Sources -------------------------- #
