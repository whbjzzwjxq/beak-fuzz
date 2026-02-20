import os
import re
import shutil
from pathlib import Path

# ---------------------------------------------------------------------------- #
#                                  File Helper                                 #
# ---------------------------------------------------------------------------- #


def path_to_binary(binary: str) -> str:
    """Either returns a path in form of a `str` to the requested binary,
    or throws a `RuntimeError`.
    """
    binary_path = shutil.which(binary)
    if binary_path is None:
        if os.environ.get("FUZZER_TEST"):
            return ""
        else:
            raise RuntimeError(
                f"Unable to find '{binary}' binary! If this was triggered during unittesting, "
                "set environment variable 'FUZZER_TEST=0' to disable binary checks."
            )
    else:
        return binary_path


# ---------------------------------------------------------------------------- #


def create_dir(dirpath: Path) -> Path:
    """Creates a directory structure including non existing parent folders"""
    absolute_dirpath = dirpath.absolute()
    if not absolute_dirpath.exists():
        absolute_dirpath.mkdir(parents=True)
    return absolute_dirpath


# ---------------------------------------------------------------------------- #


def create_file(filepath: Path, content: str):
    """Creates a file at a certain position including non existing parent folders"""
    absolute_filepath = filepath.absolute()
    create_dir(absolute_filepath.parent)
    with open(absolute_filepath, "w") as file_handler:
        file_handler.write(content)


# ---------------------------------------------------------------------------- #


def create_binary_file(filepath: Path, content: bytes):
    """Creates a file at a certain position including non existing parent folders"""
    absolute_filepath = filepath.absolute()
    create_dir(absolute_filepath.parent)
    with open(absolute_filepath, "wb") as file_handler:
        file_handler.write(content)


# ---------------------------------------------------------------------------- #


def overwrite_file(filepath: Path, content: str):
    """Overwrites a file with the provided content.
    If the file does not exist, this function will throw an `IOError`."""
    absolute_filepath = filepath.absolute()
    if not absolute_filepath.is_file():
        raise FileNotFoundError(f"Unable override file '{filepath}'! File does not exists!")
    absolute_filepath.write_text(content)


# ---------------------------------------------------------------------------- #


def replace_in_file(filepath: Path, replacements: list[tuple[str, str]], *, flags: int = 0) -> bool:
    """Replaces text in a file using regex patterns. `filepath` is the file to modify,
    `replacements` is a list of pairs containing a regex pattern and a replacement string.
    The function returns `True` of at least one pattern matched and `False` otherwise.
    If the file is not present a `FileNotFoundError` exception is thrown."""

    if not filepath.exists():
        raise FileNotFoundError(
            f"Unable to replace content of file '{filepath}'! File does not exists!"
        )

    old_content = filepath.read_text()

    new_content = old_content
    for pattern, replacement in replacements:
        new_content = re.sub(pattern, replacement, new_content, flags=flags)

    # check if the content changed
    if old_content != new_content:
        filepath.write_text(new_content)
        return True

    # else: no changes were made
    return False


# ---------------------------------------------------------------------------- #


def prepend_file(filepath: Path, content: str, skip_comments: bool = True):
    """Prepends the provided content to a file.
    If `skip_comments` is activated the first comments are ignored.
    If the file does not exist, this function will throw an `IOError`."""
    absolute_filepath = filepath.absolute()
    if not absolute_filepath.is_file():
        raise FileNotFoundError(f"Unable prepend to file '{filepath}'! File does not exists!")

    old_lines = None
    with open(absolute_filepath, "r") as file_handler:
        old_lines = file_handler.readlines()

    inside_of_comment = False
    inside_of_allow_directive = False

    offset = 0
    comments = []
    if skip_comments:
        for line in old_lines:

            if (
                inside_of_comment
                or inside_of_allow_directive
                or line == "\n"
                or "//" in line
                or "#![" in line
                or "/*" in line
                or "*/" in line
            ):
                if "/*" in line:
                    inside_of_comment = True

                if "#![allow(" in line:
                    inside_of_allow_directive = True

                offset += 1
                comments.append(line)

                if "*/" in line and inside_of_comment:
                    inside_of_comment = False

                if ")]" in line and inside_of_allow_directive:
                    inside_of_allow_directive = False
            else:
                break

    file_comments = "".join(comments)
    file_tail = "".join(old_lines[offset:])
    file_content = f"{file_comments}\n{content}\n{file_tail}"

    absolute_filepath.write_text(file_content)


# ---------------------------------------------------------------------------- #
