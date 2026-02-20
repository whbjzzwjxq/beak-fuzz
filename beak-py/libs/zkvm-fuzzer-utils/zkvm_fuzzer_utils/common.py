import re


def to_clean_quoted_entry(value: str, *, max_msg_len: int | None = None) -> str:
    """
    Helper function to clean up a string to use inside of a CSV file.
        * removes unwanted bytes
        * replaces new lines
        * replaces "|" with <PIPE>
        * can be length restricted using `max_msg_len`
    """
    value = re.sub(r"[^\x20-\x7E\r\n\t]", "?", value)
    value = value.replace("\n", "\\n").replace("\r", "").replace("|", "<PIPE>")
    if max_msg_len is not None and len(value) > max_msg_len:
        value = value[:max_msg_len] + " (...)"
    return f"|{value}|"


# ---------------------------------------------------------------------------- #
#                             General Parser Helper                            #
# ---------------------------------------------------------------------------- #


def parse_hms_as_seconds(hms: str) -> int | None:
    """Given a time amount given in `hms` format, e.g. `2h10m`, `55m1s`, `1h1m1s`,
    it returns the amount in seconds. If the format is malformed, the return value
    is `None`.
    """

    pattern = re.compile(r"^(h(?P<h>[0-9]+))?(m(?P<m>[0-9]+))?(s(?P<s>[0-9]+))?$")
    matched = re.match(pattern, hms)

    if matched:
        accumulator = 0
        hours = matched.group("h")
        minutes = matched.group("m")
        seconds = matched.group("s")

        if hours is None and minutes is None and seconds is None:
            return None

        accumulator += int(hours) * 3600 if hours else 0
        accumulator += int(minutes) * 60 if minutes else 0
        accumulator += int(seconds) if seconds else 0

        return accumulator

    return None


# ---------------------------------------------------------------------------- #
