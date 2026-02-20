import re


def comment_func_call_stmts(func: str, code: str) -> str:
    """
    Given Rust source code, replace any occurrence of `func(...) ;` with a commented version:
      `/* func(...); */`

    The internal body of the function call may span multiple lines.
    """

    # - MULTILINE makes ^/$ match line boundaries
    # - DOTALL makes '.' match newlines
    flags = re.DOTALL | re.MULTILINE
    pattern = re.compile(func + r"\s*\((.*?)\);", flags=flags)

    def replacer(m: re.Match[str]) -> str:
        return f"/* {func}({m.group(1)}); */"

    return re.sub(pattern, replacer, code)

