from enum import StrEnum
from typing import TypeVar

# ---------------------------------------------------------------------------- #
#                              Generic Bound Types                             #
# ---------------------------------------------------------------------------- #


InstrKind = TypeVar("InstrKind", bound=StrEnum)
InjectionKind = TypeVar("InjectionKind", bound=StrEnum)


# ---------------------------------------------------------------------------- #
