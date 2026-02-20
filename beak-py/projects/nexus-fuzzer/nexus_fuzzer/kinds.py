try:
    from enum import StrEnum  # py>=3.11
except ImportError:  # pragma: no cover
    from enum import Enum

    class StrEnum(str, Enum):
        pass


class InstrKind(StrEnum):
    GENERIC = "generic"


class InjectionKind(StrEnum):
    NONE = "none"

