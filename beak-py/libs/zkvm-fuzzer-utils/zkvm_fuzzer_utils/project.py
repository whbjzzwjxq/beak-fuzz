from abc import ABC, abstractmethod
from pathlib import Path

# ---------------------------------------------------------------------------- #
#                               Project Generators                             #
# ---------------------------------------------------------------------------- #


class AbstractProjectGenerator(ABC):
    __root: Path
    __zkvm_path: Path

    def __init__(self, root: Path, zkvm_path: Path):
        self.__root = root
        self.__zkvm_path = zkvm_path

    @abstractmethod
    def create(self):
        raise NotImplementedError()

    @property
    def zkvm_path(self) -> Path:
        return self.__zkvm_path

    @property
    def root(self) -> Path:
        return self.__root
