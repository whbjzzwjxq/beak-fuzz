import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from openvm_fuzzer.settings import OPENVM_BENCHMARK_REGZERO_COMMIT
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractProjectGenerator

# ---------------------------------------------------------------------------- #
#                            Openvm stark sdk helper                           #
# ---------------------------------------------------------------------------- #

__SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE: str | None = None


def _set_openvm_stark_sdk_from_openvm(value: str):
    """This function is used to set the singleton for testing purposes!"""
    global __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE
    __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE = value


def get_openvm_stark_sdk_from_openvm_workspace_cargo_toml(zkvm_path: Path) -> str:
    """Parses the Cargo.toml file of the openvm repository and extracts
    the openvm-stark-sdk dependency line. It is then saved into a singleton
    and never parsed again.

    NOTE: It expects the entry to be a one liner!
    """

    global __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE

    if __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE is None:
        cargo_toml = zkvm_path / "Cargo.toml"
        lines = cargo_toml.read_text().split("\n")
        for line in lines:
            if line.startswith("openvm-stark-sdk"):
                __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE = line
                break  # stop searching

    assert (
        __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE
    ), f"unable to find 'openvm-stark-sdk' entry in {zkvm_path}"

    return __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE


# ---------------------------------------------------------------------------- #
#                           Circuit project generator                          #
# ---------------------------------------------------------------------------- #


class CircuitProjectGenerator(AbstractProjectGenerator):
    commit_or_branch: str
    instructions_asm: list[str]
    initial_regs: dict[int, int]

    def __init__(
        self,
        root: Path,
        zkvm_path: Path,
        instructions_asm: list[str],
        initial_regs: dict[int, int],
        fault_injection: bool,
        commit_or_branch: str,
    ):
        super().__init__(root, zkvm_path)
        self.instructions_asm = instructions_asm
        self.initial_regs = initial_regs
        self._fault_injection = fault_injection
        self.commit_or_branch = commit_or_branch
        self.template_env = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    @property
    def is_fault_injection(self) -> bool:
        return self._fault_injection

    def render_template(self, template_name: str, **kwargs) -> str:
        template = self.template_env.get_template(template_name)
        return template.render(**kwargs)

    def create(self):
        self.create_root_cargo_toml()
        self.create_host_cargo_toml()
        self.create_host_main_rs()
        self.create_guest_cargo_toml()
        self.create_guest_main_rs()

    def create_root_cargo_toml(self):
        content = self.render_template("root_cargo.toml.j2")
        create_file(self.root / "Cargo.toml", content)

    def create_host_cargo_toml(self):
        zkvm_relpath = os.path.relpath(self.zkvm_path, self.root / "host")
        content = self.render_template(
            "host_cargo.toml.j2",
            zkvm_path=zkvm_relpath,
        )
        create_file(self.root / "host" / "Cargo.toml", content)

    def create_host_main_rs(self):
        # Initial regs info for host to push into stdin
        sanitized_regs = {k: (v & 0xFFFFFFFF) for k, v in self.initial_regs.items()}
        content = self.render_template(
            "host_main.rs.j2",
            is_fault_injection=self.is_fault_injection,
            initial_regs=sanitized_regs,
            use_generic_sdk=(self.commit_or_branch == OPENVM_BENCHMARK_REGZERO_COMMIT),
        )
        create_file(self.root / "host" / "src" / "main.rs", content)

    def create_guest_cargo_toml(self):
        zkvm_relpath = os.path.relpath(self.zkvm_path, self.root / "guest")
        content = self.render_template("guest_cargo.toml.j2", zkvm_path=zkvm_relpath)
        create_file(self.root / "guest" / "Cargo.toml", content)

    def create_guest_main_rs(self):
        content = self.render_template(
            "guest_main.rs.j2",
            instructions=self.instructions_asm,
            initial_regs=self.initial_regs,
            use_reveal_u32=(self.commit_or_branch == OPENVM_BENCHMARK_REGZERO_COMMIT),
        )
        create_file(self.root / "guest" / "src" / "main.rs", content)
