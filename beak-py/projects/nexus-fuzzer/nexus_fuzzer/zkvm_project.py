from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from beak_core.rv32im import FuzzingInstance
from nexus_fuzzer.settings import get_riscv_target, get_rust_toolchain_version
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractProjectGenerator


class InstructionProjectGenerator(AbstractProjectGenerator):
    instance: FuzzingInstance
    commit_or_branch: str

    def __init__(self, root: Path, zkvm_path: Path, instance: FuzzingInstance, commit_or_branch: str):
        super().__init__(root, zkvm_path)
        self.instance = instance
        self.commit_or_branch = commit_or_branch
        self.template_env = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render_template(self, template_name: str, **kwargs) -> str:
        template = self.template_env.get_template(template_name)
        return template.render(**kwargs)

    def create(self):
        regs = dict(sorted(self.instance.initial_regs.items()))
        regs = {k: (v & 0xFFFFFFFF) for k, v in regs.items()}
        output_word_count = 2 * len(regs)
        riscv_target = get_riscv_target(self.commit_or_branch)

        create_file(self.root / "Cargo.toml", self.render_template("root_cargo.toml.j2"))
        create_file(
            self.root / "rust-toolchain.toml",
            self.render_template(
                "rust-toolchain.toml.j2",
                rust_toolchain_version=get_rust_toolchain_version(self.commit_or_branch),
            ),
        )
        create_file(
            self.root / "guest" / ".cargo" / "config.toml",
            self.render_template("guest_config.toml.j2", riscv_target=riscv_target),
        )
        create_file(
            self.root / "host" / "Cargo.toml",
            self.render_template("host_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(
            self.root / "host" / "src" / "main.rs",
            self.render_template(
                "host_main.rs.j2",
                initial_regs=regs,
                output_word_count=output_word_count,
            ),
        )
        create_file(
            self.root / "guest" / "Cargo.toml",
            self.render_template("guest_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(
            self.root / "guest" / "src" / "main.rs",
            self.render_template(
                "guest_main.rs.j2",
                initial_regs=regs,
                instructions=[inst.asm for inst in self.instance.instructions],
                output_word_count=output_word_count,
            ),
        )
