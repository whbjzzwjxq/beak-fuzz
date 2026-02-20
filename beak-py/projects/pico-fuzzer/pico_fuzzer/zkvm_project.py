from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from beak_core.rv32im import FuzzingInstance
from pico_fuzzer.settings import RUST_TOOLCHAIN_VERSION
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractProjectGenerator


class InstructionProjectGenerator(AbstractProjectGenerator):
    instance: FuzzingInstance

    def __init__(self, root: Path, zkvm_path: Path, instance: FuzzingInstance):
        super().__init__(root, zkvm_path)
        self.instance = instance
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

        create_file(self.root / "Cargo.toml", self.render_template("root_cargo.toml.j2"))
        create_file(
            self.root / "rust-toolchain.toml",
            self.render_template("rust-toolchain.toml.j2", rust_toolchain_version=RUST_TOOLCHAIN_VERSION),
        )

        create_file(
            self.root / "app" / "Cargo.toml",
            self.render_template("app_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(
            self.root / "app" / "src" / "main.rs",
            self.render_template(
                "app_main.rs.j2",
                instructions=[inst.asm for inst in self.instance.instructions],
                initial_regs=regs,
            ),
        )

        create_file(
            self.root / "prover" / "Cargo.toml",
            self.render_template("prover_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(
            self.root / "prover" / "src" / "main.rs",
            self.render_template(
                "prover_main.rs.j2",
                initial_regs=regs,
                output_word_count=output_word_count,
            ),
        )
