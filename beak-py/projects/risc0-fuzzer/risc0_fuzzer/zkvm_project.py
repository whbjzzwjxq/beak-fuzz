from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from beak_core.rv32im import FuzzingInstance
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
            self.root / "methods" / "Cargo.toml",
            self.render_template("methods_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(self.root / "methods" / "build.rs", self.render_template("methods_build.rs.j2"))
        create_file(self.root / "methods" / "src" / "lib.rs", self.render_template("methods_lib.rs.j2"))

        create_file(
            self.root / "host" / "Cargo.toml",
            self.render_template("host_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(
            self.root / "host" / "src" / "main.rs",
            self.render_template("host_main.rs.j2", initial_regs=regs, output_word_count=output_word_count),
        )

        create_file(
            self.root / "methods" / "guest" / "Cargo.toml",
            self.render_template("guest_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(
            self.root / "methods" / "guest" / "src" / "main.rs",
            self.render_template(
                "guest_main.rs.j2",
                instructions=[inst.asm for inst in self.instance.instructions],
                initial_regs=regs,
                output_word_count=output_word_count,
            ),
        )
