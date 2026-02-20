from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from beak_core.rv32im import FuzzingInstance
from sp1_fuzzer.settings import RUST_TOOLCHAIN_VERSION
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
            self.root / "host" / "Cargo.toml",
            self.render_template("host_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )

        host_main = self.render_template(
            "host_main.rs.j2",
            initial_regs=regs,
            output_word_count=output_word_count,
        )

        # SP1 SDK API compatibility:
        # - older snapshots use `ProverClient::new()` and `prove(&pk, stdin)`.
        sdk_has_client_rs = (self.zkvm_path / "crates" / "sdk" / "src" / "client.rs").is_file()
        if not sdk_has_client_rs:
            host_main = host_main.replace(
                "let client = ProverClient::builder().cpu().build();",
                "let client = ProverClient::new();",
            )
            host_main = host_main.replace("        .prove(&pk, &stdin)", "        .prove(&pk, stdin)")
            host_main = host_main.replace("        .deferred_proof_verification(false)\n", "")

        create_file(self.root / "host" / "src" / "main.rs", host_main)

        create_file(
            self.root / "guest" / "Cargo.toml",
            self.render_template("guest_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(
            self.root / "guest" / "src" / "main.rs",
            self.render_template(
                "guest_main.rs.j2",
                instructions=[inst.asm for inst in self.instance.instructions],
                initial_regs=regs,
            ),
        )
