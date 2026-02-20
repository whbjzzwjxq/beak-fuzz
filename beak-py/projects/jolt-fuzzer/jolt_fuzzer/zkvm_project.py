from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from beak_core.rv32im import FuzzingInstance
from jolt_fuzzer.settings import get_rust_toolchain_version
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractProjectGenerator


class InstructionProjectGenerator(AbstractProjectGenerator):
    instance: FuzzingInstance
    commit_or_branch: str
    cached_patch_crates_io: str | None

    def __init__(self, root: Path, zkvm_path: Path, instance: FuzzingInstance, commit_or_branch: str):
        super().__init__(root, zkvm_path)
        self.instance = instance
        self.commit_or_branch = commit_or_branch
        self.cached_patch_crates_io = None
        self.template_env = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    @property
    def patch_crates_io_section(self) -> str:
        if self.cached_patch_crates_io is None:
            cargo_toml = self.zkvm_path / "Cargo.toml"
            if not cargo_toml.is_file():
                # Unit tests pass a dummy path; patch section is only required for real checkouts.
                self.cached_patch_crates_io = ""
                return self.cached_patch_crates_io

            cargo_toml_lines = cargo_toml.read_text().split("\n")
            patch_section_lines: list[str] = []
            is_record = False
            for line in cargo_toml_lines:
                if line == "[patch.crates-io]":
                    is_record = True
                if line == "":
                    is_record = False
                if is_record:
                    patch_section_lines.append(line)
            self.cached_patch_crates_io = "\n".join(patch_section_lines)

        assert self.cached_patch_crates_io is not None
        return self.cached_patch_crates_io

    def render_template(self, template_name: str, **kwargs) -> str:
        template = self.template_env.get_template(template_name)
        return template.render(**kwargs)

    def create(self):
        regs = dict(sorted(self.instance.initial_regs.items()))
        regs = {k: (v & 0xFFFFFFFF) for k, v in regs.items()}
        output_word_count = 2 * len(regs)

        # Use the zkVM's lockfile when available to avoid dependency drift.
        lockfile = self.zkvm_path / "Cargo.lock"
        if lockfile.is_file():
            create_file(self.root / "Cargo.lock", lockfile.read_text())

        create_file(
            self.root / "Cargo.toml",
            self.render_template(
                "root_cargo.toml.j2",
                zkvm_path=self.zkvm_path,
                commit_or_branch=self.commit_or_branch,
                patch_crates_io_section=self.patch_crates_io_section,
            ),
        )
        create_file(
            self.root / "rust-toolchain.toml",
            self.render_template(
                "rust-toolchain.toml.j2",
                rust_toolchain_version=get_rust_toolchain_version(self.commit_or_branch),
            ),
        )
        create_file(
            self.root / "src" / "main.rs",
            self.render_template(
                "host_main.rs.j2",
                initial_regs=regs,
                output_word_count=output_word_count,
                commit_or_branch=self.commit_or_branch,
            ),
        )

        create_file(
            self.root / "guest" / "Cargo.toml",
            self.render_template("guest_cargo.toml.j2", zkvm_path=self.zkvm_path),
        )
        create_file(self.root / "guest" / "src" / "main.rs", self.render_template("guest_main.rs.j2"))
        create_file(
            self.root / "guest" / "src" / "lib.rs",
            self.render_template(
                "guest_lib.rs.j2",
                initial_regs=regs,
                instructions=[inst.asm for inst in self.instance.instructions],
                output_word_count=output_word_count,
            ),
        )
