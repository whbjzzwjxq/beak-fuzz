import argparse
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from zkvm_fuzzer_utils.file import create_dir


class FuzzerClient(ABC):
    """Base class for a zkvm fuzzer client. This class handles the basic log
    file management and argument parsing.
    """

    backend_name: str
    logger_prefix: str
    allowed_commits_and_branches: list[str]

    verbosity: int
    seed: float
    log_filename: Path | None
    out_dir: Path | None
    zkvm_dir: Path | None
    findings_csv: Path | None
    fault_injection: bool
    trace_collection: bool
    zkvm_modification: bool
    commit_or_branch: str
    timeout: int | None
    only_modify_word: bool
    no_inline_assembly: bool
    no_schedular: bool

    argument_parser: argparse.ArgumentParser
    args: argparse.Namespace

    def __init__(
        self, backend_name: str, logger_prefix: str, allowed_commits_and_branches: list[str]
    ):
        if len(allowed_commits_and_branches) == 0:
            raise ValueError("Fuzzer client needs at least 1 commit or branch!")

        self.backend_name = backend_name
        self.logger_prefix = logger_prefix
        self.allowed_commits_and_branches = allowed_commits_and_branches
        self.commit_or_branch = self.allowed_commits_and_branches[0]

        self.verbosity = 0
        self.seed = 0
        self.log_filename = None
        self.out_dir = None
        self.zkvm_dir = None
        self.findings_csv = None
        self.fault_injection = False
        self.trace_collection = False
        self.zkvm_modification = False
        self.timeout = None
        self.only_modify_word = False
        self.no_inline_assembly = False
        self.no_schedular = False
        self.argument_parser = self.generate_parser()
        self.args = argparse.Namespace()  # default empty namespace

    def extract_log_filename(self) -> Path | None:
        log_filename = None
        if self.args.log_file:
            log_filename = Path(self.args.log_file)
            if log_filename.is_dir():
                self.argument_parser.error("--log-file requires to be a file, found directory!")
            if not log_filename.parent.is_dir():
                create_dir(log_filename.parent)
            if log_filename.is_file():
                log_filename.unlink()
        return log_filename

    def extract_out_dir(self) -> Path:
        out_dir = Path(self.args.out).absolute()
        if out_dir.is_file():
            self.argument_parser.error("--out requires to be a directory, found a file!")
        create_dir(out_dir)
        return out_dir

    def extract_zkvm_dir(self) -> Path:
        if self.args.zkvm:
            zkvm_dir = Path(self.args.zkvm).absolute()
            if zkvm_dir.is_file():
                self.argument_parser.error("--zkvm requires to be a directory, found a file!")
            if not zkvm_dir.is_dir():
                create_dir(zkvm_dir)
            return zkvm_dir
        self.argument_parser.error(
            f"{self.backend_name} fuzzer requires path to zkvm git repository ('--zkvm')!"
        )

    def extract_findings_csv(self) -> Path:
        if self.args.csv_file:
            csv_file = Path(self.args.csv_file).absolute()
            if not csv_file.is_file() or not csv_file.suffix == ".csv":
                self.argument_parser.error(f"provided path {csv_file} is not a csv file")
            return csv_file
        self.argument_parser.error("required csv file was not provided!")

    def set_logger_config(self):
        logger = logging.getLogger("fuzzer")
        logger.propagate = False

        verbosity = min(max(0, self.verbosity), 2)
        logging_level = {0: logging.ERROR, 1: logging.INFO, 2: logging.DEBUG}.get(
            verbosity, logging.ERROR
        )
        logger.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            f"[{self.logger_prefix} %(asctime)s ~ %(levelname)s]: %(message)s"
        )
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging_level)
        logger.addHandler(console_handler)

        if self.log_filename:

            log_file_max_byte_size = 1024 * 1024 * 15  # 15MB
            log_file_backups = 1
            base_log_file = self.log_filename.absolute().as_posix()
            file_handler = RotatingFileHandler(
                base_log_file, maxBytes=log_file_max_byte_size, backupCount=log_file_backups
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            logger.addHandler(file_handler)

    def add_shared_parser_flags_logging(self, subparser: argparse.ArgumentParser):
        subparser.add_argument("-l", "--log-file", metavar="FILE_PATH", type=str)
        subparser.add_argument("-v", "--verbosity", default=1, choices=[0, 1, 2], type=int)
        subparser.add_argument(
            "--commit-or-branch",
            type=str,
            choices=self.allowed_commits_and_branches,
            default=self.commit_or_branch,
            help=("Specific zkvm commit or branch to use."),
        )

    def add_shared_parser_flags_runtime(self, subparser: argparse.ArgumentParser):
        subparser.add_argument(
            "--fault-injection",
            action="store_true",
            help="enables fault injection (requires installation with --zkvm-modification)",
        )
        subparser.add_argument(
            "--trace-collection",
            action="store_true",
            help=(
                "enables trace collection, is automatically enabled if --fault-injection"
                "is set (requires installation with --zkvm-modification)"
            ),
        )
        subparser.add_argument(
            "--only-modify-word",
            action="store_true",
            help=("only uses instruction word modification if fault injection is enabled"),
        )
        subparser.add_argument(
            "--no-inline-assembly",
            action="store_true",
            help=("disables inline assembly for rust generation"),
        )
        subparser.add_argument(
            "-o",
            "--out",
            metavar="OUTPUT_DIR",
            type=str,
            default=f"out/{self.backend_name.lower()}",
            help="output directory for the generated artifacts",
        )
        subparser.add_argument(
            "-z", "--zkvm", metavar="ZKVM_DIR", type=str, help="path to the zkvm repository"
        )

    def generate_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog=f"{self.backend_name} Fuzzer",
            description=f"{self.backend_name} zkVM Fuzzer using a combination of \
                        metamorphic testing and fault injection techniques",
        )

        subparsers = parser.add_subparsers(required=True, dest="command")

        # --------------------------------- installer -------------------------------- #

        install_subparser = subparsers.add_parser(
            "install", description=f"installer for the {self.backend_name} zkVM"
        )
        install_subparser.add_argument(
            "zkvm",
            metavar="ZKVM_INSTALL_PATH",
            help=f"target destination for the {self.backend_name} zkVM installation",
        )
        install_subparser.add_argument(
            "--zkvm-modification",
            action="store_true",
            help=(
                "Extends the zkVM sources with trace collection and fault injection code segments."
            ),
        )
        self.add_shared_parser_flags_logging(install_subparser)

        # ---------------------------------- runner ---------------------------------- #

        fuzzer_subparser = subparsers.add_parser("run", description="starts the fuzzer")
        fuzzer_subparser.add_argument(
            "-s", "--seed", metavar="SEED_NUM", type=float, help="seed that is used for fuzzing"
        )
        fuzzer_subparser.add_argument(
            "--timeout",
            metavar="TIMEOUT",
            type=int,
            help="Stops the fuzzer after the timeout is reached",
        )
        fuzzer_subparser.add_argument(
            "--no-schedular",
            action="store_true",
            help="disables instruction schedular for injections and picks instructions at random",
        )
        self.add_shared_parser_flags_logging(fuzzer_subparser)
        self.add_shared_parser_flags_runtime(fuzzer_subparser)

        # ---------------------------------- checker --------------------------------- #

        check_subparser = subparsers.add_parser(
            "check", help="check refound instances from CSV file"
        )
        check_subparser.add_argument("csv_file", help="Path to the CSV Bug Finding file")
        self.add_shared_parser_flags_logging(check_subparser)
        self.add_shared_parser_flags_runtime(check_subparser)

        # --------------------------------- generator -------------------------------- #

        generate_subparser = subparsers.add_parser(
            "generate", help="generates a project with the provided seed"
        )
        generate_subparser.add_argument(
            "-s",
            "--seed",
            metavar="SEED_NUM",
            type=float,
            help="project generation seed",
        )
        self.add_shared_parser_flags_logging(generate_subparser)
        self.add_shared_parser_flags_runtime(generate_subparser)

        return parser

    def start(self):
        # command line argument parsing
        self.args = self.argument_parser.parse_args()

        # logger properties
        self.verbosity = self.args.verbosity
        self.log_filename = self.extract_log_filename()
        self.set_logger_config()

        # install and run both store it to "zkvm"
        self.zkvm_dir = self.extract_zkvm_dir()

        # get the desired commit
        self.commit_or_branch = self.args.commit_or_branch

        # run and check specifics
        if self.args.command in ["run", "check", "generate"]:
            # output dir
            self.out_dir = self.extract_out_dir()

            # check if any modifications are enabled
            self.trace_collection = self.args.trace_collection
            self.fault_injection = self.args.fault_injection

            # only use instruction word mod
            self.only_modify_word = self.args.only_modify_word

            # do not use inline assembly
            self.no_inline_assembly = self.args.no_inline_assembly

        # execute client behavior
        match self.args.command:
            case "install":
                # check if zkvm modifications are allowed
                self.zkvm_modification = self.args.zkvm_modification
                self.install()
            case "run":
                self.seed = (
                    self.args.seed if self.args.seed is not None else datetime.now().timestamp()
                )
                self.timeout = self.args.timeout
                self.no_schedular = self.args.no_schedular
                self.run()
            case "check":
                self.findings_csv = self.extract_findings_csv()
                self.check()
            case "generate":
                self.seed = (
                    self.args.seed if self.args.seed is not None else datetime.now().timestamp()
                )
                self.generate()
            case _:
                raise NotImplementedError(
                    f"Unknown subcommand {self.args.command} for {self.backend_name}"
                )

    @property
    def is_fault_injection(self) -> bool:
        return self.fault_injection

    @property
    def is_trace_collection(self) -> bool:
        return self.trace_collection or self.fault_injection

    @property
    def is_zkvm_modification(self) -> bool:
        return not self.zkvm_modification

    @property
    def is_only_modify_word(self) -> bool:
        return self.only_modify_word

    @property
    def is_no_inline_assembly(self) -> bool:
        return self.no_inline_assembly

    @property
    def is_no_schedular(self) -> bool:
        return self.no_schedular

    @abstractmethod
    def install(self):
        raise NotImplementedError()

    @abstractmethod
    def run(self):
        raise NotImplementedError()

    @abstractmethod
    def check(self):
        raise NotImplementedError()

    @abstractmethod
    def generate(self):
        raise NotImplementedError()
