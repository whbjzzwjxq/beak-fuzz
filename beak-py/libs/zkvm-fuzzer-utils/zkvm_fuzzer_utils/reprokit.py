import logging
import os
import shutil
import stat
import uuid
from pathlib import Path

from zkvm_fuzzer_utils.cmd import ExecStatus

logger = logging.getLogger("fuzzer")

# ---------------------------------------------------------------------------- #
#                              Reproducibility Kit                             #
# ---------------------------------------------------------------------------- #


def prepare_reproducibility_kit(
    project_dir: Path, execution: ExecStatus, error_info: str | None = None
):
    root_dir = project_dir.parent.absolute()
    finding_dir = root_dir / "findings"
    if not finding_dir.is_dir():
        try:
            os.makedirs(finding_dir, exist_ok=True)
        except Exception as e:
            # NOTE: In theory this should not happen, but if something goes
            #       wrong we should try to continue. If the folder is not
            #       created the copy part will fail anyways.
            logger.error(e)
    # NOTE: uuid4 should be unique enough to avoid clashes
    target_dir = finding_dir / str(uuid.uuid4())
    shutil.copytree(project_dir, target_dir)  # dump the whole folder
    run_script = target_dir / "run.sh"
    with open(run_script, "w") as fp:
        fp.write("#!/usr/bin/env bash\n\n")

        fp.write(f"{execution.command} > output.txt\n\n")

        # NOTE: if we reproduce a fault injection we also need the normal run and a diff from it
        fp.write(
            f"# {execution.command} > output.no_inj.txt\n\n"
            "# diff -y2 output.no_inj.txt output.txt > diff.txt\n"
        )
    run_script.chmod(run_script.stat().st_mode | stat.S_IEXEC)  # make executable

    if error_info is not None:
        info_txt = target_dir / "error_info.txt"
        with open(info_txt, "w") as fp:
            fp.write(error_info)

    logger.info(f"Faulty instance saved at {target_dir}")


# ---------------------------------------------------------------------------- #
