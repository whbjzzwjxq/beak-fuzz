from openvm_fuzzer.patches.injection_sources.ca36de3 import (
    auipc_core_rs_ca36de3,
    base_alu_core_rs_ca36de3,
    divrem_core_rs_ca36de3,
    load_sign_extend_core_rs_ca36de3,
    loadstore_core_rs_ca36de3,
    segment_rs_ca36de3,
)


def openvm_extensions_rv32im_circuit_src_auipc_core_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return auipc_core_rs_ca36de3()
        case "ca36de3803213da664b03d111801ab903d55e360":
            return auipc_core_rs_ca36de3()
        case _:
            raise NotImplementedError(f"unknown commit {commit_or_branch}")


def openvm_extensions_rv32im_circuit_src_base_alu_core_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return base_alu_core_rs_ca36de3()
        case "ca36de3803213da664b03d111801ab903d55e360":
            return base_alu_core_rs_ca36de3()
        case _:
            raise NotImplementedError(f"unknown commit {commit_or_branch}")


def openvm_extensions_rv32im_circuit_src_divrem_core_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return divrem_core_rs_ca36de3()
        case "ca36de3803213da664b03d111801ab903d55e360":
            return divrem_core_rs_ca36de3()
        case _:
            raise NotImplementedError(f"unknown commit {commit_or_branch}")


def openvm_extensions_rv32im_circuit_src_load_sign_extend_core_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return load_sign_extend_core_rs_ca36de3()
        case "ca36de3803213da664b03d111801ab903d55e360":
            return load_sign_extend_core_rs_ca36de3()
        case _:
            raise NotImplementedError(f"unknown commit {commit_or_branch}")


def openvm_extensions_rv32im_circuit_src_loadstore_core_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return loadstore_core_rs_ca36de3()
        case "ca36de3803213da664b03d111801ab903d55e360":
            return loadstore_core_rs_ca36de3()
        case _:
            raise NotImplementedError(f"unknown commit {commit_or_branch}")


def openvm_crates_vm_src_arch_segment_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return segment_rs_ca36de3()
        case "ca36de3803213da664b03d111801ab903d55e360":
            return segment_rs_ca36de3()
        case _:
            raise NotImplementedError(f"unknown commit {commit_or_branch}")
