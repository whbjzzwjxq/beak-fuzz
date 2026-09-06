from openvm_fuzzer.passes.pass1_infrastructure import _render_fuzzer_utils_lib
from openvm_fuzzer.settings import (
    OPENVM_BENCHMARK_336F_COMMIT,
    OPENVM_BENCHMARK_BF11_COMMIT,
)


def test_frozen_336_uses_legacy_prime_field_constructor() -> None:
    rendered = _render_fuzzer_utils_lib(OPENVM_BENCHMARK_336F_COMMIT)

    assert "F::from_canonical_u32(internal_random_mod_of_u32(" in rendered
    assert "F::from_u32(internal_random_mod_of_u32(" not in rendered


def test_bf11_uses_current_prime_field_constructor() -> None:
    rendered = _render_fuzzer_utils_lib(OPENVM_BENCHMARK_BF11_COMMIT)

    assert "F::from_u32(internal_random_mod_of_u32(" in rendered
    assert "F::from_canonical_u32(internal_random_mod_of_u32(" not in rendered
