# Beak Fuzzer for SP1

This package provides a minimal SP1 backend that runs a loop-1 style check:
generate a RISC-V instruction sequence, execute it in SP1, and compare committed
register outputs against the Unicorn oracle.

