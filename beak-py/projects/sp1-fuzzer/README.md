# sp1-fuzzer

Python-side installer package for SP1 integration in `beak-py`.

## Commands

- `sp1-fuzzer install`

The install command materializes an SP1 snapshot at:
`beak-py/out/sp1-<commit>/sp1-src`.

The default install root is repo-stable now. Prefer `make sp1-install` from `beak-fuzz/`, or run
the CLI from `beak-py/` when you need a direct install.
