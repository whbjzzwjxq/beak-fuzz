# pico-fuzzer

Python-side installer package for Pico integration in `beak-py`.

## Commands

- `pico-fuzzer install`

The install command materializes a Pico snapshot at:
`beak-py/out/pico-<commit>/pico-src`.

The default install root is repo-stable now. Prefer `make pico-install` from `beak-fuzz/`, or run
the CLI from `beak-py/` when you need a direct install.
