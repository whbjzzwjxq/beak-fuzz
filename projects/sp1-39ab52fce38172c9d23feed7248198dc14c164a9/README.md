# SP1 39ab52fc Audit Repro

This snapshot targets the last known vulnerable commit for the SP1 v4 audit finding
`[High] is_memory underconstrained`.

Relevant commits:

- vulnerable: `39ab52fce38172c9d23feed7248198dc14c164a9`
- fix: `185d266233e09a15bc3d5d077d36b714d5d55084`

This project depends on the locally installed SP1 checkout under:

- `beak-py/out/sp1-39ab52fce38172c9d23feed7248198dc14c164a9/sp1-src`

## Install

```bash
cd path/to/beak
make sp1-install SP1_COMMIT=39ab52fce38172c9d23feed7248198dc14c164a9
```

## Build

```bash
cd path/to/beak
make sp1-build SP1_COMMIT=39ab52fce38172c9d23feed7248198dc14c164a9
```

## Trace

```bash
cd path/to/beak/projects/sp1-39ab52fce38172c9d23feed7248198dc14c164a9
cargo run --release --bin beak-trace -- --bin "00012183" --print-buckets
```

## Benchmark

```bash
cd path/to/beak
make sp1-fuzz SP1_COMMIT=39ab52fce38172c9d23feed7248198dc14c164a9
```

The semantic injection kind for the real audit issue is:

- `sp1.audit_v4.is_memory_instruction_interaction`
