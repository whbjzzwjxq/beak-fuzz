# Jolt Read/Write-Memory Vulnerable Snapshot

This project wires Jolt commit `6c3b0b49db0afceb967b33656176fa7a27e557b9`
into the normal `beak-trace` / `beak-fuzz` entrypoints for prover-exception
evidence around the vulnerable read/write-memory witness sizing path.

The upstream Jolt source is installed through the standard Beak Python
installer into:

`beak-py/out/jolt-6c3b0b49db0afceb967b33656176fa7a27e557b9/jolt-src`

The snapshot also pins Binius beside that checkout at:

`beak-py/out/jolt-6c3b0b49db0afceb967b33656176fa7a27e557b9/binius-src`

No Beak source fix is applied to
`jolt-core/src/jolt/vm/read_write_memory.rs`, and this project intentionally
does not expose semantic injection mappings. The strict target is a non-injected
backend panic from the ordinary prover path.

Current semantic coverage is bucket-only:

- `sem.row.bytecode_table_boundary` for existing obligation `pd4`

Minimal smoke:

```bash
cargo run -q --bin beak-trace -- --bin "00700593 0040406f" --print-buckets
```
