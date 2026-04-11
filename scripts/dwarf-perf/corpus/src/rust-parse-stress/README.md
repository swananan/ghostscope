# rust-parse-stress

`rust-parse-stress` is a generated Rust corpus for large-symbol DWARF parse
baselines.

Design goals:

- produce a much denser symbol table than the C `parse-stress` corpus
- force a broad slice of `std` into the binary
- keep source generation deterministic so the same inputs produce the same
  Rust crate

The generated sources are not committed. Build them through:

```bash
./scripts/dwarf-perf/build_corpus.sh
```

The generator lives at:

- `scripts/dwarf-perf/generate_rust_parse_stress.py`

The build compiles the generated crate with:

- `-C debuginfo=2`
- `-C opt-level=0`
- `-C force-frame-pointers=yes`
- `-C link-dead-code=yes`

That combination intentionally favors large, symbol-rich DWARF over runtime
performance.

Preset scale:

- `medium`: `24` modules, `16` types/module, `48` worker functions/module
- `large`: `64` modules, `24` types/module, `96` worker functions/module
- `xlarge`: `96` modules, `32` types/module, `160` worker functions/module

Default preset:

- `large`
