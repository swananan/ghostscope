# rust-generic-stress

`rust-generic-stress` is a generated Rust corpus for generic-heavy DWARF parse
baselines.

Design goals:

- force broad generic monomorphization across many module-local type families
- keep symbol names stable and dense enough to expose demangle and index-build
  costs in the startup path
- keep generation deterministic so the same inputs reproduce the same crate

The generated sources are not committed. Build them through:

```bash
./scripts/dwarf-perf/build_corpus.sh
```

The generator lives at:

- `scripts/dwarf-perf/generate_rust_generic_stress.py`

The build compiles the generated crate with:

- `-C debuginfo=2`
- `-C opt-level=0`
- `-C force-frame-pointers=yes`
- `-C link-dead-code=yes`

Preset scale:

- `medium`: `8` modules, `10` families/module, `18` monomorphs/family
- `large`: `16` modules, `16` families/module, `28` monomorphs/family
- `xlarge`: `20` modules, `18` families/module, `34` monomorphs/family

Default preset:

- `large`

The `large` preset targets roughly `20K-50K` mangled symbols.
