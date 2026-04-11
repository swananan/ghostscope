# cpp-deep-namespace

`cpp-deep-namespace` is a generated C++ corpus for deep-namespace DWARF parse
baselines.

Design goals:

- produce long hierarchical symbol names without relying on template expansion
- stress fragment extraction and namespace splitting quality separately from
  template-heavy demangling
- keep generation deterministic so the same inputs reproduce the same corpus

The generated sources are not committed. Build them through:

```bash
./scripts/dwarf-perf/build_corpus.sh
```

The generator lives at:

- `scripts/dwarf-perf/generate_cpp_deep_namespace.py`

Preset scale:

- `medium`: `8` units, namespace depth `6`, `12` branches/unit,
  `16` functions/branch
- `large`: `16` units, namespace depth `8`, `16` branches/unit,
  `24` functions/branch
- `xlarge`: `20` units, namespace depth `10`, `18` branches/unit,
  `28` functions/branch

Default preset:

- `large`

The `large` preset targets roughly `10K-30K` mangled symbols.
