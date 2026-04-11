# cpp-template-stress

`cpp-template-stress` is a generated C++ corpus for template-heavy DWARF parse
baselines.

Design goals:

- produce large batches of explicit template instantiations with nested type
  arguments and non-type template parameters
- keep mangled names dense enough to make demangling and symbol-map assembly
  visible in startup profiles
- keep generation deterministic so the same inputs reproduce the same corpus

The generated sources are not committed. Build them through:

```bash
./scripts/dwarf-perf/build_corpus.sh
```

The generator lives at:

- `scripts/dwarf-perf/generate_cpp_template_stress.py`

Preset scale:

- `medium`: `8` units, `10` families/unit, `24` instantiations/family,
  `4` methods/family
- `large`: `16` units, `16` families/unit, `48` instantiations/family,
  `4` methods/family
- `xlarge`: `20` units, `18` families/unit, `56` instantiations/family,
  `4` methods/family

Default preset:

- `large`

The `large` preset targets roughly `50K-100K` mangled symbols.
