# parse-stress

`parse-stress` is the generated corpus for fast-parse / startup baselines.

Design goals:

- many translation units to exercise module loading and CU traversal
- many distinct types and helper functions per unit to expand `.debug_info`
- enough statements and loops to make `.debug_line` non-trivial
- deterministic source generation so the same inputs produce the same corpus

The generated sources are not committed. Build them through:

```bash
./scripts/dwarf-perf/build_corpus.sh
```

The generator lives at:

- `scripts/dwarf-perf/generate_parse_stress.py`

The generator now emits:

- `parse_stress_shared.h`
- `parse_stress_inline.h`
- `main.c`
- `unit_XX.h`
- `unit_XX.c`
- `generation_config.json`

Preset scale:

- `medium`: `16` units, `12` types/unit, `32` helper functions/unit, `8` history entries
- `large`: `48` units, `24` types/unit, `72` helper functions/unit, `16` history entries
- `xlarge`: `96` units, `40` types/unit, `128` helper functions/unit, `24` history entries

Default preset:

- `large`
