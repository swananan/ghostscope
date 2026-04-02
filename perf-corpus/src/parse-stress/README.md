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

Default scale:

- `PARSE_STRESS_UNITS=16`
- `PARSE_STRESS_TYPES_PER_UNIT=10`
- `PARSE_STRESS_FUNCTIONS_PER_UNIT=24`
- `PARSE_STRESS_HISTORY_LEN=8`
