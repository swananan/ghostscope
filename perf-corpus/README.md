# DWARF Perf Corpus

This directory holds reproducible programs used for DWARF parser performance baselines.

The corpus is intentionally separate from `ghostscope/tests/fixtures`:

- correctness fixtures stay small and easy to reason about
- perf fixtures can grow in size and DWARF density without making routine e2e work slower

## Corpus Layout

- `src/query-hotspot/query_hotspot.c`
  - hand-written single-binary sample for single-address query baselines
  - contains a unique `DWARF_PERF_QUERY_HOTSPOT` source marker that the build step records in the manifest
- `src/parse-stress/`
  - documentation for the generated multi-translation-unit corpus
  - sources are emitted by `scripts/dwarf-perf/generate_parse_stress.py` during the build

## Build Flow

Use the dedicated builder image created by the DWARF perf image workflow:

```bash
DWARF_PERF_BUILDER_IMAGE=ghcr.io/swananan/ghostscope-dwarf-perf-builder:ubuntu24.04-llvm18-rust1.88 \
  ./scripts/dwarf-perf/build_corpus.sh
```

The build writes artifacts under `perf-corpus/out/`:

- `query-hotspot/query_hotspot`
- `parse-stress/parse_stress`
- `manifest.json`

## Tuning

The generated parse corpus is deterministic and can be scaled without editing sources:

- `PARSE_STRESS_UNITS`
- `PARSE_STRESS_TYPES_PER_UNIT`
- `PARSE_STRESS_FUNCTIONS_PER_UNIT`
- `PARSE_STRESS_HISTORY_LEN`

The compiler and DWARF flavor are also configurable:

- `DWARF_PERF_CC`
- `DWARF_PERF_DWARF_VERSION`
- `DWARF_PERF_CFLAGS`
- `DWARF_PERF_LDFLAGS`

Current default:

- `DWARF_PERF_CC=gcc`

`gcc` is the default because the current `dwarf-tool` query flows resolve the `query-hotspot`
sample more reliably with GCC-generated DWARF than with Clang-generated DWARF.
