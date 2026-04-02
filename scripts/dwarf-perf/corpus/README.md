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

By default the build uses the image pinned in
`scripts/dwarf-perf/builder_image_ref.txt`, produced by the DWARF perf image workflow:

```bash
./scripts/dwarf-perf/build_corpus.sh
```

Current locked image:

```text
ghcr.io/swananan/ghostscope-dwarf-perf-builder@sha256:ed99b20a96a4fb2abc4845ca55e7e3780e97752d3281da441b8aa335b56b9ecb
```

To override the pinned image temporarily:

```bash
DWARF_PERF_BUILDER_IMAGE=ghcr.io/swananan/ghostscope-dwarf-perf-builder:ubuntu24.04-llvm18-rust1.88 \
  ./scripts/dwarf-perf/build_corpus.sh
```

The build writes artifacts under `scripts/dwarf-perf/corpus/out/`:

- `query-hotspot/query_hotspot`
- `parse-stress/parse_stress`
- `manifest.json`

End-to-end baseline runner:

```bash
./scripts/dwarf-perf/run_baseline.sh
```

This will:

- build the corpus unless `--skip-build` is passed
- run the parse benchmark through `dwarf-tool benchmark`
- run the query benchmark through `dwarf-tool benchmark-source-line`
- write a JSON result under `perf-results/`

The script prints three separate sections:

- `Fast parse benchmark`
- `Source-line query benchmark`
- `Query result snapshot`

`Fast parse benchmark` is the analyzer load path, which reflects the initial
DWARF fast-parse and index-build cost. It reports `average_ms`, `p50_ms`,
`p95_ms`, `min_ms`, and `max_ms`.

The source-line benchmark keeps one analyzer instance warm, repeats the same
query multiple times, and records `first_run_ms`, `average_ms`, `p50_ms`,
`p95_ms`, `min_ms`, and `max_ms`. Its latency covers the full source-line
query path: source-line lookup, matched address resolution, and variable
collection for those addresses.

## Tuning

The generated parse corpus is deterministic and can be scaled without editing sources:

- `PARSE_STRESS_PRESET`
- `PARSE_STRESS_UNITS`
- `PARSE_STRESS_TYPES_PER_UNIT`
- `PARSE_STRESS_FUNCTIONS_PER_UNIT`
- `PARSE_STRESS_HISTORY_LEN`

Preset defaults:

- `medium`: `16` units, `12` types/unit, `32` helper functions/unit, `8` history entries
- `large`: `48` units, `24` types/unit, `72` helper functions/unit, `16` history entries
- `xlarge`: `96` units, `40` types/unit, `128` helper functions/unit, `24` history entries

Current default:

- `PARSE_STRESS_PRESET=large`

The generator now emits:

- a shared type header
- a shared inline-helper header
- one header and one source per unit
- cross-unit type references and callback edges
- a `generation_config.json` file consumed by the build manifest

The compiler and DWARF flavor are also configurable:

- `DWARF_PERF_CC`
- `DWARF_PERF_DWARF_VERSION`
- `DWARF_PERF_CFLAGS`
- `DWARF_PERF_LDFLAGS`

Compiler default:

- `DWARF_PERF_CC=gcc`

`gcc` is the default because the current `dwarf-tool` query flows resolve the `query-hotspot`
sample more reliably with GCC-generated DWARF than with Clang-generated DWARF.
