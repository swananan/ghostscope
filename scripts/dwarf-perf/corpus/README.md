# DWARF Perf Corpus

This directory holds reproducible programs used for DWARF parser performance baselines.

The corpus is intentionally separate from `e2e-tests/tests/fixtures`:

- correctness fixtures stay small and easy to reason about
- perf fixtures can grow in size and DWARF density without making routine e2e work slower

## Corpus Layout

- `src/query-hotspot/query_hotspot.c`
  - hand-written single-binary sample for single-address query baselines
  - contains a unique `DWARF_PERF_QUERY_HOTSPOT` source marker that the build step records in the manifest
- `src/parse-stress/`
  - documentation for the generated multi-translation-unit corpus
  - sources are emitted by `scripts/dwarf-perf/generate_parse_stress.py` during the build
- `src/rust-parse-stress/`
  - documentation for the generated Rust large-symbol corpus
  - sources are emitted by `scripts/dwarf-perf/generate_rust_parse_stress.py` during the build
- `src/cpp-template-stress/`
  - documentation for the generated C++ template-heavy corpus
  - sources are emitted by `scripts/dwarf-perf/generate_cpp_template_stress.py` during the build
- `src/rust-generic-stress/`
  - documentation for the generated Rust generic-heavy corpus
  - sources are emitted by `scripts/dwarf-perf/generate_rust_generic_stress.py` during the build
- `src/cpp-deep-namespace/`
  - documentation for the generated C++ deep-namespace corpus
  - sources are emitted by `scripts/dwarf-perf/generate_cpp_deep_namespace.py` during the build

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
- `rust-parse-stress/rust_parse_stress`
- `cpp-template-stress/cpp_template_stress`
- `rust-generic-stress/rust_generic_stress`
- `cpp-deep-namespace/cpp_deep_namespace`
- `manifest.json`

These generated outputs are ignored by Git through the repository
`/.gitignore`.

End-to-end baseline runner:

```bash
./scripts/dwarf-perf/run_baseline.sh
```

This will:

- build the corpus unless `--skip-build` is passed
- run the parse benchmark through `dwarf-tool benchmark` for every built-in fast-parse corpus by default
- run the query benchmark through `dwarf-tool benchmark-source-line`
- write a JSON result under `perf-results/`

To run only one parse corpus:

```bash
./scripts/dwarf-perf/run_baseline.sh --parse-target rust-parse-stress
```

Other built-in parse targets include:

- `parse-stress`
- `rust-parse-stress`
- `cpp-template-stress`
- `rust-generic-stress`
- `cpp-deep-namespace`

`perf-results/` is also ignored by Git and is intended for local or CI
benchmark result snapshots.

For long-term main-branch history, see
`.github/workflows/dwarf-perf-history.yml`. That workflow publishes the
baseline history site through GitHub Pages custom workflow deployment and
keeps the generated site state in the `dwarf-perf-history-data` branch.

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
- `RUST_PARSE_STRESS_PRESET`
- `RUST_PARSE_STRESS_MODULES`
- `RUST_PARSE_STRESS_TYPES_PER_MODULE`
- `RUST_PARSE_STRESS_FUNCTIONS_PER_MODULE`
- `CPP_TEMPLATE_STRESS_PRESET`
- `CPP_TEMPLATE_STRESS_UNITS`
- `CPP_TEMPLATE_STRESS_FAMILIES_PER_UNIT`
- `CPP_TEMPLATE_STRESS_INSTANTIATIONS_PER_FAMILY`
- `CPP_TEMPLATE_STRESS_METHODS_PER_FAMILY`
- `RUST_GENERIC_STRESS_PRESET`
- `RUST_GENERIC_STRESS_MODULES`
- `RUST_GENERIC_STRESS_FAMILIES_PER_MODULE`
- `RUST_GENERIC_STRESS_MONOMORPHS_PER_FAMILY`
- `CPP_DEEP_NAMESPACE_PRESET`
- `CPP_DEEP_NAMESPACE_UNITS`
- `CPP_DEEP_NAMESPACE_NAMESPACE_DEPTH`
- `CPP_DEEP_NAMESPACE_BRANCHES_PER_UNIT`
- `CPP_DEEP_NAMESPACE_FUNCTIONS_PER_BRANCH`

Preset defaults:

- `medium`: `16` units, `12` types/unit, `32` helper functions/unit, `8` history entries
- `large`: `48` units, `24` types/unit, `72` helper functions/unit, `16` history entries
- `xlarge`: `96` units, `40` types/unit, `128` helper functions/unit, `24` history entries

Rust large-symbol preset defaults:

- `medium`: `24` modules, `16` types/module, `48` worker functions/module
- `large`: `64` modules, `24` types/module, `96` worker functions/module
- `xlarge`: `96` modules, `32` types/module, `160` worker functions/module

C++ template preset defaults:

- `medium`: `8` units, `10` families/unit, `24` instantiations/family, `4` methods/family
- `large`: `16` units, `16` families/unit, `48` instantiations/family, `4` methods/family
- `xlarge`: `20` units, `18` families/unit, `56` instantiations/family, `4` methods/family

Rust generic preset defaults:

- `medium`: `8` modules, `10` families/module, `18` monomorphs/family
- `large`: `16` modules, `16` families/module, `28` monomorphs/family
- `xlarge`: `20` modules, `18` families/module, `34` monomorphs/family

C++ deep-namespace preset defaults:

- `medium`: `8` units, namespace depth `6`, `12` branches/unit, `16` functions/branch
- `large`: `16` units, namespace depth `8`, `16` branches/unit, `24` functions/branch
- `xlarge`: `20` units, namespace depth `10`, `18` branches/unit, `28` functions/branch

Current default:

- `PARSE_STRESS_PRESET=large`
- `RUST_PARSE_STRESS_PRESET=large`
- `CPP_TEMPLATE_STRESS_PRESET=large`
- `RUST_GENERIC_STRESS_PRESET=large`
- `CPP_DEEP_NAMESPACE_PRESET=large`

The generator now emits:

- a shared type header
- a shared inline-helper header
- one header and one source per unit
- cross-unit type references and callback edges
- a `generation_config.json` file consumed by the build manifest

The compiler and DWARF flavor are also configurable:

- `DWARF_PERF_CC`
- `DWARF_PERF_CXX`
- `DWARF_PERF_DWARF_VERSION`
- `DWARF_PERF_CFLAGS`
- `DWARF_PERF_CXXFLAGS`
- `DWARF_PERF_LDFLAGS`
- `DWARF_PERF_RUSTC`
- `DWARF_PERF_RUSTFLAGS`

Compiler default:

- `DWARF_PERF_CC=gcc`
- `DWARF_PERF_CXX=g++`
- `DWARF_PERF_RUSTC=rustc`

`gcc` is the default because the current `dwarf-tool` query flows resolve the `query-hotspot`
sample more reliably with GCC-generated DWARF than with Clang-generated DWARF.

The Rust parse corpus is intentionally tuned for DWARF density rather than runtime
performance. It keeps debug info in the binary, references a broad slice of `std`,
and compiles with `-C link-dead-code=yes` so it is useful for fast-index pressure
tests.

The new comparison groups focus on mangled-symbol coverage from three angles:

- `cpp-template-stress`: larger C++ template instantiation sets, roughly `50K-100K`
  mangled symbols on the default preset
- `rust-generic-stress`: Rust generic monomorphization, roughly `20K-50K`
  mangled symbols on the default preset
- `cpp-deep-namespace`: long hierarchical namespace names, roughly `10K-30K`
  mangled symbols on the default preset
