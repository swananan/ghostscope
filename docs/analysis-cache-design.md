# Prepared DWARF analysis cache

## Scope and baseline

This redesign of PR #247 is based on main `2c9d6204`. Main already reads source
headers at startup, evaluates line rows per compilation unit on demand, and
prefers native DWARF accelerators. Persisting eagerly evaluated line tables would
undo that work and introduce a second implementation of interval lookup.

The prepared cache is a CU-selection accelerator, sharing the existing native
accelerator query path. It stores exact full-scan name-to-CU mappings (including
aliases), PC-to-CU ranges, and source-file header metadata. CU identity is a
DWARF offset, never its display name. Overlapping ranges remain valid. Repeated
names and paths use a shared string table; header strings are shared in memory,
and headers are restored in parallel.

A hit starts with no concrete symbol entries or line rows. Symbol queries
materialize the selected CUs from original DWARF, preserving lexical ownership,
cross-CU references and supplementary imports. Startup statistics and symbol
name enumeration use the complete prepared directory without materializing all
CUs. Ambiguous or uncovered queries retain the existing exhaustive fallback;
workloads that eventually visit every CU can therefore still pay scan costs.

Detailed DIE/type evaluation, lazy line rows, module identity/ASLR, PID namespaces,
CFI, and eBPF remain runtime work. Source rows use the existing line lookup
implementation. Runtime backtrace-only modules retain their bounded CFI/symbol
loader. The cache is not a serialized runtime object graph.

## Selection and user interface

1. Resolve and validate the ELF, primary debug object and supplementary object.
2. Consult the prepared cache using all three identities plus the schema and
   package version. Only full-scan preparation can write an entry: a valid hit
   implies that no usable native accelerator existed for these exact objects.
   Changing an object invalidates the entry. This invariant allows hits to skip
   native-index discovery and source-header parsing.
3. A miss or rejected entry uses normal native-index selection: usable
   `.debug_names`, `.gdb_index`, or GNU pubnames, then the full-scan fallback.
4. Runtime never creates or repairs payloads. CLI/TUI report hits, misses and
   rejection reasons separately from native-index fallback.
5. `ghostscope --prepare -t TARGET` runs without eBPF privileges and writes the
   full-scan directories, or reports that a native index needs no cache. A valid
   entry is reused. A rejected entry is rebuilt atomically.

`--analysis-cache-dir` selects a shared location explicitly when preparation and
tracing use different accounts. `--no-analysis-cache` provides the raw baseline.
The analysis `--prepare` flag is separate from the script-specific
`ghostscope prepare` trace-bundle subcommand.

## Format and failure behavior

Schema v5 uses a fixed 24-byte prefix (magic, schema, header length, payload
length), a bounded header, and a postcard payload. The header binds the GhostScope
package version, payload CRC32, and identities of the ELF, debug object, and
optional supplementary object. File identity includes build ID, length, device,
inode, ctime and mtime; metadata comes from the descriptor used for mapping.
Replacing a pathname cannot pair an old mapping with new inode metadata.
Copying an object can produce a conservative cache miss even with the same build
ID. Schema v5 replaces the unmaintained bincode codec; v4 entries must be
prepared again. Schema changes must accompany incompatible index semantics within a release.

Readers reject non-regular files, final-component symlinks, oversized/truncated
entries, incompatible versions, identity mismatch and checksum mismatch. They
read an owned snapshot before decoding, so later truncation cannot cause SIGBUS.
Decoding is byte-bounded; restored string/CU references, file indices and CU
ranges are validated.
CRC32 detects accidental corruption, not malicious authenticated content; cache
directories should be writable only by trusted users.

Writers create private directories and exclusive 0600 temporary files, flush and
sync the complete entry, then rename it into place. Publication never exposes a
partially written payload. Preparation reports write errors; runtime reads do
not turn unusable cache data into a module load failure. Old schema directories
are ignored by readers and count toward the prepare budget. Cross-machine cache
distribution is outside this change.

## Capacity and eviction

`[dwarf.analysis_cache].max_size_mb` sets a positive total managed-file budget,
defaulting to 1024 MiB. The library exposes `AnalysisCache::with_max_size_bytes`.
The format's 512 MiB payload bound remains independent of this disk budget.
Changing policy does not invalidate existing v5 entries.

Recency uses the cache file's modification timestamp, updated through its opened
file descriptor only after successful decoding and validation. A 60-second
coalescing interval avoids metadata writes on every hit. This is approximate LRU;
access order within that interval is intentionally not exact. Concurrent readers
may duplicate a timestamp update; recency never requires a reader lock. It does not depend
on filesystem atime/relatime settings. Read-only mounts and shared entries whose
timestamps cannot be changed still load successfully. Cache payloads remain
immutable during tracing, and runtime readers never scan directories or acquire
the maintenance lock.

Prepare holds an exclusive root `.lock` file from pruning through temporary-file
creation, flush and rename. A cache hit in prepare also takes this lock and
applies a lowered budget while protecting the reused entry. Serialization happens
before acquiring the publication lock. Oversized incoming entries are rejected
before eviction. Before opening a temporary output, prepare reserves its full
encoded size and evicts to the remaining budget. Thus cooperating writers cannot
independently consume the same free space; temporary output also fits within the
budget. A failed write can leave fewer cached entries, but cannot expose a partial
published payload. Already-open readers and decoded snapshots survive unlink.

Maintenance recognizes only canonical `vN` directories up to the current schema,
16-digit lowercase hexadecimal `.bin` names, and the writer's exact temporary
filename pattern. It never follows directory/file symlinks or removes unknown
files and future-format directories. Obsolete schema entries are first in the
eviction order, followed by modification time and a stable path tie-breaker.
Current-format abandoned temporaries can be removed under the writer lock;
legacy temporaries are removed only after 24 hours, with younger files counted
against the budget. Lock files, directory/filesystem metadata, unknown files and
future formats are outside the logical byte count. Writers sharing a directory
must use a consistent budget and the locking protocol. There is no background
cleaner: all reclamation occurs during cache preparation.

## Validation and performance

Regression tests cover aliases and CU-scoped source headers, corruption, forged
lengths, invalid references, version/size/symlink rejection, supplementary identity
replacement and post-load truncation. Real DWARF fixtures compare prepared/raw
name enumeration and symbol queries, verify that enumeration leaves all CUs
unparsed, and exercise cross-CU type projection while unrelated CUs stay lazy.
E2E covers rootless prepare/reuse, corruption fallback and a cached executable
with an uncached shared-library backtrace.

Reproduce a rootless warm module-loading benchmark (one warmup pair, alternating run order):

```bash
cargo run --release -p ghostscope-dwarf --example analysis_cache_bench -- \
  /usr/local/openresty/nginx/sbin/nginx 15
```

The benchmark checks confirmed cache hits and equal symbol/source query results. It reports
all samples, their medians and artifact size. It does not flush the OS page cache
or measure whole-CLI startup or attachment throughput. Native-index targets deliberately avoid this
cache and must not be presented as cache speedups.

### Schema v4 measurement (2026-11-17)

The earlier cooked-index design (v3) measured 94.102 ms raw and 78.600 ms cached
on the OpenResty nginx sample. Profiling found three remaining costs: source
header parsing (56–59 ms), full symbol index decode/reconstruction (40–46 ms),
and type-index construction (13 ms). Header and symbol parsing overlapped, so
these times are not additive. Persisting the lightweight directories and deferring
concrete symbols removes those costs from the hit path.

The v4 benchmark includes module/CFI loading, startup symbol statistics,
and the same `main` function/source query. It asserts hits and query equivalence.
The previous benchmark counted statistics after stopping the timer; the new
measurement deliberately includes them.

Linux x86_64, release profile, `/usr/local/openresty/nginx/sbin/nginx`
(28,319,352 bytes), one warmup pair followed by 15 alternating pairs in one
process. No build or E2E run from this task overlapped this final measurement.
The benchmark requires a nonempty source location, in addition to equal results.

| Measurement | Result |
| --- | ---: |
| Raw median, including startup statistics | 100.518 ms |
| Prepared median, including startup statistics | 26.408 ms |
| Median reduction | 73.7% (3.81x) |
| v4 cache size | 7,042,340 bytes (6.72 MiB) |
| Previous v3 cache size | 10,039,698 bytes (9.57 MiB) |

Raw samples (ms): 97.893, 105.488, 98.085, 101.707, 102.494, 100.633, 99.256, 97.979,
100.518, 101.093, 97.417, 99.361, 106.187, 100.610, 97.400.

Prepared samples (ms): 35.536, 29.036, 40.302, 26.408, 24.958, 24.926, 26.883, 27.832,
26.781, 24.720, 25.930, 24.440, 26.356, 25.573, 26.587.

With capacity/recency tracking enabled, the prepared median is 26.408 ms; the
preceding v4 measurement without this policy was 26.256 ms. This comparison is
within observed run-to-run variation, not a statistical equivalence claim.

These are warm module-loading/query measurements, not whole-CLI startup,
cold-storage measurements or tracing throughput. Queries that visit many CUs
will amortize less of the preparation cost. Native-index targets use their
existing accelerators and are not part of this speedup claim.

### Initial v4 verification record (2026-11-17)

- `cargo fmt --all`, its final `--check`, and `git diff --check`.
- `cargo clippy --all-targets --all-features -- -D warnings -D clippy::undocumented_unsafe_blocks`.
- `cargo test -p ghostscope-dwarf --lib`: 389 passed, including prepared-directory
  enumeration, cross-CU projection, DWARF 4/5 file numbering, corrupt headers,
  recency, quota reservation, concurrent writers and safe eviction.
- `cargo test -p ghostscope-ui -p ghostscope --lib --bins`: 50 UI and 129 CLI
  tests passed.
- `cargo build --release -p ghostscope --all-features`: passed. The release CLI
  prepared and reused the nginx cache successfully without root.
- Standard host E2E: runner `9103b6583c9f` completed in one full invocation,
  exit code 0, **434 tests passed**. The rootless prepare/reuse test also verifies
  a lowered configured budget, eviction ordering and abandoned-temporary cleanup.
  Host-mode capability/topology skips inside tests retain their usual behavior.
- Release CLI smoke test with three copies of nginx: a 16 MiB budget evicted the
  cold entry and retained the recently reused entry; lowering it to 8 MiB pruned
  on reuse; 1 MiB rejected the oversized entry without deleting the retained cache.
  All smoke-test temporary directories were removed after completion.
- Container-topology E2E is intentionally excluded because this change does not
  alter container behavior, PID namespaces or runner topology.

### CI follow-up (2026-11-18)

Schema v5 uses postcard instead of the unmaintained bincode dependency. The
same nginx sample produces a 3,382,242-byte entry (3.23 MiB), down from
7,042,340 bytes in v4. The v4 timings above are historical measurements; the
codec change needs its own timing comparison. Input length, checksums,
trailing-byte rejection and reference validation remain enforced. Eviction
tests account for variable-length encoded identity metadata.

The performance validator accepts the new `prepared` counter and treats its
absence in base-revision reports as zero. It still rejects unexpected cache
hits and unknown counters. All 11 archived CI base reports pass with both
counter layouts; the three index-selection tests pass. The real DWZ/GDB
corpus-generation test was skipped locally because the required tools were
not all available.

The overlap execution tests share one fixture initialization before launching
targets. The inode-sensitive prepared-backtrace test uses private executable
and shared-library copies and includes prepare/runtime output on failure.
The original CI cache miss did not reproduce in local focused or parallel
backtrace runs.

Dependency checks also required replacing chrono with jiff for local timestamp
formatting and updating rustix, quinn-proto and quinn-udp to fixed versions.
`cargo audit --deny warnings`, `cargo deny check advisories bans licenses sources`,
formatting and the CI Clippy command pass. Unit tests pass: 390 DWARF, 129 CLI,
50 UI, 9 debuginfod and 82 process tests. Full standard E2E results are recorded
in the PR; container-topology runs remain outside the local scope of this fix.
