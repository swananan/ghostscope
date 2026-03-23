# GhostScope Agent Notes

## Skill Routing
- Prefer skill `ghostscope-e2e-runner` for all e2e execution requests.
- Install shared project skill with `./scripts/e2e/runner/install_codex_skill.sh` and restart Codex.

## Scope
- Keep CI workflows and developer-facing docs on normal project test commands.
- Treat `scripts/e2e/runner/run_e2e_runner.sh` as an agent-oriented operational helper used through the `ghostscope-e2e-runner` skill for standard e2e.

## Verification
- After code changes, always run formatting and lint checks before handoff.
- After routine feature development, also run both e2e paths before handoff:
  - Standard e2e through the `ghostscope-e2e-runner` skill, using `./scripts/e2e/runner/run_e2e_runner.sh`
  - Container e2e through `./scripts/e2e/container/run_container_e2e.sh --pid-mode private` and `--pid-mode host`
- Use the same commands as CI in `.github/workflows/ci.yml` whenever possible.
- Local formatting: `cargo fmt --all` (single run is enough).
- CI uses `cargo fmt --all -- --check` for verification only.
- Minimum local checks (aligned with CI):
  - `cargo clippy --all-targets --all-features -- -D warnings`
- If full-workspace `clippy` is too slow or blocked, run `clippy` for affected crates and clearly report scope.
- If runner service, Docker, or required privileges are unavailable, report that explicitly with the blocked verification scope.
