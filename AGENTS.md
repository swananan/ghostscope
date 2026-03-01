# GhostScope Agent Notes

## Skill Routing
- Prefer skill `ghostscope-e2e-runner` for all e2e execution requests.
- Install shared project skill with `./scripts/e2e_runner/install_codex_skill.sh` and restart Codex.

## Scope
- Keep CI workflows and developer-facing docs on normal project test commands.
- Treat `run_e2e_runner.sh` as an agent-oriented operational helper.

## Verification
- After code changes, always run formatting and lint checks before handoff.
- Use the same commands as CI in `.github/workflows/ci.yml` whenever possible.
- Local formatting: `cargo fmt --all` (single run is enough).
- CI uses `cargo fmt --all -- --check` for verification only.
- Minimum local checks (aligned with CI):
  - `cargo clippy --all-targets --all-features -- -D warnings`
- If full-workspace `clippy` is too slow or blocked, run `clippy` for affected crates and clearly report scope.
