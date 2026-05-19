# GhostScope Agent Notes

## Working Rules
- Keep CI workflows and developer-facing docs on normal project test commands.
- Prefer skill `ghostscope-e2e-runner` for all e2e execution requests.
- Install the internal runner skill with `./scripts/e2e/runner/install_ghostscope_e2e_runner_skill.sh` and restart Codex.
- Agent-driven e2e should default to the runner service API instead of invoking local container helper scripts directly.
- If the runner service is not running, tell the user to start it manually instead of trying to start it on their behalf, because it typically requires `sudo`.
- Do not create commits unless the user explicitly asks for a commit.

## Start A Task
- First classify the change before choosing validation scope:
  - docs-only, comment-only, AGENTS-only, or other non-runtime text edits
  - CI/workflow-only edits
  - normal Rust or runtime behavior changes
  - container or topology-related changes
- Treat `.github/workflows/ci.yml` and `.github/workflows/container-e2e.yml` as the source of truth for CI-parity validation scope and intended topology coverage.
- Do not work directly on `main` for non-trivial changes.
- Prefer branch names in the form `<type>/<short-kebab-case-summary>`.
- Common prefixes: `feature/`, `fix/`, `docs/`, `refactor/`, `test/`, `chore/`, `ci/`.
- Keep branch names concise, ASCII-only, and descriptive. An issue ID prefix is fine when the repo or task already uses one.

## Develop And Verify
- Match verification scope to the kind of change instead of running every check by default.
- Docs-only, comment-only, AGENTS-only, and other non-runtime text edits do not require `cargo fmt`, `cargo clippy`, or e2e.
- CI/workflow-only edits do not require routine local e2e unless they change e2e behavior, topology coverage, or runner invocation semantics.
- For normal Rust or runtime behavior changes, run formatting, linting, and standard e2e through the `ghostscope-e2e-runner` skill.
- Local formatting: `cargo fmt --all` (single run is enough).
- CI uses `cargo fmt --all -- --check` for verification only.
- Minimum local checks, aligned with CI:
  - `cargo clippy --all-targets --all-features -- -D warnings`
- If full-workspace `clippy` is too slow or blocked, run `clippy` for affected crates and clearly report scope.
- Do not default to container-topology e2e during routine day-to-day development.
- Only add container-topology e2e when the change is container-related or when the user explicitly asks for it.
- Reserve container-topology e2e for changes that touch container behavior, PID namespace handling, sandbox/topology logic, Docker execution, runner topology requests, or related e2e infrastructure.
- When routine development needs extra integration confidence, prefer a single full `host -> docker-private` run before broader container-topology coverage.
- Container/topology verification expectations:
  - container, PID namespace, sandbox, topology, Docker, or runner-topology changes: add full e2e for `host -> docker-private`
  - same-sandbox private-container behavior changes: also add full e2e for `docker-private -> same docker-private`
  - host-PID container behavior changes: also add smoke e2e for `docker-host -> same docker-host`
- Preferred container-topology escalation order:
  - full e2e for `host -> docker-private`
  - full e2e for `docker-private -> same docker-private` when same-sandbox private-container behavior is relevant
  - smoke e2e for `docker-host -> same docker-host` when host-PID container behavior is relevant
- During normal agent work, align with CI by matching topology intent in runner requests rather than manually reconstructing CI shell commands.
- Use direct topology-aware `sudo env ... cargo test` or `scripts/e2e/container/*.sh` only as a fallback when the runner service is unavailable or when you are explicitly validating CI parity outside the runner.
- If runner service, Docker, or required privileges are unavailable, report that explicitly with the blocked verification scope.

## Finish A Task
- Handoff messages must state what changed, what verification actually ran, and any blocked or intentionally skipped coverage.
- If standard e2e or container-topology e2e was not run, say why in one sentence.
- If e2e is blocked because the runner service is not running, explicitly say that the user should start the runner manually since it usually needs `sudo`.
- If container-topology e2e is intentionally skipped because the change is unrelated, say so explicitly in the handoff.
- Do not claim validation that was not actually executed.
- Keep user-facing messages concise and concrete.
- When a commit is requested, use conventional commits format.
- Format the subject as `<type>: <imperative summary>` and use it to state what the patch does.
- Keep the subject concise and specific, use a lowercase type, and do not end the subject with a period.
- Avoid vague subjects such as `update stuff` or `fix issue`.
- Add a body only when the reason, scope, or risk is not obvious from the subject. Use it to explain why the change is necessary, including relevant design trade-offs and side effects.
- Wrap commit body lines at 80 columns or fewer.
- Prefer one logical change per commit.
