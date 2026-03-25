---
name: ghostscope-e2e-runner
description: Run GhostScope e2e tests through the project scripts under `scripts/e2e/`. Use when the user asks to execute e2e tests, run a specific test case, run tests for a specific repo path, diagnose e2e failures, handle sudo or permission issues around eBPF test execution, or run container PID-namespace smoke tests.
---

# GhostScope E2E Runner

## Overview

Execute GhostScope e2e with the project-standard scripts in `scripts/e2e/`.
Use `scripts/e2e/runner/` for the HTTP runner service flow and `scripts/e2e/container/` for Docker PID-namespace smoke runs.
The container path runs directly via Docker and does not use the HTTP runner service.
This skill is the default path for standard GhostScope e2e execution.
Prefer the HTTP runner service path for standard e2e, then use local fallback only when the service path is unavailable.

## Core Commands

Use repository root `/mnt/500g/code/ghostscope` unless the user gives another path.

Start runner service (user can run with sudo when required):

```bash
./scripts/e2e/runner/start_e2e_runner_service.sh
```

Run one case through service:

```bash
E2E_USE_SERVICE=1 \
E2E_SERVICE_URL=http://127.0.0.1:8788 \
E2E_SUDO=1 \
E2E_REPO_DIR=/mnt/500g/code/ghostscope \
E2E_TEST_CASE=test_rust_script_print_globals \
./scripts/e2e/runner/run_e2e_runner.sh
```

Run one case with explicit sandbox topology through the runner API:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "test_case": "test_correct_pid_filtering",
    "topology": {
      "ghostscope": "host",
      "target": "docker-private",
      "share": false
    }
  }'
```

Run full e2e set (no case filter):

```bash
E2E_USE_SERVICE=1 E2E_SUDO=1 ./scripts/e2e/runner/run_e2e_runner.sh
```

Run container PID smoke:

```bash
./scripts/e2e/container/run_container_e2e.sh --pid-mode private
./scripts/e2e/container/run_container_e2e.sh --pid-mode host
```

Check service health:

```bash
curl -sS http://127.0.0.1:8788/health
```

## Execution Flow

1. For routine feature completion, run the full verification set in this order:
- standard e2e through this skill, using `scripts/e2e/runner/run_e2e_runner.sh`
- container e2e through `scripts/e2e/container/run_container_e2e.sh --pid-mode private`
- container e2e through `scripts/e2e/container/run_container_e2e.sh --pid-mode host`
2. Check `/health` before submitting runs when the user expects service mode.
3. Run `scripts/e2e/runner/run_e2e_runner.sh` for standard host-host runs:
- `E2E_REPO_DIR` when repo is not default.
- `E2E_TEST_CASE` when user asks for a single case.
- `E2E_SUDO=1` for eBPF tests that require elevated privileges.
4. For cross-environment PID scenarios, submit directly to the runner API with a `topology` object:
 - `ghostscope`: `host|docker-private|docker-host`
 - `target`: `host|docker-private|docker-host`
 - `share`: optional boolean; defaults to `false`
 - If `topology` is omitted, the run defaults to `host -> host`
5. Wait for final status and report:
- job id
- status and exit code
- failing test name and first actionable error
6. Avoid silent fallback on test failures:
- treat failed service test run as real failure, not transport failure.

## Failure Handling

If output contains `GhostScope needs elevated privileges to load eBPF programs`:
- confirm service was started with sudo or environment has required capabilities.
- rerun with `E2E_SUDO=1`.

If output shows `sudo: a password is required`:
- ask user to start service as root/sudo in their terminal.
- or ask user to provide a non-interactive sudo setup.

If output contains invalid repo path or missing `Cargo.toml`:
- correct `E2E_REPO_DIR` or service `DEFAULT_REPO_DIR`.

## References

Use [quick-reference.md](references/quick-reference.md) for command templates and environment variables.
