---
name: ghostscope-e2e-runner
description: Run GhostScope e2e through the project runner service API, including explicit topology runs, with direct topology-aware `cargo test` only as a fallback when the runner is unavailable. Use when the user asks to execute e2e tests, run a specific test case, run tests for a specific repo path, diagnose e2e failures, handle sudo or permission issues around eBPF test execution, or run container-topology e2e scenarios.
---

# GhostScope E2E Runner

## Overview

Execute GhostScope e2e with the project-standard runner service and explicit topology requests.
Use `scripts/e2e/runner/` for the HTTP runner service flow.
Use direct `cargo test` with sandbox environment variables only as a fallback when the runner service is unavailable or when the user explicitly asks for the raw CI-style commands.
This skill is the default path for both standard and container-topology GhostScope e2e execution.
Prefer the HTTP runner service path first, then fall back to local commands only when the service path is unavailable.

## Core Commands

Use repository root `/mnt/500g/code/ghostscope` unless the user gives another path.

Start runner service (user can run with sudo when required):

```bash
./scripts/e2e/runner/start_e2e_runner_service.sh
```

Run one case through service:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "test_case": "test_rust_script_print_globals"
  }'
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
      "target": "docker-private"
    }
  }'
```

Run one case with explicit topology and GhostScope debug logs through the runner API:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "test_case": "test_correct_pid_filtering",
    "logging": {
      "level": "debug"
    },
    "topology": {
      "ghostscope": "host",
      "target": "docker-private"
    }
  }'
```

Run full e2e set (no case filter):

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope"
  }'
```

Run full e2e for the primary container topologies through the runner API:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "topology": {
      "ghostscope": "host",
      "target": "docker-private"
    }
  }'

curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "topology": {
      "ghostscope": "docker-private",
      "target": "docker-private",
      "target_mode": "child-container"
    }
  }'
```

Run host-PID same-sandbox smoke through the runner API:

```bash
for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  curl -sS -X POST http://127.0.0.1:8788/runs \
    -H 'Content-Type: application/json' \
    -d "{
      \"sudo\": true,
      \"repo\": \"/mnt/500g/code/ghostscope\",
      \"test_case\": \"$test_case\",
      \"topology\": {
        \"ghostscope\": \"docker-host\",
        \"target\": \"docker-host\"
      }
    }"
done
```

Fallback local topology commands:

```bash
sudo env \
  E2E_GHOSTSCOPE_SANDBOX=host \
  E2E_TARGET_SANDBOX=docker-private \
  cargo test -p ghostscope --tests --all-features -- --nocapture

sudo env \
  E2E_GHOSTSCOPE_SANDBOX=docker-private \
  E2E_TARGET_SANDBOX=docker-private \
  cargo test -p ghostscope --tests --all-features -- --nocapture

for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  sudo env \
    E2E_GHOSTSCOPE_SANDBOX=docker-host \
    E2E_TARGET_SANDBOX=docker-host \
    cargo test -p ghostscope --all-features --test script_execution "$test_case" -- --nocapture
done
```

Check service health:

```bash
curl -sS http://127.0.0.1:8788/health
```

## Execution Flow

1. For routine feature completion, run the full verification set in this order:
- standard e2e through this skill, using the runner service API
- full e2e for `host -> docker-private` through the runner service API with `topology`
- full e2e for `docker-private -> same docker-private` through the runner service API with `topology`
- smoke e2e for `docker-host -> same docker-host` through the runner service API with `topology`
- use direct `sudo env ... cargo test` only when the runner service is unavailable or when the user explicitly asks for the raw CI-style commands
2. Check `/health` before submitting runs when the user expects service mode.
3. Submit `POST /runs` for standard host-host runs:
- `repo` when the checkout path is not the default repo.
- `test_case` when the user asks for a single case.
- `sudo: true` for eBPF tests that require elevated privileges.
4. For cross-environment PID scenarios and container-topology verification, submit directly to the runner API with a `topology` object:
- `ghostscope`: `host|docker-private|docker-host`
- `target`: `host|docker-private|docker-host`
- `target_mode`: `same|child-container` (use `child-container` only with `docker-private -> docker-private`)
- Optional `logging.level`: `error|warn|info|debug|trace`
 - If `topology` is omitted, the run defaults to `host -> host`
 - If `logging.level` is set, the e2e helper enables GhostScope file+console logging for that run
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
- ask user to start the runner service as root/sudo in their terminal.
- or ask user to provide a non-interactive sudo setup if they specifically need the local fallback commands.

If output contains invalid repo path or missing `Cargo.toml`:
- correct `E2E_REPO_DIR` or service `DEFAULT_REPO_DIR`.

## References

Use [quick-reference.md](references/quick-reference.md) for command templates and environment variables.
