# e2e runner service (agent-oriented)

## Shared Skill Install

Install the internal runner skill for Codex:

```bash
./scripts/e2e/runner/install_ghostscope_e2e_runner_skill.sh
```

Then restart Codex.

## Start service

```bash
./scripts/e2e/runner/start_e2e_runner_service.sh
```

Common env vars:

- `HOST` / `PORT` (default: `127.0.0.1:8788`)
- `DEFAULT_REPO_DIR` (or legacy `REPO_DIR`)
- `LLVM_PREFIX` (default: `/usr/lib/llvm-18`)
- `DEFAULT_SUDO=1|0`
- `E2E_SERVICE_TOKEN=<token>` (optional auth for POST)

## Submit run

`POST /runs` supports:

- `sudo` (`true|false`, optional)
- `repo` (optional absolute path to repo root; must contain `Cargo.toml`)
- `test_case` (optional cargo test filter)
- `logging.level` (`error|warn|info|debug|trace`, optional)
- `topology.ghostscope` (`host|docker-private|docker-host`, optional)
- `topology.target` (`host|docker-private|docker-host`, optional)
- `topology.target_mode` (`same|child-container`, optional)

Each submitted job automatically uses `E2E_SANDBOX_SESSION=runner-<job-id>`.
The service also performs best-effort cleanup of session-scoped Docker sandboxes after the job finishes.

Example:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "test_case": "integration::basic_flow"
  }'
```

The service builds and runs GhostScope integration e2e only: effectively `cargo test -p ghostscope --tests --all-features ...`, plus `cargo build -p dwarf-tool`.

## Agent-side trigger

Submit runs directly to the service:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "test_case": "test_rust_script_print_globals"
  }'
```

## Container topology smoke (preferred)

Use runner API topology requests for `-p` PID smoke validation:

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

Fallback local CI-style commands:

```bash
for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  sudo env \
    E2E_GHOSTSCOPE_SANDBOX=docker-private \
    E2E_TARGET_SANDBOX=docker-private \
    cargo test -p ghostscope --all-features --test script_execution "$test_case" -- --nocapture
done

for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  sudo env \
    E2E_GHOSTSCOPE_SANDBOX=docker-host \
    E2E_TARGET_SANDBOX=docker-host \
    cargo test -p ghostscope --all-features --test script_execution "$test_case" -- --nocapture
done
```
