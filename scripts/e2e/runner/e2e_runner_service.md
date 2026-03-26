# e2e runner service (agent-oriented)

## Shared Skill Install

Install project skill for Codex:

```bash
./scripts/e2e/runner/install_codex_skill.sh
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

## Container topology smoke (CI/local)

Use topology-aware `cargo test` runs for `-p` PID smoke validation:

```bash
for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  sudo env \
    E2E_GHOSTSCOPE_SANDBOX=docker-private \
    E2E_TARGET_SANDBOX=docker-private \
    E2E_SHARE_SANDBOX=1 \
    cargo test --all-features --test script_execution "$test_case" -- --nocapture
done

for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  sudo env \
    E2E_GHOSTSCOPE_SANDBOX=docker-host \
    E2E_TARGET_SANDBOX=docker-host \
    E2E_SHARE_SANDBOX=1 \
    cargo test --all-features --test script_execution "$test_case" -- --nocapture
done
```
