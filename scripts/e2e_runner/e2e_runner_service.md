# e2e runner service (agent-oriented)

## Shared Skill Install

Install project skill for Codex:

```bash
./scripts/e2e_runner/install_codex_skill.sh
```

Then restart Codex.

## Start service

```bash
./scripts/e2e_runner/start_e2e_runner_service.sh
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

```bash
./scripts/e2e_runner/run_e2e_runner.sh
```

Optional env vars for agent trigger:

- `E2E_REPO_DIR=/path/to/repo`
- `E2E_TEST_CASE=<cargo_test_filter>`
