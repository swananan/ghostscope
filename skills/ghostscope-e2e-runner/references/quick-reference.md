# GhostScope E2E Runner Quick Reference

## Service Startup

Use project scripts:

```bash
cd /mnt/500g/code/ghostscope
./scripts/e2e/runner/start_e2e_runner_service.sh
```

Root startup example:

```bash
cd /mnt/500g/code/ghostscope
sudo env HOST=127.0.0.1 PORT=8788 DEFAULT_SUDO=1 DEFAULT_REPO_DIR=/mnt/500g/code/ghostscope ./scripts/e2e/runner/start_e2e_runner_service.sh
```

## Trigger Runs

Run one case:

```bash
E2E_USE_SERVICE=1 \
E2E_SERVICE_URL=http://127.0.0.1:8788 \
E2E_SUDO=1 \
E2E_REPO_DIR=/mnt/500g/code/ghostscope \
E2E_TEST_CASE=test_rust_script_print_globals \
./scripts/e2e/runner/run_e2e_runner.sh
```

Run all:

```bash
E2E_USE_SERVICE=1 E2E_SUDO=1 ./scripts/e2e/runner/run_e2e_runner.sh
```

Recommended post-feature sequence:

```bash
E2E_USE_SERVICE=1 E2E_SUDO=1 ./scripts/e2e/runner/run_e2e_runner.sh
./scripts/e2e/container/run_container_e2e.sh --pid-mode private
./scripts/e2e/container/run_container_e2e.sh --pid-mode host
```

## Container PID Smoke

```bash
./scripts/e2e/container/run_container_e2e.sh --pid-mode private
./scripts/e2e/container/run_container_e2e.sh --pid-mode host
```

## API

Health:

```bash
curl -sS http://127.0.0.1:8788/health
```

Submit:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{"sudo": true, "repo": "/mnt/500g/code/ghostscope", "test_case": "test_rust_script_print_globals"}'
```
