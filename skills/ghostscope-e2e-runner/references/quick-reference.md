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
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "test_case": "test_rust_script_print_globals"
  }'
```

Run one case with explicit topology via API:

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

Run one case with explicit topology and GhostScope debug logs:

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

Run all:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope"
  }'
```

Recommended post-feature sequence:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope"
  }'
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
      "target": "docker-private"
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

## Container Topology E2E

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
      "target": "docker-private"
    }
  }'
```

Host-PID same-sandbox smoke:

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

Fallback local CI-style commands:

```bash
sudo env \
  E2E_GHOSTSCOPE_SANDBOX=host \
  E2E_TARGET_SANDBOX=docker-private \
  cargo test --all-features -- --nocapture

sudo env \
  E2E_GHOSTSCOPE_SANDBOX=docker-private \
  E2E_TARGET_SANDBOX=docker-private \
  cargo test --all-features -- --nocapture

for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  sudo env \
    E2E_GHOSTSCOPE_SANDBOX=docker-host \
    E2E_TARGET_SANDBOX=docker-host \
    cargo test --all-features --test script_execution "$test_case" -- --nocapture
done
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

Submit with sandbox topology:

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

## Local Cargo Logging

Enable GhostScope debug logs for direct `cargo test` runs:

```bash
E2E_GHOSTSCOPE_LOG_LEVEL=debug \
cargo test --all-features --test script_execution test_correct_pid_filtering -- --nocapture
```

Supported levels:

- `error`
- `warn`
- `info`
- `debug`
- `trace`
