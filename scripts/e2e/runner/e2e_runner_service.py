#!/usr/bin/env python3
"""Simple HTTP service to trigger GhostScope e2e runs.

Endpoints:
- GET  /health
- GET  /runs
- GET  /runs/<job_id>
- GET  /runs/<job_id>/log?tail=200
- POST /runs

POST /runs body (JSON, optional):
{
  "sudo": true,
  "repo": "/mnt/500g/code/ghostscope",
  "test_case": "my_case_name",
  "logging": {
    "level": "debug"
  },
  "topology": {
    "ghostscope": "host",
    "target": "docker-private",
    "target_mode": "same"
  }
}

If E2E_SERVICE_TOKEN is set, POST endpoints require header:
X-Auth-Token: <token>
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shlex
import shutil
import signal
import subprocess
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


DEFAULT_REPO = "/mnt/500g/code/ghostscope"
MAX_TEST_CASE_LEN = 256
DOCKER_CLEANUP_LIST_TIMEOUT_SECS = 5
DOCKER_CLEANUP_REMOVE_TIMEOUT_SECS = 20
VALID_SANDBOX_ALIASES = {
    "host": "host",
    "docker-private": "docker-private",
    "private": "docker-private",
    "container-private": "docker-private",
    "docker-host": "docker-host",
    "host-pid": "docker-host",
    "docker-host-pid": "docker-host",
    "container-host": "docker-host",
}
VALID_TARGET_MODE_ALIASES = {
    "same": "same",
    "direct": "same",
    "same-sandbox": "same",
    "child-container": "child-container",
    "child": "child-container",
    "nested": "child-container",
    "descendant": "child-container",
}
VALID_LOG_LEVELS = {"error", "warn", "info", "debug", "trace"}
E2E_TEST_PACKAGE = "ghostscope"


def ghostscope_e2e_cargo_args(*extra: str) -> List[str]:
    return ["test", "-p", E2E_TEST_PACKAGE, "--tests", "--all-features", *extra]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class StepResult:
    name: str
    command: List[str]
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None


@dataclass
class Job:
    id: str
    requested_sudo: Optional[bool]
    requested_repo: Optional[str]
    repo: str
    test_case: Optional[str]
    ghostscope_log_level: Optional[str]
    ghostscope_sandbox: str
    target_sandbox: str
    target_mode: str
    status: str = "queued"
    created_at: str = field(default_factory=now_iso)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None
    error: Optional[str] = None
    steps: List[StepResult] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)


def validate_repo_path(repo: Path) -> Path:
    resolved = repo.expanduser().resolve()
    if not resolved.exists() or not (resolved / "Cargo.toml").exists():
        raise ValueError(f"Invalid repo path: {resolved}")
    return resolved


def normalize_test_case(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    candidate = value.strip()
    if not candidate:
        return None

    if len(candidate) > MAX_TEST_CASE_LEN:
        raise ValueError(f"test_case too long (max {MAX_TEST_CASE_LEN})")

    if any(ch in candidate for ch in "\r\n\x00"):
        raise ValueError("test_case cannot contain control characters")

    return candidate


def normalize_sandbox_selection(name: str, value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    candidate = value.strip().lower()
    if not candidate:
        return None

    normalized = VALID_SANDBOX_ALIASES.get(candidate)
    if normalized is None:
        raise ValueError(
            f"{name} must be one of: host, docker-private, docker-host"
        )
    return normalized


def normalize_log_level(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    candidate = value.strip().lower()
    if not candidate:
        return None

    if candidate not in VALID_LOG_LEVELS:
        allowed = ", ".join(sorted(VALID_LOG_LEVELS))
        raise ValueError(f"log level must be one of: {allowed}")
    return candidate


def normalize_target_mode(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    candidate = value.strip().lower()
    if not candidate:
        return None

    normalized = VALID_TARGET_MODE_ALIASES.get(candidate)
    if normalized is None:
        raise ValueError("target_mode must be one of: same, child-container")
    return normalized


class JobStore:
    def __init__(
        self,
        default_repo: Path,
        llvm_prefix: str,
        default_sudo: bool,
        cargo_home: Optional[str],
        max_log_lines: int,
    ) -> None:
        self.default_repo = default_repo
        self.llvm_prefix = llvm_prefix
        self.default_sudo = default_sudo
        self.cargo_home = cargo_home
        self.max_log_lines = max_log_lines

        self._jobs: Dict[str, Job] = {}
        self._order: List[str] = []
        self._lock = threading.Lock()
        self._queue: "queue.Queue[Optional[str]]" = queue.Queue()
        self._worker = threading.Thread(target=self._worker_loop, name="e2e-worker", daemon=True)
        self._worker.start()

    def _resolve_repo(self, requested_repo: Optional[str]) -> Path:
        if requested_repo is None:
            return self.default_repo

        raw = requested_repo.strip()
        if not raw:
            return self.default_repo

        return validate_repo_path(Path(raw))

    def create_job(
        self,
        requested_sudo: Optional[bool],
        requested_repo: Optional[str],
        requested_test_case: Optional[str],
        requested_ghostscope_log_level: Optional[str],
        requested_ghostscope_sandbox: Optional[str],
        requested_target_sandbox: Optional[str],
        requested_target_mode: Optional[str],
    ) -> Job:
        repo = self._resolve_repo(requested_repo)
        test_case = normalize_test_case(requested_test_case)
        ghostscope_log_level = normalize_log_level(requested_ghostscope_log_level)
        ghostscope_sandbox = normalize_sandbox_selection(
            "ghostscope_sandbox", requested_ghostscope_sandbox
        ) or "host"
        target_sandbox = normalize_sandbox_selection(
            "target_sandbox", requested_target_sandbox
        ) or "host"
        target_mode = normalize_target_mode(requested_target_mode) or "same"
        if (
            target_mode == "child-container"
            and (
                ghostscope_sandbox != "docker-private"
                or target_sandbox != "docker-private"
            )
        ):
            raise ValueError(
                "topology.target_mode=child-container requires ghostscope=docker-private and target=docker-private"
            )

        job = Job(
            id=uuid.uuid4().hex[:12],
            requested_sudo=requested_sudo,
            requested_repo=requested_repo,
            repo=str(repo),
            test_case=test_case,
            ghostscope_log_level=ghostscope_log_level,
            ghostscope_sandbox=ghostscope_sandbox,
            target_sandbox=target_sandbox,
            target_mode=target_mode,
        )
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
        self._queue.put(job.id)
        return job

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            job_ids = list(self._order[-limit:])
            jobs = [self._jobs[jid] for jid in job_ids]
        return [self._job_summary(j) for j in reversed(jobs)]

    def get_job(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def stop(self) -> None:
        self._queue.put(None)
        self._worker.join(timeout=5)

    @property
    def worker_alive(self) -> bool:
        return self._worker.is_alive()

    def _append_log(self, job: Job, line: str) -> None:
        stamped = f"[{now_iso()}] {line}"
        with self._lock:
            job.logs.append(stamped)
            overflow = len(job.logs) - self.max_log_lines
            if overflow > 0:
                del job.logs[:overflow]

    def _set_status(self, job: Job, **updates: Any) -> None:
        with self._lock:
            for key, value in updates.items():
                setattr(job, key, value)

    def _job_summary(self, job: Job) -> Dict[str, Any]:
        return {
            "id": job.id,
            "status": job.status,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "exit_code": job.exit_code,
            "error": job.error,
            "requested_sudo": job.requested_sudo,
            "requested_repo": job.requested_repo,
            "repo": job.repo,
            "test_case": job.test_case,
            "ghostscope_log_level": job.ghostscope_log_level,
            "ghostscope_sandbox": job.ghostscope_sandbox,
            "target_sandbox": job.target_sandbox,
            "target_mode": job.target_mode,
            "topology": {
                "ghostscope": job.ghostscope_sandbox,
                "target": job.target_sandbox,
                "target_mode": job.target_mode,
            },
            "steps": len(job.steps),
            "log_lines": len(job.logs),
        }

    def _resolve_test_command(self, use_sudo: bool, test_case: Optional[str]) -> List[str]:
        cargo_args = ghostscope_e2e_cargo_args()
        if test_case:
            cargo_args.append(test_case)

        if os.geteuid() == 0 or not use_sudo:
            return ["cargo", *cargo_args]

        cargo_path = shutil.which("cargo") or "cargo"
        return ["sudo", "-E", cargo_path, *cargo_args]

    def _step_commands(self, requested_sudo: Optional[bool], test_case: Optional[str]) -> List[StepResult]:
        use_sudo = self.default_sudo if requested_sudo is None else requested_sudo

        build_cmd = ["cargo", *ghostscope_e2e_cargo_args("--no-run")]
        if test_case:
            build_cmd.append(test_case)

        return [
            StepResult(name="build_test_binaries", command=build_cmd),
            StepResult(name="build_dwarf_tool", command=["cargo", "build", "-p", "dwarf-tool"]),
            StepResult(
                name="run_e2e_case" if test_case else "run_e2e",
                command=self._resolve_test_command(use_sudo, test_case),
            ),
        ]

    def _session_name(self, job: Job) -> str:
        return f"runner-{job.id}"

    def _resolve_docker_command(self, use_sudo: bool, *args: str) -> List[str]:
        if os.geteuid() == 0 or not use_sudo:
            return ["docker", *args]
        return ["sudo", "-E", "docker", *args]

    def _cleanup_session_sandboxes(self, job: Job) -> None:
        use_sudo = self.default_sudo if job.requested_sudo is None else job.requested_sudo
        session = self._session_name(job)

        list_cmd = self._resolve_docker_command(
            use_sudo,
            "ps",
            "-aq",
            "--filter",
            f"label=ghostscope.session={session}",
        )
        try:
            result = subprocess.run(
                list_cmd,
                cwd=job.repo,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=DOCKER_CLEANUP_LIST_TIMEOUT_SECS,
            )
        except subprocess.TimeoutExpired:
            self._append_log(
                job,
                (
                    f"Cleanup: timed out listing session sandboxes for {session} "
                    f"after {DOCKER_CLEANUP_LIST_TIMEOUT_SECS}s"
                ),
            )
            return
        if result.returncode != 0:
            stderr = result.stderr.strip() or "<no stderr>"
            self._append_log(
                job,
                f"Cleanup: failed to list session sandboxes for {session}: {stderr}",
            )
            return

        container_ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not container_ids:
            self._append_log(job, f"Cleanup: no session sandboxes found for {session}")
            return

        remove_cmd = self._resolve_docker_command(use_sudo, "rm", "-f", *container_ids)
        try:
            result = subprocess.run(
                remove_cmd,
                cwd=job.repo,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=DOCKER_CLEANUP_REMOVE_TIMEOUT_SECS,
            )
        except subprocess.TimeoutExpired:
            self._append_log(
                job,
                (
                    f"Cleanup: timed out removing {len(container_ids)} session sandbox(s) "
                    f"for {session} after {DOCKER_CLEANUP_REMOVE_TIMEOUT_SECS}s"
                ),
            )
            return
        if result.returncode != 0:
            stderr = result.stderr.strip() or "<no stderr>"
            self._append_log(
                job,
                (
                    f"Cleanup: failed to remove {len(container_ids)} session sandbox(s) "
                    f"for {session}: {stderr}"
                ),
            )
            return

        self._append_log(
            job,
            f"Cleanup: removed {len(container_ids)} session sandbox(s) for {session}",
        )

    def _start_cleanup_session_sandboxes(self, job: Job) -> None:
        def cleanup_task() -> None:
            try:
                self._cleanup_session_sandboxes(job)
            except Exception as exc:  # noqa: BLE001
                self._append_log(job, f"Cleanup: unhandled exception: {exc}")

        thread = threading.Thread(
            target=cleanup_task,
            name=f"cleanup-{job.id}",
            daemon=True,
        )
        thread.start()
        self._append_log(
            job,
            f"Cleanup: scheduled background session cleanup for {self._session_name(job)}",
        )

    def _run_step(self, job: Job, step: StepResult) -> int:
        step.started_at = now_iso()
        self._append_log(job, f"cwd={job.repo}")
        self._append_log(job, f"$ {' '.join(shlex.quote(part) for part in step.command)}")

        env = os.environ.copy()
        env["LLVM_SYS_181_PREFIX"] = self.llvm_prefix
        llvm_config = Path(self.llvm_prefix) / "bin" / "llvm-config"
        if llvm_config.exists():
            env["LLVM_CONFIG_PATH"] = str(llvm_config)
        else:
            env.pop("LLVM_CONFIG_PATH", None)
        if self.cargo_home:
            env["CARGO_HOME"] = self.cargo_home
        env["E2E_GHOSTSCOPE_SANDBOX"] = job.ghostscope_sandbox
        env["E2E_TARGET_SANDBOX"] = job.target_sandbox
        env["E2E_SANDBOX_SESSION"] = self._session_name(job)
        if job.target_mode != "same":
            env["E2E_TARGET_MODE"] = job.target_mode
        else:
            env.pop("E2E_TARGET_MODE", None)
        if job.ghostscope_log_level:
            env["E2E_GHOSTSCOPE_LOG_LEVEL"] = job.ghostscope_log_level
        else:
            env.pop("E2E_GHOSTSCOPE_LOG_LEVEL", None)

        process = subprocess.Popen(
            step.command,
            cwd=job.repo,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        assert process.stdout is not None
        for line in process.stdout:
            self._append_log(job, line.rstrip("\n"))

        process.wait()
        step.exit_code = process.returncode
        step.finished_at = now_iso()
        self._append_log(job, f"Step '{step.name}' exited with code {process.returncode}")
        return process.returncode

    def _worker_loop(self) -> None:
        while True:
            job_id = self._queue.get()
            if job_id is None:
                return

            job = self.get_job(job_id)
            if job is None:
                continue

            self._set_status(job, status="running", started_at=now_iso())
            self._append_log(
                job,
                (
                    "starting job "
                    f"id={job.id} repo={job.repo} test_case={job.test_case or '<all>'} "
                    f"requested_sudo={job.requested_sudo} "
                    f"log_level={job.ghostscope_log_level or '<default>'} "
                    f"topology={job.ghostscope_sandbox}->{job.target_sandbox} "
                    f"target_mode={job.target_mode}"
                ),
            )

            steps = self._step_commands(job.requested_sudo, job.test_case)
            with self._lock:
                job.steps = steps

            failed_code: Optional[int] = None
            try:
                for step in steps:
                    rc = self._run_step(job, step)
                    if rc != 0:
                        failed_code = rc
                        break
            except Exception as exc:  # noqa: BLE001
                self._append_log(job, f"Unhandled exception: {exc}")
                self._set_status(
                    job,
                    status="failed",
                    exit_code=1,
                    error=str(exc),
                    finished_at=now_iso(),
                )
            else:
                if failed_code is None:
                    self._set_status(job, status="succeeded", exit_code=0, finished_at=now_iso())
                else:
                    self._set_status(job, status="failed", exit_code=failed_code, finished_at=now_iso())
            finally:
                self._start_cleanup_session_sandboxes(job)


class Handler(BaseHTTPRequestHandler):
    store: JobStore
    auth_token: str

    server_version = "e2e-runner/0.2"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return

    def _write_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _check_auth(self) -> bool:
        if not self.auth_token:
            return True
        supplied = self.headers.get("X-Auth-Token", "")
        return supplied == self.auth_token

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self._write_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "worker_alive": self.store.worker_alive,
                    "default_repo": str(self.store.default_repo),
                },
            )
            return

        if path == "/runs":
            self._write_json(HTTPStatus.OK, {"runs": self.store.list_jobs()})
            return

        if path.startswith("/runs/"):
            parts = path.strip("/").split("/")
            if len(parts) < 2:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid path"})
                return

            job_id = parts[1]
            job = self.store.get_job(job_id)
            if job is None:
                self._write_json(HTTPStatus.NOT_FOUND, {"error": "job not found"})
                return

            if len(parts) == 2:
                data = asdict(job)
                data["summary"] = self.store._job_summary(job)
                data["log_tail"] = job.logs[-200:]
                self._write_json(HTTPStatus.OK, data)
                return

            if len(parts) == 3 and parts[2] == "log":
                qs = parse_qs(parsed.query)
                tail = 200
                if "tail" in qs:
                    try:
                        tail = max(1, min(5000, int(qs["tail"][0])))
                    except ValueError:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": "tail must be an integer"})
                        return
                self._write_json(
                    HTTPStatus.OK,
                    {
                        "id": job.id,
                        "status": job.status,
                        "exit_code": job.exit_code,
                        "tail": tail,
                        "lines": job.logs[-tail:],
                    },
                )
                return

        self._write_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._check_auth():
            self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path != "/runs":
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        try:
            body = self._parse_json_body()
        except json.JSONDecodeError:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json body"})
            return

        requested_sudo = body.get("sudo")
        if requested_sudo is not None and not isinstance(requested_sudo, bool):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "sudo must be true/false"})
            return

        requested_repo = body.get("repo", body.get("repo_dir"))
        if requested_repo is not None and not isinstance(requested_repo, str):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "repo must be a string"})
            return

        requested_test_case = body.get("test_case")
        if requested_test_case is not None and not isinstance(requested_test_case, str):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "test_case must be a string"})
            return

        logging = body.get("logging")
        if logging is not None and not isinstance(logging, dict):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "logging must be an object"})
            return

        requested_ghostscope_log_level = body.get(
            "ghostscope_log_level",
            body.get("log_level", logging.get("level") if logging else None),
        )
        if requested_ghostscope_log_level is not None and not isinstance(
            requested_ghostscope_log_level, str
        ):
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "ghostscope_log_level must be a string"},
            )
            return

        topology = body.get("topology")
        if topology is not None and not isinstance(topology, dict):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "topology must be an object"})
            return

        requested_ghostscope_sandbox = body.get(
            "ghostscope_sandbox",
            topology.get("ghostscope") if topology else None,
        )
        if requested_ghostscope_sandbox is not None and not isinstance(
            requested_ghostscope_sandbox, str
        ):
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "ghostscope_sandbox must be a string"},
            )
            return

        requested_target_sandbox = body.get(
            "target_sandbox",
            topology.get("target") if topology else None,
        )
        if requested_target_sandbox is not None and not isinstance(
            requested_target_sandbox, str
        ):
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "target_sandbox must be a string"},
            )
            return

        requested_target_mode = body.get(
            "target_mode",
            topology.get("target_mode") if topology else None,
        )
        if requested_target_mode is not None and not isinstance(
            requested_target_mode, str
        ):
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "target_mode must be a string"},
            )
            return

        try:
            job = self.store.create_job(
                requested_sudo=requested_sudo,
                requested_repo=requested_repo,
                requested_test_case=requested_test_case,
                requested_ghostscope_log_level=requested_ghostscope_log_level,
                requested_ghostscope_sandbox=requested_ghostscope_sandbox,
                requested_target_sandbox=requested_target_sandbox,
                requested_target_mode=requested_target_mode,
            )
        except ValueError as exc:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        self._write_json(
            HTTPStatus.ACCEPTED,
            {
                "id": job.id,
                "status": job.status,
                "requested_sudo": job.requested_sudo,
                "requested_repo": job.requested_repo,
                "repo": job.repo,
                "test_case": job.test_case,
                "ghostscope_log_level": job.ghostscope_log_level,
                "ghostscope_sandbox": job.ghostscope_sandbox,
                "target_sandbox": job.target_sandbox,
                "target_mode": job.target_mode,
                "topology": {
                    "ghostscope": job.ghostscope_sandbox,
                    "target": job.target_sandbox,
                    "target_mode": job.target_mode,
                },
            },
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GhostScope e2e runner service")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8788, help="Bind port (default: 8788)")
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help="Default repository path if request does not provide repo",
    )
    parser.add_argument(
        "--llvm-prefix",
        default="/usr/lib/llvm-18",
        help="LLVM_SYS_181_PREFIX value",
    )
    parser.add_argument(
        "--default-sudo",
        action="store_true",
        help="Use sudo for final e2e step by default",
    )
    parser.add_argument(
        "--cargo-home",
        default=os.environ.get("CARGO_HOME"),
        help="Optional CARGO_HOME for cargo cache",
    )
    parser.add_argument(
        "--max-log-lines",
        type=int,
        default=20000,
        help="Maximum stored log lines per job",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("E2E_SERVICE_TOKEN", ""),
        help="Optional auth token for POST requests",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    default_repo = validate_repo_path(Path(args.repo))

    store = JobStore(
        default_repo=default_repo,
        llvm_prefix=args.llvm_prefix,
        default_sudo=args.default_sudo,
        cargo_home=args.cargo_home,
        max_log_lines=args.max_log_lines,
    )

    Handler.store = store
    Handler.auth_token = args.token

    server = ThreadingHTTPServer((args.host, args.port), Handler)

    shutdown_once = threading.Event()

    def request_shutdown(reason: str) -> None:
        if shutdown_once.is_set():
            return
        shutdown_once.set()
        print(f"Shutting down ({reason})...")
        threading.Thread(target=server.shutdown, daemon=True).start()

    def shutdown_handler(signum: int, _frame: Any) -> None:
        request_shutdown(f"signal {signum}")

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print(f"e2e-runner-service listening on http://{args.host}:{args.port}")
    print(f"default_repo={default_repo}")
    print(f"default_sudo={args.default_sudo}")
    print(f"token_required={'yes' if args.token else 'no'}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        request_shutdown("keyboard interrupt")
    finally:
        store.stop()
        server.server_close()


if __name__ == "__main__":
    main()
