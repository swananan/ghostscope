#!/usr/bin/env python3
"""Trace a real DWARF parameter with the packaged executable (requires BPF privileges)."""
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def smoke(binary):
    binary = binary.resolve()
    with tempfile.TemporaryDirectory(prefix="ghostscope-release-trace-") as tmp:
        root = Path(tmp)
        source, target = root / "target.c", root / "target"
        source.write_text('''#include <unistd.h>
__attribute__((noinline)) void release_probe(int value) {
    asm volatile("" : : "r"(value) : "memory");
}
int main(void) {
    for (;;) { release_probe(42); usleep(10000); }
}
''')
        subprocess.run(["cc", "-g", "-O0", "-o", str(target), str(source)], check=True)
        trace = None
        process = subprocess.Popen([str(target)])
        output, errors = root / "stdout", root / "stderr"
        try:
            with output.open("w") as stdout, errors.open("w") as stderr:
                trace = subprocess.Popen([
                    str(binary), "-t", str(target), "-p", str(process.pid),
                    "--no-status", "--no-log", "--script",
                    'trace release_probe { print "release-smoke {}", value; }',
                ], cwd=root, stdout=stdout, stderr=stderr)
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    if "release-smoke 42" in output.read_text():
                        break
                    if trace.poll() is not None:
                        raise RuntimeError("tracer exited before receiving an event")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("timed out waiting for DWARF parameter capture")
                trace.send_signal(signal.SIGINT)
                if trace.wait(timeout=10) != 0:
                    raise RuntimeError("tracer failed during graceful shutdown")
        except Exception:
            print(output.read_text() if output.exists() else "", file=sys.stderr)
            print(errors.read_text() if errors.exists() else "", file=sys.stderr)
            raise
        finally:
            if trace is not None and trace.poll() is None:
                trace.kill()
                trace.wait()
            process.terminate()
            process.wait(timeout=10)
        print("Release tracing smoke passed: captured release-smoke 42 and shut down cleanly")


if __name__ == "__main__":
    smoke(Path(sys.argv[1]))
