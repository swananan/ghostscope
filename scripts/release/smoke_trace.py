#!/usr/bin/env python3
"""Trace DWARF values and validate probe PC/SP against real mappings (requires BPF privileges)."""
from pathlib import Path
import re
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
volatile int release_global = 73;
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
                    'trace release_probe { print "release-smoke {} {} pc={:p} sp={:p}", '
                    'value, release_global, cast($pc, "unsigned char *"), '
                    'cast($sp, "unsigned char *"); }',
                ], cwd=root, stdout=stdout, stderr=stderr)
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    match = re.search(r"release-smoke 42 73 pc=(0x[0-9a-fA-F]+) sp=(0x[0-9a-fA-F]+)", output.read_text())
                    if match:
                        pc, sp = (int(value, 16) for value in match.groups())
                        mappings = Path(f"/proc/{process.pid}/maps").read_text().splitlines()
                        pc_valid = sp_valid = False
                        for mapping in mappings:
                            fields = mapping.split(maxsplit=5)
                            start, end = (int(value, 16) for value in fields[0].split("-"))
                            name = fields[5] if len(fields) == 6 else ""
                            pc_valid |= start <= pc < end and "x" in fields[1] and name == str(target)
                            sp_valid |= start <= sp < end and name == "[stack]"
                        if not pc_valid or not sp_valid:
                            raise RuntimeError(f"probe registers do not match target mappings: pc={pc:#x}, sp={sp:#x}")
                        break
                    if trace.poll() is not None:
                        raise RuntimeError("tracer exited before receiving an event")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("timed out waiting for DWARF values and probe registers")
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
        print("Release tracing smoke passed: captured parameter 42, global 73, validated PC/SP, and shut down cleanly")


if __name__ == "__main__":
    smoke(Path(sys.argv[1]))
