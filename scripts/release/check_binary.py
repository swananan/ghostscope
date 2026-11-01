#!/usr/bin/env python3
"""Reject release binaries exceeding the Linux x86_64 / glibc 2.31 baseline."""
import re
import subprocess
import sys


def check(binary):
    header = subprocess.check_output(["readelf", "-h", binary], text=True)
    if "ELF64" not in header or "Advanced Micro Devices X86-64" not in header:
        raise ValueError("release binary must be x86_64 ELF64")
    symbols = subprocess.check_output(["objdump", "-T", binary], text=True)
    versions = {tuple(map(int, v.split("."))) for v in re.findall(r"\bGLIBC_([0-9.]+)", symbols)}
    if not versions:
        raise ValueError("no GLIBC symbol versions found; cannot verify baseline")
    maximum = max(versions)
    print("Maximum required GLIBC version:", ".".join(map(str, maximum)))
    if maximum > (2, 31):
        raise ValueError("release requires glibc newer than 2.31")
    dynamic = subprocess.check_output(["readelf", "-d", binary], text=True)
    needed = re.findall(r"\(NEEDED\).*\[([^]]+)\]", dynamic)
    print("Shared libraries:", ", ".join(needed))
    if any("libffi" in name or "libLLVM" in name for name in needed):
        raise ValueError("release must not depend on shared LLVM or libffi")


if __name__ == "__main__":
    try:
        check(sys.argv[1])
    except (ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
