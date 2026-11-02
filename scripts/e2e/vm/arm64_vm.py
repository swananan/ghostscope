#!/usr/bin/env python3
"""Prepare a rootless ARM64 Linux VM; never start the e2e runner automatically."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys

IMAGE = "ubuntu-24.04-minimal-cloudimg-arm64.img"
URL = "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20261027/" + IMAGE
SHA256 = "6e971c7935c62c8ea7796b085e4ea038e2301a067f8c853e154133f8df192c85"


def run(*args):
    return subprocess.run([str(arg) for arg in args], check=True)


def prepare(state):
    import pycdlib  # Only needed to create the NoCloud seed ISO.

    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    base = state / "base.qcow2"
    if not base.exists():
        download = state / "base.qcow2.download"
        if not download.exists():
            run("curl", "-fL", "--retry", "2", "--connect-timeout", "15", URL, "-o", download)
        with download.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != SHA256:
            raise RuntimeError(f"image checksum mismatch; remove {download} and retry")
        download.rename(base)
    with base.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SHA256:
            raise RuntimeError("base image checksum mismatch")
    key = state / "id_ed25519"
    if not key.exists():
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
    disk = state / "root.qcow2"
    if not disk.exists():
        run("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base, disk, "12G")
    seed = state / "seed.iso"
    if not seed.exists():
        public_key = key.with_suffix(".pub").read_text().strip()
        user_data = """#cloud-config
hostname: ghostscope-arm64
users:
  - name: ghostscope
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - PUBLIC_KEY
ssh_pwauth: false
disable_root: true
""".replace("PUBLIC_KEY", public_key)
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="cidata")
        for name, content in [("user-data", user_data), ("meta-data", "instance-id: ghostscope-arm64-v1\n")]:
            data = content.encode()
            iso.add_fp(io.BytesIO(data), len(data), iso_path="/" + name.upper().replace("-", "_") + ";1",
                       rr_name=name, joliet_path="/" + name)
        iso.write(str(seed))
        iso.close()
    print(f"Prepared {state}; base image verified, writable disk is a sparse overlay.")


def ssh_args(state, port):
    return ["ssh", "-i", str(state / "id_ed25519"), "-p", str(port),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={state / 'known_hosts'}",
            "-o", "ConnectTimeout=30", "ghostscope@127.0.0.1"]


def start(args, state):
    pidfile = state / "qemu.pid"
    if pidfile.exists() and Path("/proc", pidfile.read_text().strip()).exists():
        raise RuntimeError("VM PID is still present; inspect it before starting another instance")
    for name in ["root.qcow2", "seed.iso"]:
        if not (state / name).exists():
            raise RuntimeError("run prepare first")
    firmware = Path(args.firmware)
    if not firmware.is_file():
        raise RuntimeError(f"missing AArch64 firmware: {firmware}")
    # TCG intentionally works on x86 hosts; no KVM, TAP, or host sudo needed.
    run("qemu-system-aarch64", "-machine", "virt", "-cpu", "max",
        "-accel", "tcg,thread=multi", "-smp", "4", "-m", "4096",
        "-bios", firmware, "-display", "none", "-monitor", "none",
        "-serial", f"file:{state / 'console.log'}", "-daemonize", "-pidfile", pidfile,
        "-drive", f"file={state / 'root.qcow2'},if=virtio,format=qcow2",
        "-drive", f"file={state / 'seed.iso'},if=virtio,format=raw,readonly=on",
        "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{args.ssh_port}-:22,hostfwd=tcp:127.0.0.1:{args.runner_port}-:8788",
        "-device", "virtio-net-pci,netdev=net0", "-device", "virtio-rng-pci")
    (state / "ports.json").write_text(json.dumps({"ssh": args.ssh_port, "runner": args.runner_port}))
    print(f"VM started; boot log: {state / 'console.log'}; SSH port: {args.ssh_port}")


def check(state, port):
    run(*ssh_args(state, port), """set -eu
sudo cloud-init status --wait
[ "$(uname -m)" = aarch64 ]
uname -a
sudo test -r /sys/kernel/btf/vmlinux
for option in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_UPROBES CONFIG_UPROBE_EVENTS CONFIG_PERF_EVENTS CONFIG_DEBUG_INFO_BTF; do
    grep -x "$option=y" "/boot/config-$(uname -r)"
done
command -v python3
sudo -n true
df -h /
""")
    preflight = Path(__file__).with_name("check_arm64_bpf.py").read_bytes()
    subprocess.run(ssh_args(state, port) + ["sudo python3 -"], input=preflight, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path, help="directory on a disk with room for VM data")
    parser.add_argument("--ssh-port", type=int, default=22264)
    parser.add_argument("--runner-port", type=int, default=8789)
    parser.add_argument("--firmware", default="/usr/share/qemu-efi-aarch64/QEMU_EFI.fd")
    parser.add_argument("action", choices=["prepare", "start", "check", "ssh", "stop"])
    args = parser.parse_args()
    state = args.state_dir.resolve()
    if "," in str(state):
        parser.error("QEMU state directory must not contain commas")
    if not all(1 <= port <= 65535 for port in [args.ssh_port, args.runner_port]) or args.ssh_port == args.runner_port:
        parser.error("SSH and runner ports must be distinct valid port numbers")
    if args.action == "prepare":
        prepare(state)
    elif args.action == "start":
        start(args, state)
    else:
        ports = json.loads((state / "ports.json").read_text())
        if args.action == "check":
            check(state, ports["ssh"])
        elif args.action == "ssh":
            run(*ssh_args(state, ports["ssh"]))
        else:
            run(*ssh_args(state, ports["ssh"]), "sudo shutdown -h now")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
