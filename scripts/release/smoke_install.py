#!/usr/bin/env python3
"""Exercise the real installer offline with a release archive and isolated home.

Only GitHub metadata/download transport is substituted. Extraction, installation,
config selection, existing-config preservation, cleanup and CLI execution are real.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def smoke(archive):
    archive = archive.resolve()
    tag = archive.name[len("ghostscope-"):-len("-x86_64-linux.tar.gz")]
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="ghostscope-release-smoke-") as tmp:
        root = Path(tmp)
        home, shim, downloads = (root / name for name in ("home", "shim", "downloads"))
        for path in (home, shim, downloads):
            path.mkdir()
        # Run a standalone installer, as with curl | bash, without repository config.
        installer = root / "install.sh"
        shutil.copyfile(repo / "scripts/install.sh", installer)
        curl = shim / "curl"
        curl.write_text('''#!/usr/bin/env python3
import os, shutil, sys
args = sys.argv[1:]
if "-o" in args:
    shutil.copyfile(os.environ["SMOKE_ARCHIVE"], args[args.index("-o") + 1])
else:
    print(os.environ["SMOKE_METADATA"])
''')
        curl.chmod(0o755)
        env = os.environ.copy()
        env.update({
            "HOME": str(home), "TMPDIR": str(downloads),
            "PATH": str(shim) + os.pathsep + env["PATH"],
            "SMOKE_ARCHIVE": str(archive),
            "SMOKE_METADATA": json.dumps({"tag_name": tag, "assets": [{
                "name": archive.name, "browser_download_url": "https://example.invalid/" + archive.name,
            }]}),
        })
        env.pop("PREFIX", None)
        env.pop("DESTDIR", None)
        command = ["bash", str(installer), "--version", tag]
        subprocess.run(command, env=env, cwd=root, check=True)
        config = home / ".ghostscope/config.toml"
        assert config.read_bytes() == (repo / "config.toml").read_bytes(), "archive config was not installed"
        assert not list(downloads.iterdir()), "installer leaked temporary files"
        binary = home / ".ghostscope/bin/ghostscope"
        version = subprocess.check_output([str(binary), "--version"], env=env, text=True).strip()
        assert version == "ghostscope " + tag.lstrip("v"), version
        for flag, doc in (("--script-help", "scripting.md"), ("--value-diagnostics-help", "value-diagnostics.md")):
            output = subprocess.check_output([str(binary), flag], env=env)
            assert output == (repo / "docs" / doc).read_bytes(), flag
        subprocess.run([str(binary), "--help"], env=env, check=True, stdout=subprocess.DEVNULL)
        config.write_text("# preserve user configuration\n")
        subprocess.run(command, env=env, cwd=root, check=True)
        assert config.read_text() == "# preserve user configuration\n"
        assert not list(downloads.iterdir()), "reinstall leaked temporary files"
        print("Release install smoke passed:", version)


if __name__ == "__main__":
    smoke(Path(sys.argv[1]))
