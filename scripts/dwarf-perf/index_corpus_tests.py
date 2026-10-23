#!/usr/bin/env python3
"""Behavioral checks for index selection guards and real corpus generation."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from build_index_corpus import VARIANTS, build, sections
from validate_index_usage import INDEX_KINDS, validate


class IndexSelectionTests(unittest.TestCase):
    def test_selected_index_and_supplement_are_required(self):
        for kind in INDEX_KINDS[:-1]:
            for supplementary in (False, True):
                with self.subTest(kind=kind, supplementary=supplementary):
                    expected = {"kind": kind, "supplementary": supplementary}
                    actual = {key: int(key == kind) for key in INDEX_KINDS}
                    actual["supplementary"] = int(supplementary)
                    validate(expected, actual)
                    for field in actual:
                        wrong = {**actual, field: 1 - actual[field]}
                        with self.assertRaises(ValueError):
                            validate(expected, wrong)
                    with self.assertRaises(ValueError):
                        validate(expected, None)

    def test_legacy_manifests_remain_usable(self):
        validate(None, None)
        validate(None, {"full_scan": 1})


class RealCorpusTests(unittest.TestCase):
    def test_real_dwz_and_gdb_outputs_preserve_original(self):
        dwz = os.environ.get("DWARF_PERF_TEST_DWZ", "dwz")
        if not all(shutil.which(tool) for tool in ("cc", "gdb", "gdb-add-index", "readelf", dwz)):
            self.skipTest("requires cc, dwz, GDB, and binutils")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "test.c"
            source.write_text("struct Value { int count; }; struct Value state; int main(void) { return state.count; }\n")
            binary = root / "parse-stress" / "parse_stress"
            binary.parent.mkdir()
            subprocess.run(["cc", "-g", "-gdwarf-5", str(source), "-o", str(binary)], check=True)
            original_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            (root / "manifest.json").write_text(json.dumps({"artifacts": [{
                "name": "parse-stress", "kind": "fast-parse",
                "relative_path": "parse-stress/parse_stress", "generator": {},
            }]}))
            for _ in range(2):  # Rebuilding must not reuse previously indexed input.
                manifest = build(root, dwz, "gdb-add-index")
                self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), original_sha)
                self.assertEqual(len(manifest["artifacts"]), 1 + len(VARIANTS))
                for artifact in manifest["artifacts"][1:]:
                    generated = root / artifact["relative_path"]
                    names = sections(generated)
                    expected = artifact["expected_index"]
                    if expected["kind"] != "full_scan":
                        self.assertIn(".gdb_index" if expected["kind"] == "gdb_index" else ".debug_names", names)
                    if expected["supplementary"]:
                        self.assertIn(".gnu_debugaltlink", names)
                        companion = root / artifact["supplementary"]["relative_path"]
                        self.assertTrue(companion.is_file())
                        self.assertEqual(companion.parent, generated.parent)
                        self.assertEqual(artifact["supplementary"]["sha256"], hashlib.sha256(companion.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
