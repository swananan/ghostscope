import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import runtime_perf as perf


class RuntimeMeasurementTests(unittest.TestCase):
    def collect(self, program, iterations):
        process = subprocess.Popen(
            [sys.executable, "-c", program], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        output = perf.OutputCollector(process, iterations)
        try:
            process.wait(timeout=10)
            output.join()
            return output
        finally:
            perf.terminate(process)

    def test_both_pipes_are_drained_before_ready_and_tail_stays_bounded(self):
        output = self.collect(
            "import sys\n"
            "for _ in range(4000):\n"
            " print('x' * 1024)\n"
            " print('y' * 1024, file=sys.stderr)\n"
            f"print('{perf.READY_MARKER}')\n"
            f"print('{perf.EVENT_PREFIX} 0')\n", 1,
        )
        self.assertTrue(output.ready.is_set())
        self.assertEqual(output.seen, {0})
        self.assertGreater(output.stdout_bytes, 4_000_000)
        self.assertLessEqual(len(output.tails["stdout"]), 16)
        self.assertLessEqual(len(output.tails["stderr"]), 16)

    def test_duplicates_and_bad_ids_do_not_mask_missing_events(self):
        output = self.collect(
            "\n".join(f"print('{perf.EVENT_PREFIX} {value}')" for value in (0, 0, 2, 99, "<error: failed>")), 3,
        )
        self.assertEqual(output.seen, {0, 2})
        self.assertEqual(output.duplicates, 1)
        self.assertEqual(output.invalid_events, 2)
        self.assertTrue(output.value_error)

    def test_complex_value_failures_invalidate_complete_event_streams(self):
        args = perf.parse_args(["--iterations", "2", "--inner-work", "32"])
        rendered_values = (
            "RuntimePayload { index = 1 }",
            "<unreadable: memory read failed> (struct RuntimePayload*)",
            "<unreadable: memory read failed; errno=-14; address=0x1234> (struct RuntimePayload*)",
            "<unavailable: optimized out>",
            "RuntimePayload { bounds = <unreadable: memory read failed> }",
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            perf.hot.run_checked([
                str(perf.hot.resolve_compiler()), *perf.COMPILER_FLAGS,
                "-o", str(target), str(Path(perf.__file__).with_name("runtime_target.c")),
            ])
            observer = root / "fake_observer"
            for index, rendered_value in enumerate(rendered_values):
                with self.subTest(rendered_value=rendered_value):
                    # All IDs and one valid payload arrive even when the other value fails.
                    lines = [
                        perf.READY_MARKER,
                        f"{perf.EVENT_PREFIX} 0",
                        "RuntimePayload { index = 0 }",
                        f"{perf.EVENT_PREFIX} 1",
                        rendered_value,
                    ]
                    rendered_output = "\n".join(lines)
                    observer.write_text(
                        f"#!{sys.executable}\nimport signal, sys\n"
                        "signal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n"
                        f"print({rendered_output!r}, flush=True)\n"
                        "while True: signal.pause()\n"
                    )
                    observer.chmod(0o755)
                    if index == 0:
                        result = perf.run_once(target, observer, "complex", args, root)
                        self.assertEqual(result["received_events"], args.iterations)
                        self.assertEqual(result["missing_events"], 0)
                    else:
                        with self.assertRaisesRegex(perf.hot.BenchmarkError, "invalid trace output") as error:
                            perf.run_once(target, observer, "complex", args, root)
                        self.assertIn(rendered_value, str(error.exception))

    def test_real_target_barriers_produce_repeatable_checksums(self):
        args = perf.parse_args(["--iterations", "20", "--inner-work", "32", "--warmups", "0"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            perf.hot.run_checked([
                str(perf.hot.resolve_compiler()), *perf.COMPILER_FLAGS,
                "-o", str(target), str(Path(perf.__file__).with_name("runtime_target.c")),
            ])
            runs = [perf.run_once(target, None, "baseline", args, root) for _ in range(2)]
        self.assertEqual(runs[0]["target_sink"], runs[1]["target_sink"])
        self.assertGreater(runs[0]["target_elapsed_ns"], 0)
        self.assertGreater(runs[0]["target_peak_rss_kib"], 0)
        self.assertIsNone(runs[0]["missing_events"])

    def test_failed_observer_is_detected_without_waiting_for_full_ready_timeout(self):
        process = subprocess.Popen([sys.executable, "-c", "raise SystemExit(2)"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = perf.OutputCollector(process, 1)
        try:
            with self.assertRaises(perf.hot.BenchmarkError):
                perf.wait_until_ready(process, output, 30)
        finally:
            perf.terminate(process)

    def test_target_timeout_reaps_both_processes(self):
        args = perf.parse_args(["--iterations", "1", "--inner-work", "500000000",
                                "--target-timeout", "0.03"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            perf.hot.run_checked([
                str(perf.hot.resolve_compiler()), *perf.COMPILER_FLAGS,
                "-o", str(target), str(Path(perf.__file__).with_name("runtime_target.c")),
            ])
            observer = root / "fake_observer"
            observer.write_text(
                f"#!{sys.executable}\nimport time\n"
                f"print('{perf.READY_MARKER}', flush=True)\ntime.sleep(30)\n"
            )
            observer.chmod(0o755)
            processes = []
            popen = subprocess.Popen

            def record_process(*args, **kwargs):
                process = popen(*args, **kwargs)
                processes.append(process)
                return process

            with patch.object(perf.subprocess, "Popen", side_effect=record_process):
                with self.assertRaises(perf.hot.BenchmarkError):
                    perf.run_once(target, observer, "print", args, root)
            self.assertEqual(len(processes), 2)
            self.assertTrue(all(process.poll() is not None for process in processes))


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.args = perf.parse_args(["--workloads", "print"])
        self.base = {"median_slowdown": 2, "median_observer_peak_rss_kib": 1024, "loss_pct": 0}
        self.results = {"variants": {
            "base": {"workloads": {"print": self.base}},
            "head": {"workloads": {"print": copy.deepcopy(self.base)}},
        }}

    def test_faster_target_with_more_loss_still_flags_a_regression(self):
        head = self.results["variants"]["head"]["workloads"]["print"]
        head["median_slowdown"] = 1
        head["loss_pct"] = 2
        rows = perf.compare(self.results, self.args)
        self.assertFalse(rows[0]["regression"])
        self.assertTrue(rows[2]["regression"])
        self.assertEqual(rows[2]["unit"], "percentage points")

    def test_memory_and_runtime_thresholds_are_relative_to_base(self):
        head = self.results["variants"]["head"]["workloads"]["print"]
        head["median_slowdown"] = 2.4
        head["median_observer_peak_rss_kib"] = 1536
        rows = perf.compare(self.results, self.args)
        self.assertTrue(rows[0]["regression"])
        self.assertTrue(rows[1]["regression"])
        self.assertAlmostEqual(rows[0]["increase"], 20)
        self.assertEqual(rows[1]["increase"], 50)

    def test_changed_target_checksum_invalidates_measurement(self):
        with self.assertRaises(perf.hot.BenchmarkError):
            perf.summarize([{"target_sink": 2}], [{"target_sink": 1}])


class CpuPlacementTests(unittest.TestCase):
    def test_target_smt_sibling_is_excluded_from_observer_and_harness(self):
        args = perf.parse_args([])
        cores = {0: (0, 0), 1: (0, 1), 2: (0, 0), 3: (0, 2)}
        with patch.object(perf.os, "sched_getaffinity", return_value=set(cores)), \
                patch.object(perf, "core_key", side_effect=cores.__getitem__):
            cpus = perf.select_cpus(args)
        self.assertEqual(cpus["target"], 0)
        self.assertEqual(cpus["observer"], 1)
        self.assertEqual(cpus["harness"], [3])

    def test_cpu_outside_allowed_set_is_rejected(self):
        args = perf.parse_args(["--target-cpu", "9"])
        with patch.object(perf.os, "sched_getaffinity", return_value={0, 1}):
            with self.assertRaises(perf.hot.BenchmarkError):
                perf.select_cpus(args)


if __name__ == "__main__":
    unittest.main()
