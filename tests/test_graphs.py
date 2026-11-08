import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from metalbench.graphs import envelope, flame_tree, fold_stacks, generate, series_points


class GraphDataTests(unittest.TestCase):
    def test_display_envelope_preserves_a_single_tail_spike(self):
        values = [1] * 10001
        values[4999] = 999999
        x, median, peaks = envelope(values, [i / 100 for i in range(len(values))], limit=100)
        self.assertLessEqual(len(x), 100)
        self.assertEqual(max(peaks), 999999)
        self.assertEqual(max(median), 1)
        self.assertEqual(x[-1], 100)
        self.assertEqual(envelope([]), ([], [], []))

    def test_flame_paths_are_root_first_and_preserve_unknown_frames(self):
        folded = fold_stacks({"\n ffffffff12345678 leaf+1\n 0000000012345678 root+2\n": 5,
                              "\n leaf+1\n root+2\n": 2,
                              "\n 0x12345678\n": 3, "": 1})
        self.assertEqual(folded["root+2;leaf+1"], 7)
        self.assertEqual(folded["0x12345678"], 3)
        self.assertEqual(folded["[empty or unavailable stack]"], 1)
        tree = flame_tree(folded)
        self.assertEqual(tree["value"], 11)
        self.assertEqual(tree["children"]["root+2"]["children"]["leaf+1"]["value"], 7)

    def test_completed_and_partial_series_have_distinct_missing_data(self):
        capture = {"status": "complete", "config": {"bin_ms": 100},
                   "markers": {"READY": 1000000000, "END": 1250000000},
                   "series": {"irq_count": [{"cpu": 2, "bin": 0, "value": 2},
                                            {"cpu": 2, "bin": 2, "value": 3}]}}
        x, y = series_points(capture, "irq_count", 2)
        self.assertAlmostEqual(x[-1], .225)
        self.assertEqual(y[:2], [20, 0])
        self.assertAlmostEqual(y[2], 60)  # final 50ms bucket, not 100ms
        capture["status"] = "partial"
        _, y = series_points(capture, "irq_count", 2)
        self.assertTrue(math.isnan(y[1]))
        self.assertEqual(series_points(capture, "irq_count", 3), ([], []))

    def test_duration_and_maximum_axes_use_different_units(self):
        capture = {"status": "complete", "config": {"bin_ms": 100}, "series": {
            "runq_ns": [{"cpu": 2, "bin": 0, "value": 10000}],
            "runq_max": [{"cpu": 2, "bin": 0, "value": 8000}]}}
        self.assertEqual(series_points(capture, "runq_ns", 2)[1], [100])  # µs per second
        self.assertEqual(series_points(capture, "runq_max", 2)[1], [8])  # µs


@unittest.skipUnless(importlib.util.find_spec("matplotlib"), "optional matplotlib not installed")
class GraphExportTests(unittest.TestCase):
    def fixture(self, root):
        report = {"case": "network <script>alert(1)</script>", "status": "partial", "diagnostic": True,
                  "primary_metric": "rtt_ns", "trials": [], "warnings": ["<unavailable>"]}
        for index in range(2):
            directory = root / f"{index:03d}-current"
            directory.mkdir()
            report["trials"].append({"index": index, "variant": "current", "directory": directory.name,
                "status": "ok", "summary": {"metrics": {"rtt_ns": {"p50": 100, "p99": 300}},
                                            "warnings": ["insufficient tail samples"]}})
            raw = {"kind": "udp-client", "rtt_ns": [100, 300, 200],
                   "start_monotonic_ns": 1000000000, "elapsed_ns": 250000000}
            if index == 0:
                raw["reply_offset_ns"] = [1000000, 3000000, 2000000]  # reordered arrivals
            (directory / "raw.json").write_text(json.dumps(raw))
        capture = {"status": "partial", "config": {"bin_ms": 100, "skipped": {"rcu": ["absent"]}},
                   "markers": {"READY": 1000000000, "END": 1250000000},
                   "warnings": ["lost_events: 2"],
                   "series": {"irq_count": [{"cpu": 2, "bin": 0, "value": 10},
                                            {"cpu": 2, "bin": 2, "value": 3}]},
                   "stacks": {"kernel_stacks": {"\nleaf\nroot\n": 3}, "user_stacks": {"": 2}}}
        (root / "000-current/bpf").mkdir()
        (root / "000-current/bpf/capture.json").write_text(json.dumps(capture))
        (root / "report.json").write_text(json.dumps(report))
        return report

    def test_offline_exports_preserve_warnings_and_separate_remote_clock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            with patch.dict(os.environ, {"MPLCONFIGDIR": str(root / "mplcache")}):
                import matplotlib
                matplotlib.use("Agg")
                import matplotlib.pyplot  # initialise wrapper metadata before patching Axes
                with patch("matplotlib.axes.Axes.axvspan") as span:
                    page = generate(root)
                    # A remote sender's monotonic origin must not be overlaid on receiver BPF.
                    span.assert_not_called()
            output = page.parent
            html = page.read_text()
            self.assertIn("&lt;script&gt;", html)
            self.assertNotIn("<script>", html)
            self.assertNotIn("https://", html)
            self.assertIn("lost_events", html)
            self.assertIn("insufficient tail samples", html)
            self.assertIn("unavailable BPF groups: rcu", html)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertTrue(manifest["diagnostic"])
            self.assertEqual(len(manifest["plots"]), 6)
            for plot in manifest["plots"]:
                self.assertIn("<svg", (output / plot["svg"]).read_text())
                self.assertEqual((output / plot["png"]).read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
            self.assertIn("Seconds since sender measurement start", (output / "trial-000-latency.svg").read_text())
            self.assertIn("Sample index (timestamps unavailable)", (output / "trial-001-latency.svg").read_text())
            self.assertEqual((output / "trial-000-kernel_stacks.folded").read_text(), "root;leaf 3\n")
            self.assertIn("[empty or unavailable stack]", (output / "trial-000-user_stacks.folded").read_text())
            with self.assertRaises(FileExistsError):
                generate(root)

    def test_trial_path_cannot_escape_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self.fixture(root)
            report["trials"][0]["directory"] = "../outside"
            (root / "report.json").write_text(json.dumps(report))
            with patch.dict(os.environ, {"MPLCONFIGDIR": str(root / "mplcache")}):
                with self.assertRaisesRegex(ValueError, "escapes run directory"):
                    generate(root)


if __name__ == "__main__":
    unittest.main()
