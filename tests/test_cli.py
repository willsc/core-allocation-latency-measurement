import json
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from metalbench.cli import parser
from metalbench.runner import run

ROOT = Path(__file__).resolve().parents[1]
CPUS = sorted(os.sched_getaffinity(0))


@unittest.skipUnless((ROOT / "build/latprobe").exists() and len(CPUS) >= 3, "requires built worker and three CPUs")
class CLITests(unittest.TestCase):
    def test_partial_bpf_capture_propagates_to_run_status(self):
        class PartialCollector:
            def __init__(self, *_):
                self.result = {"status": "partial", "warnings": ["lost_events: 2"]}
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def start(self):
                pass
            def stop(self):
                pass
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            args = parser().parse_args(["run", "tlb", "--cpu", str(CPUS[1]), "--noise-cpu", str(CPUS[2]),
                                       "--samples", "1000", "--gap-us", "100", "--warmup-ms", "10",
                                       "--rounds", "1", "--memory-mb", "1", "--bpf", "--output", str(out)])
            with patch("metalbench.runner.BPFCollector", PartialCollector), \
                 patch("metalbench.runner.bpf_selection", return_value={"reasons": [], "skipped": {}}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 4)
            report = json.loads((out / "report.json").read_text())
            self.assertEqual(report["status"], "partial")
            self.assertTrue(report["diagnostic"])
            self.assertTrue(all(t["bpf"]["status"] == "partial" for t in report["trials"]))
            self.assertIn("lost_events", (out / "report.md").read_text())

    def test_tlb_end_to_end_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            proc = subprocess.run(["python3", "-m", "metalbench", "run", "tlb",
                                   "--cpu", str(CPUS[1]), "--noise-cpu", str(CPUS[2]),
                                   "--samples", "1000", "--gap-us", "100", "--warmup-ms", "10",
                                   "--rounds", "1", "--memory-mb", "1", "--output", str(out)],
                                  cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            report = json.loads((out / "report.json").read_text())
            self.assertEqual(report["status"], "complete")
            self.assertEqual(len(report["trials"]), 6)
            for trial in report["trials"]:
                d = out / trial["directory"]
                self.assertTrue(json.loads((d / "settings.json").read_text())["restored"])
                self.assertEqual(len(json.loads((d / "raw.json").read_text())["batch_ns"]), 1000)
                self.assertTrue((d / "before.json").exists())
                self.assertTrue((d / "after.json").exists())
            self.assertIn("insufficient", (out / "report.md").read_text())

    def test_unsupported_elc_produces_skipped_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            proc = subprocess.run(["python3", "-m", "metalbench", "run", "elc",
                                   "--cpu", str(CPUS[1]), "--uncore-dir",
                                   "/sys/devices/system/cpu/intel_uncore_frequency/missing-domain",
                                   "--floor-khz", "1800000", "--output", str(out)],
                                  cwd=ROOT, capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
            report = json.loads((out / "report.json").read_text())
            self.assertEqual(report["status"], "skipped")
            self.assertEqual(report["trials"], [])


if __name__ == "__main__":
    unittest.main()
