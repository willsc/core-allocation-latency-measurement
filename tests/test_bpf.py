import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from metalbench.bpf import BPFCollector, GROUPS, capabilities, parse_output, program, selection
from metalbench.state import Backend, Transaction
from metalbench.stats import summarize


def config():
    return {"cpus": [2], "groups": ["irq", "softirq", "sched", "tlb", "rcu", "idle"],
            "bin_ms": 100, "max_bins": 512, "stacks": True, "hz": 99,
            "capabilities": {"binary": "bpftrace"}, "skipped": {}}


def jsonl(*records):
    return "\n".join(json.dumps(record) for record in records)


class CapabilityTests(unittest.TestCase):
    def test_required_fields_and_missing_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for event, fields in GROUPS["sched"].items():
                fmt = root / "events" / event / "format"
                fmt.parent.mkdir(parents=True)
                fmt.write_text("\n".join(f"field:int {field}; offset:0; size:4; signed:1;" for field in fields))
            with patch("metalbench.bpf.shutil.which", return_value="/usr/bin/bpftrace"), \
                 patch("metalbench.bpf.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "bpftrace v0.20.2", "")):
                cap = capabilities([tmp])
                self.assertTrue(cap["version_ok"])
                self.assertTrue(cap["groups"]["sched"]["available"])
                self.assertFalse(cap["groups"]["rcu"]["available"])
                self.assertFalse(cap["attachment_tested"])
                (root / "events/sched/sched_wakeup/format").write_text("field:int pid;")
                cap = capabilities([tmp])
                self.assertFalse(cap["groups"]["sched"]["available"])
                self.assertIn("target_cpu", cap["groups"]["sched"]["missing"][0])

    def test_old_tool_version_is_not_supported(self):
        with patch("metalbench.bpf.shutil.which", return_value="bpftrace"), \
             patch("metalbench.bpf.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "bpftrace v0.19.0", "")):
            self.assertFalse(capabilities([])["version_ok"])

    def test_selection_reports_skips_and_rejects_invalid_cpu_scope(self):
        args = SimpleNamespace(cpu=2, bpf_cpus=None, bpf_events="sched,rcu", bpf_stacks=False,
                               bpf_hz=99, bpf_bin_ms=100, bpf_max_bins=512)
        cap = {"binary": "bpftrace", "version_ok": True, "groups": {
            "sched": {"available": True, "missing": []}, "rcu": {"available": False, "missing": ["not compiled"]}}}
        with patch("metalbench.bpf.os.sched_getaffinity", return_value={0, 1, 2, 3, 4, 5}):
            result = selection(args, cap)
            self.assertTrue(result["supported"])
            self.assertEqual(result["groups"], ["sched"])
            self.assertEqual(result["skipped"], {"rcu": ["not compiled"]})
            args.bpf_events = "rcu"
            self.assertFalse(selection(args, cap)["supported"])
            args.bpf_events, args.bpf_stacks = "none", True
            self.assertTrue(selection(args, cap)["supported"])
            args.bpf_cpus = "0-4"
            with self.assertRaisesRegex(ValueError, "one to four"):
                selection(args, cap)
            args.bpf_cpus = "99"
            with self.assertRaises(ValueError):
                selection(args, cap)
            args.bpf_cpus, args.bpf_events = None, "sched,sched"
            with self.assertRaisesRegex(ValueError, "unique"):
                selection(args, cap)


class OutputTests(unittest.TestCase):
    def test_final_aggregates_and_clock_markers(self):
        parsed = parse_output(jsonl(
            {"type": "printf", "data": "METALBENCH_BPF_READY 1000000000\n"},
            {"type": "printf", "data": "METALBENCH_BPF_END 1250000000\n"},
            {"type": "map", "data": {"@irq_count": {"2, 1": 3, "1, 0": 7}, "@origin_ns": 1000000000}},
            {"type": "map", "data": {"@kernel_stacks": {"\n leaf\n root\n": 2, "": 1}}}))
        self.assertEqual(parsed["warnings"], [])
        self.assertEqual(parsed["markers"], {"READY": 1000000000, "END": 1250000000})
        self.assertEqual(parsed["series"]["irq_count"], [
            {"cpu": 1, "bin": 0, "value": 7}, {"cpu": 2, "bin": 1, "value": 3}])
        self.assertEqual(parsed["stacks"]["kernel_stacks"][""], 1)
        self.assertNotIn("tlb_count", parsed["series"])

    def test_loss_overflow_and_helpers_are_not_silent(self):
        parsed = parse_output(jsonl(
            {"type": "map", "data": {"@overflow": 4}},
            {"type": "lost_events", "data": 5},
            {"type": "helper_error", "helper": "get_stackid", "retcode": -14, "msg": "Bad address"}) + "\n{", "diagnostic\n")
        warnings = " ".join(parsed["warnings"])
        for text in ("time-bin limit", "lost_events", "get_stackid", "truncated", "stderr"):
            self.assertIn(text, warnings)
        self.assertEqual(parsed["series"], {})

    def test_malformed_records_and_maps_survive_for_diagnostics(self):
        parsed = parse_output(jsonl(None, [], {"type": "map", "data": []},
            {"type": "map", "data": {"@irq_count": {"broken": 1, "2, 1": float("nan"), "2, 2": True},
                                     "@softirq_count": 7, "@user_stacks": {"bad": -1}, "@kernel_stacks": []}},
            {"type": "printf", "data": "METALBENCH_BPF_READY 10"},
            {"type": "printf", "data": "METALBENCH_BPF_END 5"}))
        self.assertEqual(parsed["series"], {})
        self.assertEqual(parsed["stacks"], {"kernel_stacks": {}, "user_stacks": {}})
        self.assertIn("invalid BPF capture clock markers", parsed["warnings"])
        self.assertGreaterEqual(len(parsed["warnings"]), 6)

    def test_duplicate_maps_are_reported(self):
        record = {"type": "map", "data": {"@irq_count": {"2, 0": 1}}}
        self.assertIn("duplicate final map @irq_count", parse_output(jsonl(record, record))["warnings"])

    def test_sample_offsets_never_enter_latency_statistics(self):
        summary = summarize({"batch_ns": [1, 2, 3], "sample_offset_ns": [10, 20, 30],
                             "reply_offset_ns": [100, 200, 300]})
        self.assertEqual(set(summary["metrics"]), {"batch_ns"})

    def test_generated_probe_scope_and_bounded_monotonic_buckets(self):
        code = program(config())
        self.assertIn("args->target_cpu == 2", code)
        self.assertIn("tracepoint:sched:sched_switch {", code)  # migration cleanup on all CPUs
        self.assertIn("delete(@wake[args->next_pid])", code)
        self.assertIn("$bucket < 512", code)
        self.assertIn("@overflow = count()", code)
        self.assertIn("nsecs(monotonic)", code)
        self.assertIn("profile:hz:99", code)
        self.assertNotIn("interval:", code)
        self.assertNotIn("clear(@irq_count)", code)
        invalid = config(); invalid["cpus"] = ["2; exit()"]
        with self.assertRaises(ValueError):
            program(invalid)


class CollectorTests(unittest.TestCase):
    """Run a fake tracer child to verify lifecycle without attaching kernel probes."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fake_config(self, records=(), fail=False, end=True):
        script = self.root / "fake-bpftrace"
        script.write_text("#!/usr/bin/env python3\n"
            "import json, signal, sys, time\n"
            "def emit(record):\n    print(json.dumps(record), flush=True)\n"
            "def stop(*args):\n"
            f"    for record in {list(records)!r}: emit(record)\n"
            + ("    emit({'type': 'printf', 'data': 'METALBENCH_BPF_END 1250000000'})\n" if end else "")
            + "    sys.exit(0)\n"
            "signal.signal(signal.SIGINT, stop)\n"
            + ("print('attach denied', file=sys.stderr)\nsys.exit(2)\n" if fail else "")
            + "emit({'type': 'printf', 'data': 'METALBENCH_BPF_READY 1000000000'})\n"
            "while True: time.sleep(.1)\n")
        script.chmod(0o755)
        cfg = config(); cfg["capabilities"]["binary"] = str(script)
        return cfg

    def test_detach_flushes_aggregates_and_stop_is_idempotent(self):
        cfg = self.fake_config([{"type": "map", "data": {"@tlb_count": {"2, 0": 8}}}])
        with BPFCollector(cfg, self.root) as collector:
            collector.start()
            self.assertIsNone(collector.process.poll())
        collector.stop()
        result = json.loads((self.root / "bpf/capture.json").read_text())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["series"]["tlb_count"][0]["value"], 8)
        self.assertIsNotNone(collector.process.poll())
        self.assertTrue((self.root / "bpf/program.bt").exists())

    def test_failed_attach_preserves_diagnostics_and_restores_settings(self):
        cfg = self.fake_config(fail=True)
        spec = {"kind": "file", "path": "/sys/devices/system/cpu/cpu2/power/pm_qos_resume_latency_us"}
        backend = Backend(self.root)
        setting = backend.file_path(spec)
        setting.parent.mkdir(parents=True); setting.write_text("0\n")
        with self.assertRaisesRegex(RuntimeError, "before capture"):
            with Transaction(self.root / "settings.json", backend) as txn, BPFCollector(cfg, self.root) as collector:
                txn.apply(spec, "1")
                collector.start()
        self.assertEqual(setting.read_text().strip(), "0")
        self.assertEqual(collector.result["status"], "failed")
        self.assertIn("attach denied", (self.root / "bpf/stderr.txt").read_text())

    def test_lost_events_make_capture_partial(self):
        with BPFCollector(self.fake_config([{"type": "lost_events", "data": 3}]), self.root) as collector:
            collector.start()
        self.assertEqual(collector.result["status"], "partial")

    def test_missing_end_is_a_failed_capture(self):
        with self.assertRaisesRegex(RuntimeError, "BPF capture failed"):
            with BPFCollector(self.fake_config(end=False), self.root) as collector:
                collector.start()
        self.assertEqual(collector.result["status"], "failed")

    def test_disabled_collector_creates_no_artifacts(self):
        with BPFCollector(None, self.root) as collector:
            collector.start(); collector.stop()
        self.assertFalse((self.root / "bpf").exists())


if __name__ == "__main__":
    unittest.main()
