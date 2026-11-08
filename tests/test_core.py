import errno
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from metalbench.cli import parser
from metalbench.netlink import Netdev, attribute, decode_attributes, integer, number
from metalbench.runner import compare_rcu, cpulist, plan
from metalbench.state import Backend, Transaction, boot_id, normalize
from metalbench.stats import distribution, paired_effect, summarize


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = {"kind": "file", "path": "/sys/devices/system/cpu/cpu2/power/pm_qos_resume_latency_us"}
        self.backend = Backend(self.root)
        self.file = self.backend.file_path(self.spec)
        self.file.parent.mkdir(parents=True)
        self.file.write_text("0\n")
        self.journal = self.root / "journal.json"

    def test_restore_on_measurement_failure(self):
        with self.assertRaisesRegex(RuntimeError, "measurement"):
            with Transaction(self.journal, self.backend) as txn:
                txn.apply(self.spec, "1")
                self.assertEqual(self.file.read_text().strip(), "1")
                raise RuntimeError("measurement failed")
        self.assertEqual(self.file.read_text().strip(), "0")
        self.assertTrue(json.loads(self.journal.read_text())["restored"])

    def test_journal_precedes_write_and_recovery(self):
        original_write = self.backend.write
        def observe(spec, value):
            journal = json.loads(self.journal.read_text())
            self.assertEqual(journal["entries"][0]["original"], "0")
            self.assertEqual(journal["entries"][0]["requested"], "1")
            original_write(spec, value)
        txn = Transaction(self.journal, self.backend)
        with patch.object(self.backend, "write", side_effect=observe):
            txn.apply(self.spec, "1")
        # Simulate process termination without __exit__.
        Transaction.recover(self.journal, self.backend)
        self.assertEqual(self.file.read_text().strip(), "0")

    def test_same_boot_guard(self):
        txn = Transaction(self.journal, self.backend)
        txn.apply(self.spec, "1")
        txn.data["boot_id"] = "previous-boot"
        txn.save()
        with self.assertRaisesRegex(ValueError, "this boot"):
            Transaction.recover(self.journal, self.backend)
        self.assertEqual(self.file.read_text().strip(), "1")

    def test_clamping_is_rejected_and_rolled_back(self):
        original_write = self.backend.write
        def clamp(spec, value):
            original_write(spec, "2" if value == "1" else value)
        with patch.object(self.backend, "write", side_effect=clamp):
            with self.assertRaisesRegex(OSError, "readback mismatch"):
                with Transaction(self.journal, self.backend) as txn:
                    txn.apply(self.spec, "1")
        self.assertEqual(self.file.read_text().strip(), "0")

    def test_partial_write_failure_is_restored(self):
        original_write = self.backend.write
        def partial(spec, value):
            original_write(spec, value)
            if value == "1":
                raise OSError(errno.EIO, "partial write")
        with patch.object(self.backend, "write", side_effect=partial):
            with self.assertRaises(OSError):
                with Transaction(self.journal, self.backend) as txn:
                    txn.apply(self.spec, "1")
        self.assertEqual(self.file.read_text().strip(), "0")

    def test_restore_failure_remains_recoverable(self):
        txn = Transaction(self.journal, self.backend)
        txn.apply(self.spec, "1")
        with patch.object(self.backend, "write", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(RuntimeError, "RESTORATION FAILED"):
                txn.restore()
        self.assertFalse(json.loads(self.journal.read_text())["restored"])
        Transaction.recover(self.journal, self.backend)
        self.assertEqual(self.file.read_text().strip(), "0")

    def test_scope_guard(self):
        for path in ("/etc/shadow", "/sys/devices/system/cpu/../../etc/shadow",
                     "/sys/devices/system/cpu/intel_uncore_frequency/../min_freq_khz"):
            with self.assertRaises(ValueError):
                self.backend.read({"kind": "file", "path": path})

    def test_reverse_restore_order_and_one_snapshot(self):
        second = {"kind": "file", "path": "/sys/devices/system/cpu/cpu3/power/pm_qos_resume_latency_us"}
        p = self.backend.file_path(second)
        p.parent.mkdir(parents=True); p.write_text("7")
        txn = Transaction(self.journal, self.backend)
        txn.apply(self.spec, "1"); txn.apply(second, "2"); txn.apply(self.spec, "3")
        self.assertEqual(len(txn.data["entries"]), 2)
        writes, original = [], self.backend.write
        def log(spec, value):
            writes.append((spec["path"], value)); original(spec, value)
        with patch.object(self.backend, "write", side_effect=log):
            txn.restore()
        self.assertEqual(writes, [(second["path"], "7"), (self.spec["path"], "0")])

    def test_mask_normalization(self):
        self.assertEqual(normalize("2=00FF;0=000f\n"), "0=f;2=ff")
        self.assertEqual(normalize("enabled"), "1")

    def test_napi_mode_and_original_thread_affinity_restored(self):
        state = {"id": 123, "ifindex": 7, "pid": 100, "threaded": 1,
                 "defer-hard-irqs": 2, "gro-flush-timeout": 20000, "irq-suspend-timeout": 0}
        affinities = {100: {4, 5}}
        class FakeNetdev:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def get(self, _):
                return state.copy()
            def set(self, _id, settings):
                state.update(settings)
                state["pid"] += 1
                affinities[state["pid"]] = {0, 1}
        def get_affinity(pid):
            return affinities[pid]
        def set_affinity(pid, cpus):
            affinities[pid] = set(cpus)
        spec = {"kind": "napi", "id": 123, "ifindex": 7}
        with patch("metalbench.state.Netdev", FakeNetdev), \
             patch("metalbench.state.os.sched_getaffinity", side_effect=get_affinity), \
             patch("metalbench.state.os.sched_setaffinity", side_effect=set_affinity):
            with Transaction(self.journal, self.backend) as txn:
                original = self.backend.read(spec)
                txn.apply(spec, {"settings": {"threaded": 2}, "affinity": [6]})
                self.assertEqual(affinities[state["pid"]], {6})
            self.assertEqual(self.backend.read(spec), original)
            self.assertEqual(affinities[state["pid"]], {4, 5})

    def test_napi_reused_id_refuses_mutation(self):
        class FakeNetdev:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def get(self, _):
                return {"id": 123, "ifindex": 999}
            def set(self, *_):
                raise AssertionError("must not mutate an unrelated interface")
        with patch("metalbench.state.Netdev", FakeNetdev):
            with self.assertRaisesRegex(ValueError, "interface changed"):
                self.backend.write({"kind": "napi", "id": 123, "ifindex": 7}, {"settings": {"threaded": 0}})


class NetlinkTests(unittest.TestCase):
    def test_attribute_width_and_padding(self):
        attrs = decode_attributes(attribute(1, b"ab\0") + integer(6, 20000, wide=True))
        self.assertEqual(attrs[1], b"ab\0")
        self.assertEqual(number(attrs[6]), 20000)
        self.assertEqual(len(attrs[6]), 8)

    def test_bad_lengths(self):
        for data in (b"a", struct.pack("=HH", 3, 1), struct.pack("=HH", 100, 1)):
            with self.assertRaises(ValueError):
                decode_attributes(data)

    def fake(self, messages):
        class Sock:
            def sendto(self, *_):
                pass
            def recvmsg(self, *_):
                return messages.pop(0), [], 0, (0, 0)
        dev = Netdev.__new__(Netdev)
        dev.sock, dev.sequence = Sock(), 0
        return dev

    @staticmethod
    def msg(kind, payload, flags=0):
        return struct.pack("=IHHII", 16+len(payload), kind, flags, 1, 0)+payload

    def test_data_and_ack_in_one_datagram(self):
        reply = self.msg(42, struct.pack("=BBH", 11, 1, 0) + integer(2, 123))
        reply += self.msg(2, struct.pack("=i", 0))
        dev = self.fake([reply])
        self.assertEqual(number(dev.request(42, 11)[0][2]), 123)

    def test_kernel_error(self):
        dev = self.fake([self.msg(2, struct.pack("=i", -errno.EOPNOTSUPP))])
        with self.assertRaises(OSError) as context:
            dev.request(42, 14)
        self.assertEqual(context.exception.errno, errno.EOPNOTSUPP)

    def test_interrupted_dump_rejected(self):
        dev = self.fake([self.msg(3, struct.pack("=i", 0), flags=0x10)])
        with self.assertRaises(OSError):
            dev.request(42, 11, dump=True)


def fixture_host():
    return {"allowed_cpus": list(range(8)), "kernel": "7.0.0-1012-aws", "isolated": "2-5",
            "cpus": [{"cpu": c, "siblings": str(c), "resume_latency_us": "0"} for c in range(8)],
            "uncore": {}, "resctrl": {}, "epoll_params": {}, "cmdline": "nohz_full=2-5 rcu_nocbs=2-5",
            "rcu_nocb_poll": False, "interface": None}


def fixture_args(case, *extra):
    args = parser().parse_args(["plan", case, "--cpu", "2", *extra])
    args.gap_us = 100 if case in {"idle", "elc"} else 0
    return args


class PlanTests(unittest.TestCase):
    def test_kernel_major_does_not_imply_elc(self):
        args = fixture_args("elc", "--uncore-dir", "/sys/devices/system/cpu/intel_uncore_frequency/uncore00", "--floor-khz", "1800000")
        result = plan(args, fixture_host())
        self.assertFalse(result["supported"])
        self.assertTrue(any("does not expose" in e for e in result["reasons"]))

    def test_idle_only_changes_target_cpu(self):
        result = plan(fixture_args("idle"), fixture_host())
        self.assertTrue(result["supported"])
        self.assertEqual(result["monitor_cpu"], 0)
        changes = result["variants"][1]["changes"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["resource"]["path"], "/sys/devices/system/cpu/cpu2/power/pm_qos_resume_latency_us")
        self.assertEqual(changes[0]["value"], "1")

    def test_tlb_rejects_smt_sibling(self):
        host = fixture_host()
        host["cpus"][2]["siblings"] = host["cpus"][3]["siblings"] = "2-3"
        result = plan(fixture_args("tlb", "--noise-cpu", "3"), host)
        self.assertFalse(result["supported"])

    def test_rcu_label_verified(self):
        result = plan(fixture_args("rcu", "--rcu-state", "poll"), fixture_host())
        self.assertFalse(result["supported"])
        self.assertTrue(any("boot has RCU state" in s for s in result["reasons"]))

    def test_rcu_offload_required(self):
        host = fixture_host(); host["cmdline"] = "quiet"
        self.assertFalse(plan(fixture_args("rcu"), host)["supported"])

    def test_hardware_network_rejects_local_sender(self):
        result = plan(fixture_args("napi", "--local-peer", "--peer-cpu", "6"), fixture_host())
        self.assertFalse(result["supported"])
        self.assertTrue(any("remote sender" in s for s in result["reasons"]))

    def test_napi_plan_has_distinct_queue_local_treatments(self):
        host = fixture_host()
        host["interface"] = {"ifindex": 7, "route": {"stdout": '[{"addr_info":[{"family":"inet","local":"10.0.0.1"}]}]'},
                             "napis": [{"id": 123, "ifindex": 7, "threaded": 0, "defer-hard-irqs": 2,
                                        "gro-flush-timeout": 20000, "irq-suspend-timeout": 0}]}
        args = fixture_args("napi", "--interface", "ens5", "--napi-id", "123", "--address", "10.0.0.1",
                            "--peer", "sender", "--noise-cpu", "3", "--modes", "irq,software,epoll,threaded")
        result = plan(args, host)
        self.assertTrue(result["supported"], result["reasons"])
        variants = {v["name"]: v for v in result["variants"]}
        self.assertEqual(variants["irq"]["changes"][0]["value"]["settings"]["gro-flush-timeout"], 0)
        self.assertEqual(variants["software"]["changes"][0]["value"]["settings"]["gro-flush-timeout"], 20000)
        self.assertEqual(variants["epoll"]["changes"][0]["value"]["settings"]["irq-suspend-timeout"], 100000)
        self.assertEqual(variants["threaded"]["changes"][0]["value"]["affinity"], [3])
        for v in variants.values():
            self.assertEqual(v["changes"][0]["resource"], {"kind": "napi", "id": 123, "ifindex": 7})

    def test_io_mask_preserves_other_cache_domains(self):
        host = fixture_host()
        host["resctrl"] = {"io_alloc": "enabled", "io_alloc_cbm": "0=ffff;1=ffff", "cbm_mask": "ffff"}
        host["interface"] = {"route": {"stdout": '[{"addr_info":[{"family":"inet","local":"10.0.0.1"}]}]'}}
        args = fixture_args("io-cache", "--io-mask", "0=00ff", "--noise-cpu", "3", "--interface", "ens5",
                            "--address", "10.0.0.1", "--peer", "sender")
        result = plan(args, host)
        self.assertTrue(result["supported"], result["reasons"])
        self.assertEqual(result["variants"][1]["changes"][0]["value"], "0=ff;1=ffff")

    def test_cpu_parser(self):
        self.assertEqual(cpulist("0-2,7"), {0, 1, 2, 7})
        for text in ("4-2", "1-2-3", "-1"):
            with self.assertRaises(ValueError):
                cpulist(text)


class StatisticsTests(unittest.TestCase):
    def test_exact_nearest_rank_and_tail_warning(self):
        result = distribution(list(range(1, 10001)))
        self.assertEqual(result["p99"], 9900)
        self.assertEqual(result["p99.9"], 9990)
        self.assertEqual(result["p99.99"], 9999)
        self.assertEqual(result["insufficient_tail_samples"], ["p99.9", "p99.99"])
        self.assertEqual(distribution([]), {"count": 0})

    def test_invalid_values_rejected(self):
        for values in ([-1], [float("nan")], [float("inf")]):
            with self.assertRaises(ValueError):
                distribution(values)

    def test_packet_loss_is_reported(self):
        result = summarize({"kind": "udp-client", "sent": 10, "received": 8, "lost": 2, "rtt_ns": [10]*8})
        self.assertEqual(result["loss_rate"], .2)
        self.assertTrue(any("censored" in w for w in result["warnings"]))

    def test_weak_noise_cannot_hide(self):
        result = summarize({"noise": "thread", "noise_operations": 0, "batch_ns": [10]})
        self.assertTrue(any("too weak" in w for w in result["warnings"]))

    def test_paired_rounds_require_all_replicates(self):
        trials = []
        for i in range(5):
            for label, value in (("A", 100), ("B", 80), ("B", 80), ("A", 100)):
                trials.append({"round": i, "variant": label, "status": "ok",
                               "summary": {"metrics": {"rtt_ns": {"p99.9": value}}}})
        effect = paired_effect(trials, "A", "B", "rtt_ns")
        self.assertAlmostEqual(effect["median_change_percent"], -20)
        self.assertEqual(effect["paired_rounds"], 5)
        trials[0]["status"] = "invalid"
        self.assertEqual(paired_effect(trials, "A", "B", "rtt_ns")["paired_rounds"], 4)


class RCUComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = [self.root / "wake", self.root / "poll"]
        args = fixture_args("rcu")
        for index, directory in enumerate(self.paths):
            directory.mkdir()
            host = fixture_host() | {"hostname": "fixture", "machine": "x86_64", "boot_id": f"boot-{index}",
                                     "online": "0-7", "nohz_full": "2-5"}
            host["rcu_nocb_poll"] = bool(index)
            if index:
                host["cmdline"] += " rcu_nocb_poll"
            (directory / "host.json").write_text(json.dumps(host))
            (directory / "provenance.json").write_text(json.dumps({"worker_sha256": "fixture-only"}))
            report = {"case": "rcu", "status": "complete", "parameters": vars(args),
                      "trials": [{"summary": {"metrics": {"operation_ns": {"p99.9": 10-index*2}}, "warnings": []}}]}
            (directory / "report.json").write_text(json.dumps(report))

    def compare(self):
        return compare_rcu(*self.paths, self.root / "comparison.json")

    def change_candidate(self, edit):
        path = self.paths[1] / "host.json"
        host = json.loads(path.read_text()); edit(host); path.write_text(json.dumps(host))

    def test_valid_two_boot_descriptive_comparison(self):
        result = self.compare()
        self.assertAlmostEqual(result["change_percent"], -20)
        self.assertIn("descriptive", result["interpretation"])

    def test_other_boot_change_rejected(self):
        self.change_candidate(lambda host: host.update(cmdline=host["cmdline"] + " idle=poll"))
        with self.assertRaisesRegex(ValueError, "boot arguments"):
            self.compare()

    def test_runtime_tuning_change_rejected(self):
        self.change_candidate(lambda host: host["cpus"][2].update(resume_latency_us="1"))
        with self.assertRaisesRegex(ValueError, "runtime tuning"):
            self.compare()

    def test_same_boot_rejected(self):
        self.change_candidate(lambda host: host.update(boot_id="boot-0"))
        with self.assertRaisesRegex(ValueError, "different boots"):
            self.compare()


if __name__ == "__main__":
    unittest.main()
