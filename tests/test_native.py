import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build/latprobe"
CPUS = sorted(os.sched_getaffinity(0))


@unittest.skipUnless(BIN.exists() and len(CPUS) >= 3, "requires built worker and three available CPUs")
class NativeTests(unittest.TestCase):
    def worker(self, mode, *args):
        proc = subprocess.run([str(BIN), mode, "--cpu", str(CPUS[1]), *map(str, args)],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_memory_and_both_address_space_modes(self):
        for noise in ("none", "thread", "process"):
            raw = self.worker("memory", "--noise", noise, "--noise-cpu", CPUS[2],
                              "--samples", 1000, "--gap-us", 100, "--size-mb", 1, "--warmup-ms", 10)
            self.assertEqual(len(raw["batch_ns"]), 1000)
            self.assertEqual(raw["samples"], 1000)
            self.assertEqual(raw["loads_per_batch"], 64)
            self.assertTrue(all(v > 0 for v in raw["batch_ns"]))
            self.assertEqual(len(raw["sample_offset_ns"]), raw["samples"])
            self.assertEqual(raw["sample_offset_ns"], sorted(raw["sample_offset_ns"]))
            self.assertLessEqual(max(raw["sample_offset_ns"]), raw["elapsed_ns"])
            for b, w, total in zip(raw["batch_ns"], raw["wake_lateness_ns"], raw["wakeup_plus_batch_ns"]):
                self.assertEqual(b + w, total)
            if noise != "none":
                self.assertGreater(raw["noise_operations"], 100)

    def test_bad_native_option(self):
        proc = subprocess.run([str(BIN), "memory", "--samples", "-1"], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_identity(self):
        self.assertEqual(self.worker("identity")["protocol"], 1)

    def network_available(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]
        except PermissionError:
            self.skipTest("sandbox blocks UDP sockets; rerun tests outside sandbox")

    def test_rcu_socket_lifetime_worker(self):
        self.network_available()
        raw = self.worker("rcu", "--samples", 100, "--warmup-ms", 10)
        self.assertEqual(len(raw["operation_ns"]), 100)
        self.assertEqual(len(raw["sample_offset_ns"]), 100)
        self.assertEqual(raw["kind"], "rcu")

    def test_udp_pacing_loss_accounting_and_quiet_packets(self):
        port = self.network_available()
        source_port = self.network_available()
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / "ready"
            echo = subprocess.Popen([str(BIN), "echo", "--cpu", str(CPUS[1]),
                                     "--port", str(port), "--ready", str(ready)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    if echo.poll() is not None:
                        self.fail(echo.stderr.read())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.01)
                client = subprocess.Popen([str(BIN), "udp-client", "--cpu", str(CPUS[2]),
                                           "--port", str(port), "--source-port", str(source_port),
                                           "--samples", "400", "--interval-us", "1000", "--burst", "50",
                                           "--quiet-us", "5000", "--timeout-ms", "100"],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    time.sleep(.05)
                    client.send_signal(signal.SIGSTOP)
                    time.sleep(.04)
                    client.send_signal(signal.SIGCONT)
                    out, err = client.communicate(timeout=10)
                finally:
                    if client.poll() is None:
                        client.kill(); client.wait()
                self.assertEqual(client.returncode, 0, err)
                raw = json.loads(out)
                self.assertGreater(raw["received"], 0)
                self.assertGreater(raw["skipped_slots"], 0)
                self.assertEqual(raw["sent"] + raw["send_errors"] + raw["skipped_slots"], raw["scheduled"])
                self.assertEqual(raw["received"] + raw["lost"], raw["sent"])
                self.assertEqual(len(raw["rtt_ns"]), raw["received"])
                self.assertTrue(all(a <= b for a, b in zip(raw["rtt_ns"], raw["scheduled_to_reply_ns"])))
                self.assertGreater(len(raw["first_after_quiet_rtt_ns"]), 0)
                self.assertTrue(set(raw["first_after_quiet_rtt_ns"]) <= set(raw["rtt_ns"]))
                self.assertEqual(len(raw["reply_offset_ns"]), raw["received"])
                self.assertLessEqual(max(raw["reply_offset_ns"]), raw["elapsed_ns"])
            finally:
                echo.terminate()
                out, err = echo.communicate(timeout=5)
                self.assertEqual(echo.returncode, 0, err)
                self.assertGreater(json.loads(out)["packets"], 0)

    def test_udp_no_responder_does_not_fabricate_samples(self):
        port, source = self.network_available(), self.network_available()
        raw = self.worker("udp-client", "--port", port, "--source-port", source,
                          "--samples", 10, "--interval-us", 1000, "--timeout-ms", 30)
        self.assertEqual(raw["received"], 0)
        self.assertEqual(raw["rtt_ns"], [])
        self.assertEqual(raw["reply_offset_ns"], [])
        self.assertEqual(raw["lost"], raw["sent"])


if __name__ == "__main__":
    unittest.main()
