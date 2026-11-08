"""Optional bounded bpftrace diagnostics. Nothing attaches during capability discovery."""
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

from .state import atomic_json

GROUPS = {
    "irq": {"irq/irq_handler_entry": {"irq"}, "irq/irq_handler_exit": {"irq"}},
    "softirq": {"irq/softirq_entry": {"vec"}, "irq/softirq_exit": {"vec"}},
    "sched": {"sched/sched_wakeup": {"pid", "target_cpu"}, "sched/sched_switch": {"next_pid"}},
    "tlb": {"tlb/tlb_flush": set()},
    "rcu": {"rcu/rcu_callback": set(), "rcu/rcu_invoke_callback": set()},
    "idle": {"power/cpu_idle": {"state", "cpu_id"}},
}
SERIES = {
    "irq_count": ("IRQ handler calls", "count"), "irq_ns": ("IRQ handler time", "ns"),
    "softirq_count": ("Softirq calls", "count"), "softirq_ns": ("Softirq time", "ns"),
    "runq_count": ("Observed wake-to-run delays", "count"),
    "runq_ns": ("Total wake-to-run delay", "ns"), "runq_max": ("Maximum wake-to-run delay", "ns"),
    "tlb_count": ("TLB flush events", "count"),
    "rcu_enqueue": ("RCU callback enqueue events", "count"),
    "rcu_invoke": ("RCU callback invoke events", "count"),
    "idle_count": ("Idle entries", "count"), "idle_ns": ("Completed idle intervals", "ns"),
}


def capabilities(roots=("/sys/kernel/tracing", "/sys/kernel/debug/tracing")):
    binary = shutil.which("bpftrace")
    version = None
    if binary:
        try:
            proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5)
            version = proc.stdout.strip() if proc.returncode == 0 else proc.stderr.strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            version = str(exc)
    match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", version or "")
    version_ok = bool(match and tuple(map(int, match.groups())) >= (0, 20, 0))
    root = next((Path(p) for p in roots if (Path(p) / "events").is_dir()), None)
    groups = {}
    for name, events in GROUPS.items():
        missing = []
        for event, fields in events.items():
            try:
                content = (root / "events" / event / "format").read_text() if root else ""
                present = set(re.findall(r"field:[^;]*?\b([A-Za-z_]\w*)(?:\[[^]]*\])?;", content))
                if not content or fields - present:
                    missing.append(event + (": missing fields " + ",".join(sorted(fields - present)) if content else ": unavailable"))
            except OSError as exc:
                missing.append(f"{event}: {exc}")
        groups[name] = {"available": not missing, "missing": missing}
    return {"binary": binary, "version": version, "version_ok": version_ok,
            "tracefs": str(root) if root else None, "groups": groups,
            "btf": Path("/sys/kernel/btf/vmlinux").exists(),
            "attachment_tested": False}


def selection(args, inventory=None):
    cap = inventory if inventory is not None else capabilities()
    requested = [] if args.bpf_events == "none" else args.bpf_events.split(",")
    if len(requested) != len(set(requested)) or set(requested) - GROUPS.keys():
        raise ValueError("--bpf-events must be unique irq,softirq,sched,tlb,rcu,idle entries or none")
    cpus = [args.cpu]
    if args.bpf_cpus:
        # Reuse the CPU-list parser without making runner import this module cyclically.
        from .runner import cpulist
        cpus = sorted(cpulist(args.bpf_cpus))
    if not cpus or len(cpus) > 4 or set(cpus) - set(os.sched_getaffinity(0)):
        raise ValueError("--bpf-cpus must select one to four available CPUs")
    selected = [name for name in requested if cap["groups"][name]["available"]]
    skipped = {name: cap["groups"][name]["missing"] for name in requested if name not in selected}
    reasons = []
    if not cap["binary"] or not cap["version_ok"]:
        reasons.append("bpftrace >= 0.20 is required")
    if not selected and not args.bpf_stacks:
        reasons.append("none of the requested BPF tracepoint groups is available")
    return {"capabilities": cap, "groups": selected, "skipped": skipped, "cpus": cpus,
            "stacks": args.bpf_stacks, "hz": args.bpf_hz, "bin_ms": args.bpf_bin_ms,
            "max_bins": args.bpf_max_bins, "supported": not reasons, "reasons": reasons}


def program(config):
    """Aggregate in time-keyed maps; print once after detach, never print/clear live maps."""
    cpus = config["cpus"]
    if any(not isinstance(c, int) or c < 0 or c > 65535 for c in cpus):
        raise ValueError("invalid trace CPU")
    predicate = "(" + " || ".join(f"cpu == {c}" for c in cpus) + ")"
    target = "(" + " || ".join(f"args->target_cpu == {c}" for c in cpus) + ")"
    width, maximum = config["bin_ms"] * 1000000, config["max_bins"]
    lines = ['BEGIN { @origin_ns = nsecs(monotonic); printf("METALBENCH_BPF_READY %llu\\n", @origin_ns); }']
    scratch = []

    def record(body):
        return (f"$bucket = (nsecs(monotonic) - @origin_ns) / {width}; "
                f"if ($bucket < {maximum}) {{ {body} }} else {{ @overflow = count(); }}")

    def duration(group, field, entry, exit_probe):
        scratch.append(f"{group}_start")
        lines.append(f"tracepoint:{entry} /{predicate}/ {{ @{group}_start[cpu, args->{field}] = nsecs(monotonic); "
                     + record(f"@{group}_count[cpu, $bucket] = count();") + " }")
        lines.append(f"tracepoint:{exit_probe} /{predicate}/ {{ $begin = @{group}_start[cpu, args->{field}]; "
                     + "if ($begin) { $delta = nsecs(monotonic) - $begin; "
                     + record(f"@{group}_ns[cpu, $bucket] = sum($delta);")
                     + f" delete(@{group}_start[cpu, args->{field}]); }} }}")

    for group in config["groups"]:
        if group == "irq":
            duration("irq", "irq", "irq:irq_handler_entry", "irq:irq_handler_exit")
        elif group == "softirq":
            duration("softirq", "vec", "irq:softirq_entry", "irq:softirq_exit")
        elif group == "sched":
            scratch.append("wake")
            lines.append(f"tracepoint:sched:sched_wakeup /{target} && args->pid > 0/ "
                         "{ if (!@wake[args->pid]) { @wake[args->pid] = nsecs(monotonic); } }")
            # Observe switch on every CPU to clean up wakeups for migrating tasks.
            lines.append("tracepoint:sched:sched_switch { $begin = @wake[args->next_pid]; "
                         f"if ($begin) {{ if ({predicate}) {{ $delta = nsecs(monotonic) - $begin; "
                         + record("@runq_count[cpu, $bucket] = count(); @runq_ns[cpu, $bucket] = sum($delta); "
                                  "@runq_max[cpu, $bucket] = max($delta);")
                         + " } delete(@wake[args->next_pid]); } }")
        elif group in {"tlb", "rcu"}:
            probes = [("tlb:tlb_flush", "tlb_count")] if group == "tlb" else [
                ("rcu:rcu_callback", "rcu_enqueue"), ("rcu:rcu_invoke_callback", "rcu_invoke")]
            for probe, name in probes:
                lines.append(f"tracepoint:{probe} /{predicate}/ {{ " + record(f"@{name}[cpu, $bucket] = count();") + " }")
        elif group == "idle":
            scratch.append("idle_start")
            lines.append(f"tracepoint:power:cpu_idle /{predicate}/ {{ if (args->state != 4294967295) "
                         "{ @idle_start[cpu] = nsecs(monotonic); " + record("@idle_count[cpu, $bucket] = count();")
                         + " } else { $begin = @idle_start[cpu]; if ($begin) { $delta = nsecs(monotonic) - $begin; "
                         + record("@idle_ns[cpu, $bucket] = sum($delta);") + " delete(@idle_start[cpu]); } } }")
    if config["stacks"]:
        lines.append(f"profile:hz:{config['hz']} /{predicate}/ "
                     "{ @kernel_stacks[kstack(perf, 32)] = count(); @user_stacks[ustack(perf, 32)] = count(); }")
    lines.append('END { printf("METALBENCH_BPF_END %llu\\n", nsecs(monotonic)); '
                 + " ".join(f"clear(@{name});" for name in scratch) + " }")
    return "\n".join(lines) + "\n"


def parse_output(text, stderr=""):
    maps, warnings, markers = {}, [], {}
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            warnings.append("non-JSON/truncated bpftrace output")
            continue
        if not isinstance(item, dict):
            warnings.append("invalid bpftrace output record")
            continue
        kind, data = item.get("type"), item.get("data")
        if kind == "map" and isinstance(data, dict):
            for name, value in data.items():
                if name in maps:
                    warnings.append(f"duplicate final map {name}")
                maps[name] = value
        elif kind == "map":
            warnings.append("invalid bpftrace map record")
        elif kind == "printf" and isinstance(data, str):
            match = re.search(r"METALBENCH_BPF_(READY|END) (\d+)", data)
            if match:
                markers[match[1]] = int(match[2])
        elif kind in {"lost_events", "lost", "error", "warning"}:
            warnings.append(f"bpftrace {kind}: {data}")
        elif kind == "helper_error":
            warnings.append(f"bpftrace helper failure: {item.get('helper')} {item.get('retcode')} {item.get('msg')}")
    if maps.get("@overflow", 0):
        warnings.append("time-bin limit reached; late event data are incomplete")
    if stderr.strip():
        warnings.append("bpftrace emitted diagnostics; inspect stderr (helper/map failures can lose data)")
    series = {}
    for name in SERIES:
        rows = []
        entries = maps.get("@" + name, {})
        if not isinstance(entries, dict):
            warnings.append(f"invalid {name} map shape")
            continue
        for key, value in entries.items():
            match = re.fullmatch(r"\s*(\d+)\s*,\s*(\d+)\s*", key)
            if not match or type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                warnings.append(f"invalid {name} map entry")
                continue
            rows.append({"cpu": int(match[1]), "bin": int(match[2]), "value": value})
        if rows:
            series[name] = sorted(rows, key=lambda r: (r["cpu"], r["bin"]))
    stacks = {name: maps.get("@" + name, {}) for name in ("kernel_stacks", "user_stacks")}
    for name, entries in stacks.items():
        if not isinstance(entries, dict):
            stacks[name] = {}
            warnings.append(f"invalid {name} map shape")
        else:
            stacks[name] = {key: value for key, value in entries.items() if type(value) is int and value > 0}
            if len(stacks[name]) != len(entries):
                warnings.append(f"invalid {name} map entry")
    if {"READY", "END"} <= markers.keys() and markers["END"] <= markers["READY"]:
        warnings.append("invalid BPF capture clock markers")
    return {"series": series, "stacks": stacks, "markers": markers,
            "warnings": sorted(set(warnings)), "overflow": maps.get("@overflow", 0)}


class BPFCollector:
    def __init__(self, config, directory):
        self.config, self.directory = config, Path(directory) / "bpf"
        self.process = None
        self.result = {"status": "disabled"}

    def __enter__(self):
        return self

    def start(self):
        if not self.config:
            return
        self.directory.mkdir()
        script = self.directory / "program.bt"
        script.write_text(program(self.config))
        self.result = {"schema": 1, "status": "starting", "config": self.config,
                       "clock": "receiver CLOCK_MONOTONIC", "diagnostic": True,
                       "scope": "systemwide probe hooks and profile interrupts; retained data filtered by CPU"}
        atomic_json(self.directory / "capture.json", self.result)
        self.stdout = (self.directory / "raw.jsonl").open("w")
        self.stderr = (self.directory / "stderr.txt").open("w")
        env = dict(os.environ, BPFTRACE_MAX_MAP_KEYS="4096", BPFTRACE_CACHE_USER_SYMBOLS="PER_PID")
        try:
            # -k detects failed writes/stack helpers; -kk also emits expected absent
            # map lookups, creating a large and unnecessary observer effect.
            self.process = subprocess.Popen([self.config["capabilities"]["binary"], "-q", "-f", "json", "-B", "none", "-k", str(script)],
                                            stdout=self.stdout, stderr=self.stderr, stdin=subprocess.DEVNULL,
                                            start_new_session=True, env=env)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("bpftrace exited before capture; inspect " + str(self.directory / "stderr.txt"))
                content = (self.directory / "raw.jsonl").read_text()
                if "METALBENCH_BPF_READY" in content:
                    self.result["status"] = "running"
                    atomic_json(self.directory / "capture.json", self.result)
                    return
                time.sleep(.05)
            raise TimeoutError("bpftrace did not become ready within 30 seconds")
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if not self.config or not hasattr(self, "stdout"):
            return
        forced = False
        if self.process is not None and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass  # The process may exit between poll and signal.
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                forced = True
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=5)
        self.stdout.close(); self.stderr.close()
        parsed = parse_output((self.directory / "raw.jsonl").read_text(), (self.directory / "stderr.txt").read_text())
        code = self.process.returncode if self.process is not None else None
        complete = not forced and code in (0, 130) and {"READY", "END"} <= parsed["markers"].keys()
        self.result.update(parsed, returncode=code, forced_stop=forced,
                           status="complete" if complete and not parsed["warnings"] else "partial" if complete else "failed")
        atomic_json(self.directory / "capture.json", self.result)
        del self.stdout  # idempotent stop

    def __exit__(self, exc_type, *_):
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            self.stop()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        if not exc_type and self.config and self.result["status"] == "failed":
            raise RuntimeError("BPF capture failed; raw benchmark data retained; inspect bpf/capture.json")
