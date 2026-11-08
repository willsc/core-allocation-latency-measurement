import contextlib
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import socket
import statistics
import subprocess
import threading
import time

from .discovery import command, counters, fingerprint, probe, read
from .bpf import BPFCollector, selection as bpf_selection
from .netlink import WRITABLE
from .state import Backend, HostLock, Transaction, atomic_json, normalize
from .stats import paired_effect, summarize, write_report

ROOT = Path(__file__).resolve().parent.parent
WORKER = ROOT / "build/latprobe"
CASES = ("tlb", "elc", "io-cache", "idle", "napi", "rcu", "network")


class Unsupported(Exception):
    pass


def cpulist(value):
    result = set()
    for item in value.split(","):
        if not item:
            continue
        pair = item.split("-")
        if len(pair) > 2:
            raise ValueError("bad CPU list")
        lo, hi = int(pair[0]), int(pair[-1])
        if lo < 0 or hi < lo or hi > 65535:
            raise ValueError("bad CPU range")
        result.update(range(lo, hi + 1))
    return result


def file_change(path, value):
    return {"resource": {"kind": "file", "path": str(path)}, "value": normalize(value)}


def plan(args, inventory=None):
    inventory = inventory if inventory is not None else probe(args.interface)
    errors, warnings, variants = [], [], []
    case = args.case
    metric = "batch_ns"
    baseline, candidate = "current", "candidate"
    if args.cpu not in inventory["allowed_cpus"]:
        errors.append("victim CPU is outside the process affinity mask")
    if args.noise_cpu is not None:
        if args.noise_cpu not in inventory["allowed_cpus"] or args.noise_cpu == args.cpu:
            errors.append("noise/poller CPU must be a different available CPU")
        info = {c["cpu"]: c for c in inventory.get("cpus", [])}
        if args.cpu in info and args.noise_cpu in info and info[args.cpu]["siblings"] == info[args.noise_cpu]["siblings"]:
            errors.append("noise/poller CPU shares the victim's physical core")
    isolated = cpulist(inventory.get("isolated") or "")
    occupied = {args.cpu, args.noise_cpu}
    if args.local_peer:
        occupied.add(args.peer_cpu)
    monitors = sorted(set(inventory["allowed_cpus"]) - occupied - isolated)
    if args.monitor_cpu is None:
        args.monitor_cpu = monitors[0] if monitors else None
    if args.monitor_cpu not in monitors:
        errors.append("runner needs a distinct non-isolated --monitor-cpu")
    if args.cpu not in isolated:
        warnings.append("victim CPU is not boot-isolated; scheduler noise may dominate")
    if not inventory["kernel"].startswith("7."):
        warnings.append("this host is not running the target 7.x kernel; local results are harness validation only")
    if args.telemetry_ms:
        warnings.append("frequency telemetry is enabled; sysfs reads can perturb latency, so repeat without the sampler")

    def variant(name, changes=(), **extra):
        variants.append({"name": name, "changes": list(changes), **extra})

    if case == "tlb":
        if args.noise_cpu is None:
            errors.append("--noise-cpu is required for mapping interference")
        baseline, candidate = "shared-mm", "separate-mm"
        variant("shared-mm", noise="thread")
        variant("separate-mm", noise="process")
        variant("quiet", noise="none")
    elif case == "elc":
        if not args.uncore_dir or args.floor_khz is None:
            errors.append("--uncore-dir and --floor-khz are required; select the victim's fabric domain from probe")
        else:
            domain = inventory["uncore"].get(args.uncore_dir, {})
            if any(domain.get(k) is None for k in ("elc_floor_freq_khz", "elc_low_threshold_percent")):
                errors.append("selected domain does not expose ELC controls")
            minimum = int(domain.get("min_freq_khz") or 0)
            maximum = int(domain.get("max_freq_khz") or 0)
            if args.floor_khz < minimum or (maximum and args.floor_khz > maximum):
                errors.append("ELC floor must be within the current uncore min/max range")
            changes = [file_change(Path(args.uncore_dir) / "elc_floor_freq_khz", args.floor_khz),
                       file_change(Path(args.uncore_dir) / "elc_low_threshold_percent", args.elc_low_percent)]
            variant("current")
            variant("candidate", changes)
            if all(normalize(domain.get(Path(c["resource"]["path"]).name, "")) == c["value"] for c in changes):
                errors.append("ELC candidate is identical to the current setting")
        warnings.append("ELC readback proves configuration; compare measured uncore frequencies and burst latency to establish effect")
    elif case == "idle":
        path = f"/sys/devices/system/cpu/cpu{args.cpu}/power/pm_qos_resume_latency_us"
        current = next((c.get("resume_latency_us") for c in inventory["cpus"] if c["cpu"] == args.cpu), None)
        if current is None:
            errors.append("per-CPU resume latency control is unavailable")
        elif normalize(current) == str(args.idle_latency_us):
            errors.append("idle candidate is identical to the current constraint")
        variant("current")
        variant("candidate", [file_change(path, args.idle_latency_us)])
        if not args.gap_us:
            errors.append("idle test requires a nonzero --gap-us")
        metric = "wakeup_plus_batch_ns"
        warnings.append("global C-state caps and other PM QoS requests can mask this experiment; inspect idle-state residency deltas")
    elif case == "io-cache":
        resctrl = inventory["resctrl"]
        if resctrl.get("io_alloc") not in {"enabled", "disabled"} or not resctrl.get("io_alloc_cbm"):
            errors.append("mounted resctrl does not expose I/O cache allocation")
        if not args.io_mask:
            errors.append("--io-mask CACHE_ID=HEX is required")
        if args.noise_cpu is None:
            errors.append("--noise-cpu is required for the UDP background receiver")
        if resctrl.get("io_alloc") == "disabled":
            groups = [p for p in Path("/sys/fs/resctrl").iterdir()
                      if p.is_dir() and p.name not in {"info", "mon_groups"}]
            if groups:
                errors.append("refusing to enable io_alloc while resctrl control groups exist")
        if args.io_mask and resctrl.get("io_alloc_cbm"):
            try:
                current = {int(k): int(v, 16) for k, v in (p.split("=") for p in resctrl["io_alloc_cbm"].split(";"))}
                wanted = {int(k): int(v, 16) for k, v in (p.split("=") for p in args.io_mask.split(";"))}
                if set(wanted) - set(current) or not wanted or any(v < 0 for v in wanted.values()):
                    raise ValueError("unknown cache ID or mask")
                allowed = int(resctrl["cbm_mask"], 16)
                if any(v & ~allowed for v in wanted.values()):
                    raise ValueError("mask exceeds hardware cbm_mask")
                merged = current | wanted
                mask = ";".join(f"{k}={v:x}" for k, v in sorted(merged.items()))
                changes = []
                if resctrl["io_alloc"] == "disabled":
                    changes.append(file_change("/sys/fs/resctrl/info/L3/io_alloc", "1"))
                changes.append(file_change("/sys/fs/resctrl/info/L3/io_alloc_cbm", mask))
                variant("current")
                variant("candidate", changes)
                if merged == current and resctrl["io_alloc"] == "enabled":
                    errors.append("I/O mask candidate is identical to the current allocation")
            except (ValueError, TypeError, KeyError) as exc:
                errors.append(f"invalid io mask: {exc}")
        warnings.append("I/O allocation is device/platform specific; mask readback alone does not prove ENA DMA uses those ways")
    elif case == "napi":
        metric, baseline, candidate = "rtt_ns", "irq", "epoll"
        nic = inventory.get("interface") or {}
        napi = next((n for n in nic.get("napis", []) if n["id"] == args.napi_id), None)
        if not napi:
            errors.append("--napi-id must identify an exposed NAPI on --interface")
        elif not {"defer-hard-irqs", "gro-flush-timeout", "irq-suspend-timeout"} <= napi.keys():
            errors.append("NAPI lacks the required per-queue controls")
        else:
            resource = {"kind": "napi", "id": args.napi_id, "ifindex": nic["ifindex"]}
            modes = args.modes.split(",")
            if len(modes) != len(set(modes)) or set(modes) - {"irq", "software", "epoll", "threaded"}:
                errors.append("--modes must be unique irq,software,epoll,threaded values")
            for mode in modes:
                settings = {"defer-hard-irqs": 0, "gro-flush-timeout": 0, "irq-suspend-timeout": 0}
                if "threaded" in napi:
                    settings["threaded"] = 0
                value = {"settings": settings, "affinity": None}
                if mode in {"software", "epoll"}:
                    settings.update({"defer-hard-irqs": args.defer_irqs, "gro-flush-timeout": args.gro_ns})
                if mode == "epoll":
                    settings["irq-suspend-timeout"] = args.suspend_ns
                if mode == "threaded":
                    if "threaded" not in napi or args.noise_cpu is None:
                        errors.append("threaded mode requires an exposed threaded attribute and --noise-cpu")
                    settings["threaded"] = 2
                    value["affinity"] = [args.noise_cpu]
                variant(mode, [{"resource": resource, "value": value}],
                        busy_us=args.busy_us if mode == "epoll" else 0, prefer=int(mode == "epoll"))
        if "error" in inventory.get("epoll_params", {}):
            errors.append("epoll busy-poll ioctl is unavailable")
        warnings.append("hardware coalescing, IRQ affinity, RSS and offloads are recorded and held unchanged")
    elif case == "rcu":
        metric = "operation_ns"
        label = "poll" if inventory["rcu_nocb_poll"] else "wake"
        if args.rcu_state != label:
            errors.append(f"boot has RCU state {label}; requested --rcu-state {args.rcu_state}")
        mask = set()
        for arg in inventory["cmdline"].split():
            if arg.startswith(("rcu_nocbs=", "nohz_full=")):
                try:
                    mask |= cpulist(arg.split("=", 1)[1])
                except ValueError:
                    warnings.append(f"cannot parse boot offload list {arg}")
        if args.cpu not in mask:
            errors.append("victim CPU is not in an explicit rcu_nocbs/nohz_full boot list")
        variant(label)
        baseline, candidate = "wake", "poll"
        warnings.append("socket bind/close is a kernel-lifetime surrogate; confirm RCU callback activity separately before attributing a change to RCU")
    else:
        metric, baseline, candidate = "rtt_ns", "current", "current"
        variant("current", busy_us=0, prefer=0)

    if case in {"network", "napi", "io-cache"}:
        if not args.local_peer and not args.peer:
            errors.append("supply --peer SSH_HOST or --local-peer for a local smoke test")
        if args.local_peer and (args.peer_cpu not in inventory["allowed_cpus"] or args.peer_cpu in {args.cpu, args.noise_cpu}):
            errors.append("local sender needs its own available --peer-cpu")
        if args.peer and (args.peer.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.@:\[\]-]+", args.peer)):
            errors.append("invalid SSH peer")
        try:
            ip = ipaddress.IPv4Address(args.address)
            if case in {"napi", "io-cache"} and (ip.is_loopback or ip.is_unspecified):
                errors.append("hardware network tests require a concrete non-loopback receiver address")
        except ipaddress.AddressValueError:
            errors.append("--address must be the receiver's IPv4 address")
        if case in {"napi", "io-cache"}:
            if args.local_peer:
                errors.append("hardware network tests require a remote sender to exercise ENA")
            nic = inventory.get("interface") or {}
            addresses = []
            try:
                addresses = [a["local"] for device in json.loads(nic["route"]["stdout"])
                             for a in device["addr_info"] if a["family"] == "inet"]
            except (KeyError, TypeError, json.JSONDecodeError):
                pass
            if args.address not in addresses:
                errors.append("--address must belong to --interface")
        if args.local_peer:
            warnings.append("local sender/loopback measurements validate the harness, not AWS network performance")
    if args.gap_us and case in {"tlb", "elc", "io-cache"}:
        metric = "wakeup_plus_batch_ns" if case == "elc" else metric
    for v in variants:
        for change in v["changes"]:
            if change["resource"]["kind"] == "file":
                Backend().file_path(change["resource"])  # validate scope before any execution
    bpf = bpf_selection(args) if args.bpf else None
    if bpf:
        errors.extend(bpf["reasons"])
        warnings.append("BPF diagnostic run: probe hooks and profile interrupts change timing; repeat without tracing for acceptance")
        if bpf["skipped"]:
            warnings.append("unavailable BPF groups: " + ", ".join(bpf["skipped"]))
    return {"case": case, "supported": not errors, "reasons": errors, "warnings": warnings,
            "bpf": bpf,
            "variants": variants, "primary_metric": metric, "baseline": baseline, "candidate": candidate,
            "mutates_settings": any(v["changes"] for v in variants),
            "rounds": args.rounds, "monitor_cpu": args.monitor_cpu, "ordering": "forward then reverse in each round"}


class Worker:
    def __init__(self, argv, directory, name):
        self.out = Path(directory) / f"{name}.json"
        self.err = Path(directory) / f"{name}.stderr"
        self.out_stream, self.err_stream = self.out.open("w"), self.err.open("w")
        try:
            self.process = subprocess.Popen(argv, stdout=self.out_stream, stderr=self.err_stream,
                                            stdin=subprocess.DEVNULL, start_new_session=True)
        except BaseException:
            self.out_stream.close(); self.err_stream.close()
            raise
        self.argv = argv

    def wait_ready(self, path, timeout=30):
        deadline = time.monotonic() + timeout
        while not Path(path).exists():
            if self.process.poll() is not None:
                raise RuntimeError(f"worker exited before readiness: {self.err.read_text()}")
            if time.monotonic() > deadline:
                raise TimeoutError(f"worker readiness timed out: {path}")
            time.sleep(.01)

    def finish(self, timeout, allow_signal=False):
        code = self.process.wait(timeout=timeout)
        self.out_stream.close(); self.err_stream.close()
        if code and not (allow_signal and code == 130):
            raise RuntimeError(f"worker exit {code}: {self.err.read_text()[-4000:]}")
        return json.loads(self.out.read_text())

    def stop(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        self.out_stream.close(); self.err_stream.close()


def memory_command(args, variant, rcu=False):
    argv = [str(WORKER), "rcu" if rcu else "memory", "--cpu", str(args.cpu),
            "--samples", str(args.samples), "--loads", str(args.loads),
            "--size-mb", str(args.memory_mb), "--gap-us", str(args.gap_us),
            "--churn-interval-us", str(args.churn_interval_us),
            "--warmup-ms", str(args.warmup_ms), "--noise", variant.get("noise", "none")]
    if args.noise_cpu is not None:
        argv += ["--noise-cpu", str(args.noise_cpu)]
    if args.mlock:
        argv.append("--mlock")
    return argv


class Telemetry:
    def __init__(self, args, inventory, directory):
        self.interval = args.telemetry_ms / 1000
        self.cpu, self.path = args.monitor_cpu, directory / "telemetry.json"
        self.paths = [f"/sys/devices/system/cpu/cpu{args.cpu}/cpufreq/scaling_cur_freq"]
        self.paths += [str(Path(p) / "current_freq_khz") for p, fields in inventory["uncore"].items()
                       if fields.get("current_freq_khz") is not None]
        self.stop_event, self.samples, self.error = threading.Event(), [], None

    def sample(self):
        try:
            os.sched_setaffinity(0, {self.cpu})
            while not self.stop_event.is_set():
                if len(self.samples) >= 100000:
                    raise RuntimeError("telemetry limit reached")
                self.samples.append({"monotonic_ns": time.monotonic_ns(),
                                     "values": {p: read(p) for p in self.paths}})
                self.stop_event.wait(self.interval)
        except Exception as exc:
            self.error = str(exc)

    def __enter__(self):
        if self.interval:
            self.thread = threading.Thread(target=self.sample, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, *_):
        if self.interval:
            self.stop_event.set()
            self.thread.join(timeout=10)
            if self.thread.is_alive():
                self.error = "telemetry thread did not stop"
            atomic_json(self.path, {"samples": self.samples, "error": self.error})


def peer_command(args, mode, extra=()):
    argv = [str(WORKER) if args.local_peer else args.peer_binary, mode,
            "--cpu", str(args.peer_cpu), "--address", args.address, "--port", str(args.port),
            "--source-port", str(args.source_port), "--samples", str(args.samples),
            "--interval-us", str(args.interval_us), "--burst", str(args.burst),
            "--quiet-us", str(args.quiet_us), "--packet-size", str(args.packet_size),
            "--timeout-ms", str(args.reply_timeout_ms), *extra]
    if not args.local_peer:
        return ["ssh", "-oBatchMode=yes", "-oConnectTimeout=10", args.peer, shlex.join(argv)]
    return argv


def network_trial(args, variant, directory, tracer):
    ready = directory / "echo.ready"
    echo_args = [str(WORKER), "echo", "--cpu", str(args.cpu), "--address", args.address,
                 "--port", str(args.port), "--ready", str(ready), "--busy-us", str(variant.get("busy_us", 0)),
                 "--prefer", str(variant.get("prefer", 0)), "--budget", str(args.busy_budget)]
    echo = Worker(echo_args, directory, "receiver")
    sender = None
    try:
        echo.wait_ready(ready)
        # A separate bounded warmup keeps first socket/route setup out of measured traffic.
        warm_args = peer_command(args, "udp-client", ["--samples", str(args.network_warmup_samples)])
        warm = Worker(warm_args, directory, "warmup")
        try:
            warm_raw = warm.finish(30 + args.network_warmup_samples *
                                   (args.interval_us + args.quiet_us / args.burst) / 1e6)
            if not warm_raw.get("received"):
                raise RuntimeError("network warmup received no replies; check route and UDP port")
        finally:
            warm.stop()
        tracer.start()  # receiver is alive: user-symbol caching can inspect its mappings
        sender = Worker(peer_command(args, "udp-client"), directory, "raw")
        timeout = 30 + args.samples * (args.interval_us + args.quiet_us / args.burst) / 1e6
        raw = sender.finish(timeout + args.reply_timeout_ms / 1000)
        tracer.stop()
        echo.stop()
        receiver = json.loads((directory / "receiver.json").read_text())
        warnings = []
        if args.case == "napi" and (raw.get("first_napi_id") != args.napi_id or raw.get("napi_id_changes")):
            warnings.append("INVALID: benchmark flow did not stay on the configured NAPI; choose the observed ID and rerun")
        if receiver.get("socket_drops") or receiver.get("send_errors"):
            warnings.append("INVALID: receiver dropped traffic or failed to echo packets")
        return raw, warnings
    finally:
        if sender:
            sender.stop()
        echo.stop()


def io_trial(args, variant, directory, tracer):
    echo_ready, mem_ready, gate, traffic = [directory / n for n in ("echo.ready", "memory.ready", "start", "traffic.ready")]
    echo = Worker([str(WORKER), "echo", "--cpu", str(args.noise_cpu), "--address", args.address,
                   "--port", str(args.port), "--ready", str(echo_ready), "--traffic", str(traffic)], directory, "receiver")
    memory = sender = None
    try:
        echo.wait_ready(echo_ready)
        memory = Worker(memory_command(args, variant) + ["--ready", str(mem_ready), "--start", str(gate)], directory, "raw")
        memory.wait_ready(mem_ready)
        tracer.start()
        sender = Worker(peer_command(args, "udp-load", ["--duration-ms", str(args.load_seconds * 1000)]), directory, "load")
        echo.wait_ready(traffic, timeout=20)
        atomic_json(directory / "load-before.json", counters(args.interface, [args.cpu, args.noise_cpu]))
        gate.touch()
        raw = memory.finish(args.trial_timeout)
        tracer.stop()
        load_ended = sender.process.poll() is not None
        atomic_json(directory / "load-after.json", counters(args.interface, [args.cpu, args.noise_cpu]))
        load = sender.finish(args.load_seconds + 30)
        echo.stop()
        sink = json.loads((directory / "receiver.json").read_text())
        warnings = []
        if load_ended or not load.get("sent") or not sink.get("packets"):
            warnings.append("INVALID: background traffic did not span the memory measurement")
        if load.get("send_errors") or load.get("skipped_slots"):
            warnings.append("INVALID: background sender did not sustain the requested load")
        raw["background_packets"] = sink.get("packets", 0)
        return raw, warnings
    finally:
        for worker in (memory, sender, echo):
            if worker:
                worker.stop()


def run(args):
    directory = Path(args.output).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    inventory = probe(args.interface)
    experiment = plan(args, inventory)
    atomic_json(directory / "host.json", inventory)
    atomic_json(directory / "plan.json", experiment)
    parameters = vars(args).copy()
    atomic_json(directory / "parameters.json", parameters)
    report = {"schema": 1, "case": args.case, "status": "running", "primary_metric": experiment["primary_metric"],
              "diagnostic": bool(args.bpf),
              "warnings": experiment["warnings"], "trials": [], "parameters": parameters,
              "hostname": inventory["hostname"], "boot_id": inventory["boot_id"], "kernel": inventory["kernel"]}
    if not experiment["supported"]:
        report.update(status="skipped", reasons=experiment["reasons"])
        write_report(directory, report)
        print("Skipped: " + "; ".join(experiment["reasons"]), flush=True)
        return 3
    if experiment["mutates_settings"] and not args.apply:
        report.update(status="not-run", reasons=["review plan.json and rerun with --apply in a new output directory"])
        write_report(directory, report)
        raise ValueError("this experiment changes host settings; use plan first, then run --apply")
    if not WORKER.exists():
        report.update(status="failed", error="native worker missing; run make")
        write_report(directory, report)
        raise FileNotFoundError("run make to build the native worker")
    provenance = {"worker_sha256": hashlib.sha256(WORKER.read_bytes()).hexdigest(),
                  "sources": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in list((ROOT / "metalbench").glob("*.py")) + list((ROOT / "native").glob("*.c"))}}
    atomic_json(directory / "provenance.json", provenance)
    selected = [args.cpu] + ([args.noise_cpu] if args.noise_cpu is not None else [])
    lock = HostLock() if experiment["mutates_settings"] else contextlib.nullcontext()
    original_affinity = os.sched_getaffinity(0)
    try:
        os.sched_setaffinity(0, {args.monitor_cpu})
        with lock:
            if args.case in {"network", "napi", "io-cache"}:
                identity_cmd = ([str(WORKER), "identity"] if args.local_peer else
                                ["ssh", "-oBatchMode=yes", "-oConnectTimeout=10", args.peer,
                                 shlex.join([args.peer_binary, "identity"])])
                peer_info = subprocess.run(identity_cmd, capture_output=True, text=True, timeout=20, check=True)
                peer_identity = json.loads(peer_info.stdout)
                if peer_identity.get("protocol") != 1:
                    raise RuntimeError("peer worker protocol mismatch; rebuild it from the same source")
                atomic_json(directory / "peer.json", peer_identity)
            resources = []
            for v in experiment["variants"]:
                for change in v["changes"]:
                    if change["resource"] not in resources:
                        resources.append(change["resource"])
            for round_id in range(args.rounds):
                variants = experiment["variants"]
                order = variants + list(reversed(variants))
                for variant in order:
                    index = len(report["trials"])
                    trial_dir = directory / f"{index:03d}-{variant['name']}"
                    trial_dir.mkdir()
                    trial = {"index": index, "round": round_id, "variant": variant["name"],
                             "status": "running", "directory": trial_dir.name, "warnings": []}
                    report["trials"].append(trial)
                    print(f"[{index + 1}/{args.rounds * len(order)}] {variant['name']} (round {round_id + 1})", flush=True)
                    try:
                        with Transaction(trial_dir / "settings.json") as txn, Telemetry(args, inventory, trial_dir), BPFCollector(experiment["bpf"], trial_dir) as tracer:
                            for change in variant["changes"]:
                                try:
                                    txn.apply(change["resource"], change["value"])
                                except OSError as exc:
                                    if exc.errno in {errno.EOPNOTSUPP, errno.ENOSYS}:
                                        raise Unsupported(f"kernel/driver rejected this mode: {exc}") from exc
                                    raise
                            observed = [{"resource": resource, "value": txn.backend.read(resource)} for resource in resources]
                            atomic_json(trial_dir / "effective-settings.json", observed)
                            atomic_json(trial_dir / "before.json", counters(args.interface, selected))
                            if args.case in {"network", "napi"}:
                                raw, warnings = network_trial(args, variant, trial_dir, tracer)
                            elif args.case == "io-cache":
                                raw, warnings = io_trial(args, variant, trial_dir, tracer)
                            else:
                                worker_args = memory_command(args, variant, args.case == "rcu")
                                ready, gate = trial_dir / "worker.ready", trial_dir / "worker.start"
                                if args.bpf:
                                    worker_args += ["--ready", str(ready), "--start", str(gate)]
                                worker = Worker(worker_args, trial_dir, "raw")
                                try:
                                    if args.bpf:
                                        worker.wait_ready(ready)
                                        tracer.start()
                                        gate.touch()
                                    raw, warnings = worker.finish(args.trial_timeout), []
                                    tracer.stop()
                                finally:
                                    worker.stop()
                            atomic_json(trial_dir / "after.json", counters(args.interface, selected))
                            if any(txn.backend.read(item["resource"]) != item["value"] for item in observed):
                                warnings.append("INVALID: settings changed during measurement")
                            trial["summary"] = summarize(raw)
                            trial["observations"] = {k: v for k, v in raw.items() if not isinstance(v, list)}
                            trial["warnings"] = warnings
                            if args.bpf:
                                trial["bpf"] = {"status": tracer.result["status"], "capture": "bpf/capture.json"}
                                warnings.extend("BPF: " + w for w in tracer.result.get("warnings", []))
                            invalid = any(w.startswith("INVALID:") for w in warnings)
                            invalid |= bool(raw.get("lost") or raw.get("send_errors") or raw.get("skipped_slots"))
                            invalid |= args.case in {"network", "napi"} and not raw.get("received")
                            invalid |= raw.get("noise") in {"thread", "process"} and raw.get("noise_operations", 0) < 100
                            trial["status"] = "invalid" if invalid else "ok"
                    except Unsupported as exc:
                        trial.update(status="skipped", error=str(exc))
                    except KeyboardInterrupt:
                        trial.update(status="interrupted", error="interrupted during trial")
                        raise
                    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                        trial.update(status="failed", error=str(exc))
                        write_report(directory, report)
                        raise  # includes restoration failures: do not continue with unknown host state
                    finally:
                        write_report(directory, report)
            names = {v["name"] for v in experiment["variants"]}
            if experiment["baseline"] != experiment["candidate"] and {experiment["baseline"], experiment["candidate"]} <= names:
                report["comparison"] = paired_effect(report["trials"], experiment["baseline"],
                                                      experiment["candidate"], experiment["primary_metric"])
            report["status"] = "complete" if all(t["status"] == "ok" for t in report["trials"]) else "invalid-trials"
            if any(t["status"] == "skipped" for t in report["trials"]):
                report["status"] = "partial"
            if any(t.get("bpf", {}).get("status") in {"partial", "failed"} for t in report["trials"]):
                report["status"] = "partial"
    except BaseException as exc:
        report.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", error=str(exc))
        write_report(directory, report)
        raise
    finally:
        os.sched_setaffinity(0, original_affinity)
    write_report(directory, report)
    if args.graphs:
        from .graphs import generate
        print(f"Graphs: {generate(directory)}", flush=True)
    print(f"Results: {directory / 'report.md'}", flush=True)
    return 0 if report["status"] == "complete" else 4


def compare_rcu(baseline_dir, candidate_dir, output):
    dirs = [Path(baseline_dir), Path(candidate_dir)]
    reports = [json.loads((p / "report.json").read_text()) for p in dirs]
    hosts = [json.loads((p / "host.json").read_text()) for p in dirs]
    if any(r["case"] != "rcu" or r["status"] != "complete" for r in reports):
        raise ValueError("comparison requires two completed RCU runs")
    if hosts[0]["rcu_nocb_poll"] or not hosts[1]["rcu_nocb_poll"]:
        raise ValueError("baseline must be wake; candidate must be poll")
    if hosts[0]["boot_id"] == hosts[1]["boot_id"]:
        raise ValueError("RCU polling comparison requires different boots")
    for field in ("hostname", "kernel", "machine", "online", "isolated", "nohz_full"):
        if hosts[0][field] != hosts[1][field]:
            raise ValueError(f"host mismatch: {field}")
    boot_options = [sorted(a for a in h["cmdline"].split() if a != "rcu_nocb_poll") for h in hosts]
    if boot_options[0] != boot_options[1]:
        raise ValueError("other boot arguments differ; comparison is confounded")
    if fingerprint(hosts[0]) != fingerprint(hosts[1]):
        raise ValueError("CPU topology, platform identity or runtime tuning differs between boots")
    provenance = [json.loads((p / "provenance.json").read_text()) for p in dirs]
    if provenance[0] != provenance[1]:
        raise ValueError("benchmark build/source changed between boots")
    for key in ("cpu", "samples", "loads", "memory_mb", "gap_us", "warmup_ms", "mlock", "rounds", "monitor_cpu", "telemetry_ms",
                "bpf", "bpf_events", "bpf_cpus", "bpf_stacks", "bpf_hz", "bpf_bin_ms", "bpf_max_bins"):
        if reports[0]["parameters"][key] != reports[1]["parameters"][key]:
            raise ValueError(f"workload mismatch: {key}")
    values = [[t["summary"]["metrics"]["operation_ns"]["p99.9"] for t in r["trials"]] for r in reports]
    b, c = [statistics.median(v) for v in values]
    result = {"case": "rcu", "baseline": str(dirs[0]), "candidate": str(dirs[1]),
              "baseline_median_trial_p99.9_ns": b, "candidate_median_trial_p99.9_ns": c,
              "change_percent": 100 * (c / b - 1),
              "interpretation": "descriptive two-boot comparison; alternate more boots to separate boot variation from treatment",
              "warnings": sorted({w for r in reports for t in r["trials"] for w in t["summary"]["warnings"]})}
    atomic_json(output, result)
    return result
