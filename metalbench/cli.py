import argparse
from datetime import datetime, timezone
import json
import signal
import sys

from .discovery import probe
from .runner import CASES, compare_rcu, plan, run
from .state import HostLock, Transaction, atomic_json


def bounded(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return number
    return parse


def parser():
    p = argparse.ArgumentParser(description="Linux 7.x AWS metal latency experiment harness")
    sub = p.add_subparsers(dest="command", required=True)
    inventory = sub.add_parser("probe", help="read-only host and feature inventory")
    inventory.add_argument("--interface")
    inventory.add_argument("--output")
    inventory.add_argument("--bpf", action="store_true", help="include read-only BPF capability inventory")
    for name in ("plan", "run"):
        q = sub.add_parser(name, help="preview an experiment" if name == "plan" else "execute a benchmark")
        q.add_argument("case", choices=CASES)
        q.add_argument("--cpu", type=bounded(0, 1023), required=True)
        q.add_argument("--noise-cpu", type=bounded(0, 1023))
        q.add_argument("--monitor-cpu", type=bounded(0, 1023), help="housekeeping CPU for the runner; auto-selected if omitted")
        q.add_argument("--telemetry-ms", type=bounded(0, 60000), default=0, help="optional frequency sampler; 0 disables observer overhead")
        q.add_argument("--bpf", action="store_true", help="enable optional bpftrace diagnostics; changes measurement overhead")
        q.add_argument("--bpf-events", default="irq,softirq,sched,tlb,rcu,idle")
        q.add_argument("--bpf-cpus", help="one to four CPUs to retain; defaults to the victim CPU")
        q.add_argument("--bpf-stacks", action="store_true", help="also collect sampled kernel/user stacks; implies --bpf")
        q.add_argument("--bpf-hz", type=bounded(1, 199), default=99)
        q.add_argument("--bpf-bin-ms", type=bounded(10, 60000), default=100)
        q.add_argument("--bpf-max-bins", type=bounded(16, 1024), default=512)
        q.add_argument("--graphs", action="store_true", help="render offline SVG/PNG graphs after the run (requires matplotlib)")
        q.add_argument("--churn-interval-us", type=bounded(0, 1000000), default=100)
        q.add_argument("--samples", type=bounded(1, 10000000), default=100000)
        q.add_argument("--rounds", type=bounded(1, 100), default=3)
        q.add_argument("--memory-mb", type=bounded(1, 16384), default=64)
        q.add_argument("--loads", type=bounded(1, 1000000), default=64)
        q.add_argument("--gap-us", type=bounded(0, 10000000))
        q.add_argument("--warmup-ms", type=bounded(0, 600000), default=500)
        q.add_argument("--mlock", action="store_true")
        q.add_argument("--trial-timeout", type=bounded(1, 86400), default=600)
        q.add_argument("--output")
        q.add_argument("--apply", action="store_true", help="permit the experiment's listed reversible setting changes")
        q.add_argument("--uncore-dir")
        q.add_argument("--floor-khz", type=bounded(1, 100000000))
        q.add_argument("--elc-low-percent", type=bounded(1, 100), default=100)
        q.add_argument("--idle-latency-us", type=bounded(1, 1000000), default=1)
        q.add_argument("--io-mask")
        q.add_argument("--load-seconds", type=bounded(1, 3600), default=10)
        q.add_argument("--interface")
        q.add_argument("--napi-id", type=bounded(1, 4294967295))
        q.add_argument("--modes", default="irq,software,epoll")
        q.add_argument("--gro-ns", type=bounded(1, 1000000000), default=20000)
        q.add_argument("--defer-irqs", type=bounded(1, 1000000), default=2)
        q.add_argument("--suspend-ns", type=bounded(1, 1000000000), default=100000)
        q.add_argument("--busy-us", type=bounded(0, 1000000), default=20)
        q.add_argument("--busy-budget", type=bounded(1, 65535), default=64)
        q.add_argument("--rcu-state", choices=("wake", "poll"), default="wake")
        peer = q.add_mutually_exclusive_group()
        peer.add_argument("--peer", help="SSH hostname (optionally user@host) of the sender")
        peer.add_argument("--local-peer", action="store_true", help="local smoke testing only")
        q.add_argument("--peer-binary", default="/opt/core-allocation-pipeline/build/latprobe")
        q.add_argument("--peer-cpu", type=bounded(0, 1023), default=0)
        q.add_argument("--address", default="127.0.0.1", help="receiver IPv4 address reachable from sender")
        q.add_argument("--port", type=bounded(1, 65535), default=41000)
        q.add_argument("--source-port", type=bounded(1, 65535), default=41001)
        q.add_argument("--interval-us", type=bounded(1, 10000000), default=100)
        q.add_argument("--burst", type=bounded(1, 10000000), default=1000)
        q.add_argument("--quiet-us", type=bounded(0, 10000000), default=10000)
        q.add_argument("--packet-size", type=bounded(40, 9000), default=64)
        q.add_argument("--reply-timeout-ms", type=bounded(1, 60000), default=1000)
        q.add_argument("--network-warmup-samples", type=bounded(1, 100000), default=1000)
    recover = sub.add_parser("recover", help="restore a same-boot interrupted run's settings journal")
    recover.add_argument("journal")
    recover.add_argument("--apply", action="store_true", required=True)
    compare = sub.add_parser("compare-rcu", help="validate and compare wake/poll captures from two boots")
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--candidate", required=True)
    compare.add_argument("--output", required=True)
    graph = sub.add_parser("graph", help="render offline SVG/PNG plots and optional BPF flame graphs")
    graph.add_argument("run_directory")
    graph.add_argument("--output", help="new output directory; defaults to RUN/graphs")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.command == "probe":
            data = probe(args.interface)
            if args.bpf:
                from .bpf import capabilities
                data["bpf"] = capabilities()
            if args.output:
                atomic_json(args.output, data)
            else:
                print(json.dumps(data, indent=2))
            return 0
        if args.command in {"plan", "run"}:
            args.bpf = args.bpf or args.bpf_stacks
            if args.gap_us is None:
                args.gap_us = 100 if args.case in {"elc", "idle"} else 0
            if not args.output:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
                args.output = f"results/{stamp}-{args.case}"
            if args.command == "plan":
                data = plan(args)
                print(json.dumps(data, indent=2))
                return 0 if data["supported"] else 3
            return run(args)
        if args.command == "recover":
            with HostLock():
                print(json.dumps(Transaction.recover(args.journal), indent=2))
            return 0
        if args.command == "compare-rcu":
            print(json.dumps(compare_rcu(args.baseline, args.candidate, args.output), indent=2))
            return 0
        if args.command == "graph":
            from .graphs import generate
            print(generate(args.run_directory, args.output))
            return 0
    except KeyboardInterrupt:
        print("Interrupted; inspect report.json and settings.json for restoration status.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"metalbench: {exc}", file=sys.stderr)
        return 2
