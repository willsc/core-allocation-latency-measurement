"""Build an ILLUSTRATIVE napi-shaped result directory and render it with metalbench.

The numbers are synthetic. They exist only to exercise graph types the local smoke
run did not produce (UDP RTT on the sender clock, flame graphs, an invalid trial,
a partial BPF capture). They are not measurements of any host.
"""
import json
import math
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if len(sys.argv) != 2:
    sys.exit("usage: python3 docs/graph-examples/make_synthetic_napi.py NEW_OUTPUT_DIRECTORY")
OUT = Path(sys.argv[1])
sys.path.insert(0, str(REPO))
from metalbench.graphs import generate  # noqa: E402
from metalbench.stats import distribution  # noqa: E402

rng = random.Random(7)
PPS, SECONDS = 20000, 10
N = PPS * SECONDS
VICTIM = 24


def rtt_samples(variant):
    base, sigma = (27000, .18) if variant == "irq" else (21000, .12)
    values, offsets = [], []
    for i in range(N):
        t = i / PPS
        v = rng.lognormvariate(math.log(base), sigma)
        # Periodic housekeeping burst (e.g. a timer-driven kworker) every ~2 s.
        if (t % 2.0) < .015:
            v += rng.uniform(40000, 160000 if variant == "irq" else 60000)
        # Rare isolated tail spikes.
        if rng.random() < (2e-4 if variant == "irq" else 6e-5):
            v += rng.uniform(80000, 450000)
        values.append(int(v))
        offsets.append(int(i * 1e9 / PPS + rng.uniform(0, 30000) + v))
    return values, offsets


def kstack(*frames):
    """bpftrace kstack text is leaf-first."""
    return "\n" + "".join(f"        {f}\n" for f in reversed(frames))


IDLE = ["common_startup_64", "start_secondary", "cpu_startup_entry", "do_idle",
        "cpuidle_enter", "cpuidle_enter_state"]
IRQ = IDLE + ["asm_common_interrupt", "common_interrupt", "irq_exit_rcu", "handle_softirqs",
              "net_rx_action", "__napi_poll", "ena_io_poll"]
SYS = ["entry_SYSCALL_64_after_hwframe", "do_syscall_64"]


def kernel_stacks(variant):
    s = {
        kstack(*IDLE, "intel_idle"): 610 if variant == "irq" else 120,
        kstack(*IRQ, "ena_clean_rx_irq", "napi_gro_receive", "netif_receive_skb_list_internal",
               "ip_list_rcv", "udp_rcv", "__udp4_lib_rcv", "udp_queue_rcv_skb"): 95 if variant == "irq" else 10,
        kstack(*IRQ, "ena_clean_tx_irq", "napi_consume_skb"): 24 if variant == "irq" else 3,
        kstack(*SYS, "__x64_sys_epoll_wait", "do_epoll_wait", "ep_poll", "schedule_hrtimeout_range",
               "schedule", "__schedule"): 70 if variant == "irq" else 15,
        kstack(*SYS, "__x64_sys_epoll_wait", "do_epoll_wait", "ep_poll", "napi_busy_loop",
               "__napi_poll", "ena_io_poll", "ena_clean_rx_irq", "napi_gro_receive"): 4 if variant == "irq" else 520,
        kstack(*SYS, "__x64_sys_recvmsg", "__sys_recvmsg", "___sys_recvmsg", "inet_recvmsg",
               "udp_recvmsg", "skb_copy_datagram_iter"): 85 if variant == "irq" else 140,
        kstack(*SYS, "__x64_sys_sendto", "__sys_sendto", "udp_sendmsg", "udp_send_skb",
               "ip_output", "ip_finish_output2", "__dev_queue_xmit", "ena_start_xmit"): 110 if variant == "irq" else 175,
        kstack("ret_from_fork_asm", "ret_from_fork", "kthread", "worker_thread", "process_one_work",
               "vmstat_update"): 8,
        "": 30,
    }
    return s


def ustack(*frames):
    return "\n" + "".join(f"        {f}\n" for f in reversed(frames))


MAIN = ["_start", "__libc_start_main", "__libc_start_call_main", "main", "echo_worker"]


def user_stacks(variant):
    return {
        "": 640 if variant == "irq" else 130,  # idle task / kernel threads have no user stack
        ustack(*MAIN, "epoll_wait"): 80 if variant == "irq" else 530,
        ustack(*MAIN, "recvmsg"): 90 if variant == "irq" else 145,
        ustack(*MAIN, "sendto"): 115 if variant == "irq" else 180,
        ustack(*MAIN): 18,
        ustack(*MAIN, "7f3a2c1e4b20"): 6,  # unresolved address is kept, not guessed
    }


def capture(variant, partial):
    bins = SECONDS * 10 + 5
    series = {k: [] for k in ("irq_count", "irq_ns", "softirq_count", "softirq_ns", "runq_count",
                             "runq_ns", "runq_max", "idle_count", "idle_ns")}
    gap = range(48, 61) if partial else range(0)
    for b in range(bins):
        if b in gap:
            continue  # lost map output -> renderer leaves a gap instead of zero
        t = b / 10
        burst = (t % 2.0) < .1
        if variant == "irq":
            irq = int(rng.gauss(2000, 60)); soft = int(irq * rng.uniform(.95, 1.05))
            idle_n = int(rng.gauss(2050, 80)); idle_t = int(rng.gauss(58e6, 2e6))
        else:
            irq = int(rng.gauss(35, 8)); soft = int(rng.gauss(60, 10))
            idle_n = int(rng.gauss(140, 20)); idle_t = int(rng.gauss(11e6, 1e6))
        series["irq_count"].append(irq); series["irq_ns"].append(int(irq * rng.uniform(1800, 2600)))
        series["softirq_count"].append(soft)
        series["softirq_ns"].append(int(soft * rng.uniform(5500, 8000) * (1.6 if burst else 1)))
        rq = int(rng.gauss(2010 if variant == "irq" else 45, 30 if variant == "irq" else 6)) + (40 if burst else 0)
        series["runq_count"].append(rq)
        series["runq_ns"].append(int(rq * rng.uniform(2500, 3500) * (3 if burst else 1)))
        series["runq_max"].append(int(rng.uniform(9000, 22000) + (rng.uniform(60000, 150000) if burst else 0)))
        series["idle_count"].append(idle_n); series["idle_ns"].append(idle_t)
    rows = {}
    present = [b for b in range(bins) if b not in gap]
    for name, values in series.items():
        rows[name] = [{"cpu": VICTIM, "bin": b, "value": max(0, v)} for b, v in zip(present, values)]
    ready = 5_000_000_000
    return {
        "schema": 1, "clock": "receiver CLOCK_MONOTONIC", "diagnostic": True,
        "status": "partial" if partial else "complete",
        "config": {"bin_ms": 100, "max_bins": 512, "cpus": [VICTIM], "hz": 99, "stacks": True,
                   "groups": ["irq", "softirq", "sched", "idle"],
                   "skipped": {"rcu": ["rcu/rcu_callback format unavailable"]}},
        "markers": {"READY": ready, "END": ready + int((bins - .5) * 1e8)},
        "overflow": 0,
        "warnings": ["lost_events: 13 buckets missing from map output"] if partial else [],
        "series": rows,
        "stacks": {"kernel_stacks": kernel_stacks(variant), "user_stacks": user_stacks(variant)},
    }


OUT.mkdir(parents=True, exist_ok=False)
report = {"schema": 1, "case": "napi (ILLUSTRATIVE synthetic data)", "status": "complete",
          "diagnostic": True, "primary_metric": "rtt_ns", "trials": [],
          "warnings": ["Synthetic example data for graph illustration; not a measurement"]}
plan = [("irq", 0), ("epoll", 0), ("epoll", 1), ("irq", 1), ("irq", 2), ("epoll", 2)]
for index, (variant, rnd) in enumerate(plan):
    d = OUT / f"{index:03d}-{variant}"
    d.mkdir()
    values, offsets = rtt_samples(variant)
    status = "invalid" if index == 3 else "ok"
    if status == "invalid":
        values, offsets = values[: N // 5], offsets[: N // 5]  # aborted early
    (d / "raw.json").write_text(json.dumps({"kind": "udp-client", "rtt_ns": values,
                                            "reply_offset_ns": offsets}))
    dist = distribution(values)
    trial = {"index": index, "variant": variant, "round": rnd, "directory": d.name, "status": status,
             "summary": {"metrics": {"rtt_ns": dist}, "warnings": []},
             "warnings": ["sender lateness exceeded threshold; trial invalid"] if status == "invalid" else []}
    if index in (0, 1, 2):
        (d / "bpf").mkdir()
        (d / "bpf/capture.json").write_text(json.dumps(capture(variant, partial=(index == 2))))
    report["trials"].append(trial)
(OUT / "report.json").write_text(json.dumps(report))
print(generate(OUT))
