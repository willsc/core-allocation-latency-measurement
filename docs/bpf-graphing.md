# eBPF diagnostics and graphing

Use the untraced harness for the acceptance comparison. Repeat selected cases
with BPF to explain kernel interference and CPU execution. The report records
`diagnostic: true`; BPF-instrumented percentiles are not interchangeable with
uninstrumented ones.

## Capture

```sh
python3 -m metalbench probe --interface ens5 --bpf --output host.json

sudo python3 -m metalbench run tlb --cpu 24 --noise-cpu 25 \
  --samples 200000 --rounds 3 --memory-mb 8 \
  --bpf --bpf-events sched,tlb,irq,softirq \
  --bpf-stacks --bpf-hz 99 --graphs --output results/tlb-traced
```

The same flags work with `elc`, `idle`, `io-cache`, `napi`, `rcu`, and `network`.
Hardware tuning still needs `--apply`. Tracing alone does not require that flag.

| Flag | Meaning |
|---|---|
| `--bpf` | Enable available groups from the requested event set |
| `--bpf-events irq,softirq,sched,tlb,rcu,idle` | Default event groups; use a subset to reduce overhead, or `none` for stack sampling alone |
| `--bpf-cpus 24,25` | Retain events on one to four CPUs; default is the victim CPU |
| `--bpf-stacks` | Enable kernel and user stack sampling; implies `--bpf` |
| `--bpf-hz 99` | Stack sample rate, between 1 and 199 Hz |
| `--bpf-bin-ms 100` | Event aggregation bucket width |
| `--bpf-max-bins 512` | Number of event buckets, at most 1024 |
| `--graphs` | Render graphs at the end, using matplotlib |

The default time range is **51.2 seconds per trial**. For a trial lasting up to
ten minutes, use `--bpf-bin-ms 1000 --bpf-max-bins 1024`. Events beyond the chosen
range increment an overflow counter; such captures are marked partial. Maps
have a finite key limit. Helper failures and lost output are recorded, not
silently interpreted as an idle machine.

The bpftrace userspace process inherits the runner's housekeeping affinity. The
probe hooks are **systemwide**, with CPU predicates controlling which data are
retained. Profile probes may generate interrupts on all online CPUs even though
only selected CPUs contribute stacks. CPU filtering does not eliminate all
observer overhead on other cores. Start with event-only tracing and add sampling
when needed.

The collector attaches while native workers are alive, after memory warmup or
network warmup, and before measured traffic/work is released. This also allows
user symbol caches to inspect the workers' mappings. Incoming background DMA
traffic for `io-cache` starts after tracer attachment so compilation cannot use
up the load window. Exact generated programs and bpftrace versions are retained.

## What each graph means

| Signal | Meaning and limits |
|---|---|
| IRQ handler count/time | Device handler entry/exit tracepoints; not the complete interrupt-entry/exit cost |
| Softirq count/time | Softirq entry/exit on selected CPUs; includes time when interrupted by higher-priority work |
| Wake-to-run delay | Time from an observed `sched_wakeup` to a later `sched_switch` on a selected CPU; excludes pure preemption/requeue delays and unobserved wakeups |
| TLB count | `tlb_flush` tracepoint events, including local flushing; not a direct count of remote shootdown IPIs |
| RCU enqueue/invoke | Callback tracepoint counts where those kernel tracepoints exist; include housekeeping CPUs to observe offloaded invocation |
| Idle entries/time | Completed idle intervals and entries, attributed to their completion buckets; not a full PMU power measurement |
| Kernel/user flame graph | Sampled execution stacks; width is **sample count**, not latency, wall-clock duration, or time blocked off CPU |

Counts are shown as events/second. Completed interval time is shown as µs/second;
wake-delay maxima have their own µs axis. Rates use the observed bucket duration,
including a shorter final bucket. Missing buckets in partial captures appear as
gaps rather than zero activity. Durations can overlap and span buckets,
so do not add IRQ/softirq/idle durations as if they were exclusive CPU percentages.
Partially observed entry/exit pairs at capture boundaries are excluded.

Native memory/RCU samples and BPF events share `CLOCK_MONOTONIC` on the receiver.
A green span identifies the measured portion of a local memory/RCU test in the
event timeline. Remote UDP RTT uses the **sender's** clock. The renderer keeps
it on a separate time axis and does not infer per-packet correlation or one-way
latency from unsynchronised clocks.

The latency timeline reduces display size using per-bin medians and maxima.
Every spike remains represented by a bin maximum. Full raw arrays remain in the
trial directory. Older result files without sample offsets use sample index as
the x axis rather than inventing sample times.

User stacks need frame pointers and available symbols. The default native build
provides them. Inlining, JIT code, missing debug symbols, short captures and
stack-helper failures can limit resolution. Empty stacks are explicitly labelled
`[empty or unavailable stack]`; unresolved addresses are kept, never assigned a
guessed function name. Kernel and user flame graphs are separate sample sets.
They include **all tasks running on the selected CPUs**, including background
services, and cover the full capture window rather than only the timed worker
loop. Capture startup and shutdown activity can appear in those stacks.

## Render and share

```sh
python3 -m metalbench graph results/tlb-traced
```

This creates `results/tlb-traced/graphs/` with:

* `index.html`: a static gallery that works offline.
* `overview.svg` / `.png`: per-trial percentile comparison with invalid-trial bands.
* `trial-NNN-latency.svg` / `.png`: latency timeline.
* `trial-NNN-bpf.svg` / `.png`: available kernel event timelines.
* `trial-NNN-kernel_stacks.svg` and `trial-NNN-user_stacks.svg`, plus PNG variants:
  sampled-stack flame graphs when samples were captured.
* `.folded` files: root-first collapsed stacks for use with other flame-graph tools.
* `manifest.json`: plot descriptions and capture warnings.

The directory is self-contained; there are no external JavaScript, font, analytics
or CDN requests. SVG and PNG figures can be copied into reports. Graph output
directories must be new; use `--output NEW_DIRECTORY` when rendering again.

## Availability, errors and cleanup

Discovery checks bpftrace's version, readable tracepoint formats and required
fields. The kernel still decides whether BPF loading and perf attachment are
permitted. The actual attach can fail because of permissions, lockdown, missing
kernel support, tool/kernel compatibility or resource limits. Failure records
stderr and stops the requested traced run; it never claims tracing was active.

Missing event groups are listed individually. If no requested group is available
and stack sampling is off, the experiment is skipped. A complete capture with no
events is distinct from an unavailable probe or a capture that lost data.

The collector aggregates events in time-indexed maps and prints them once after
detaching. It does not repeatedly print and clear live maps, which would race
with kernel updates. Normal failures and interrupts terminate the collector,
wait for map output, and restore the benchmark's tuning transaction. Forced
termination or missing end markers makes the capture failed/partial. SIGKILL can
leave workers or bpftrace alive: stop those processes before same-boot tuning
recovery. No BPF programs or maps are pinned into bpffs by this harness.

Sources: [bpftrace language and configuration](https://bpftrace.org/docs/0.21),
[clock and aggregation functions](https://bpftrace.org/docs/release_023/stdlib),
[upstream profiling examples](https://bpftrace.org/one-liners).
