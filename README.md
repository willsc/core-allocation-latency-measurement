# AWS metal latency benchmarks

Benchmark harnesses for **Linux 7.x AWS kernels on bare-metal instances**. The
runner probes the actual kernel, ENA and CPU interfaces. A kernel version or an
instance-family name alone never enables an experiment.

| Command | Experiment | Measurement |
|---|---|---|
| `tlb` | Mapping churn in a thread vs a separate process, plus a quiet control | Random dependent-load batch latency and achieved churn rate |
| `elc` | Current Intel ELC policy vs a specified uncore floor/low-load threshold | Memory bursts after idle; wake delay and batch latency separately |
| `io-cache` | Current I/O cache allocation vs a specified `io_alloc_cbm` mask | Memory latency while a second host supplies ENA receive traffic |
| `idle` | Current per-CPU PM QoS request vs a tighter request | Timer wake lateness plus memory work, with idle residency snapshots |
| `napi` | IRQ delivery, software IRQ deferral, epoll IRQ suspension, optional threaded busy polling | Open-loop UDP application RTT, quiet-period tails, loss and sender lateness |
| `rcu` | Captures on boots with and without `rcu_nocb_poll` | UDP socket create/bind/close latency on an offloaded CPU |
| `network` | Unmodified network baseline / flow discovery | Same UDP measurement without changing NAPI settings |

The C worker uses `CLOCK_MONOTONIC`, CPU affinity, prefaulted measurement buffers,
and raw samples retained until measurement ends. Python uses only the standard
library. There are no Python callbacks in the timed packet or memory paths.

Optional **eBPF diagnostics and offline graphs** explain what happened during a
trial: IRQ/softirq activity, wake-to-run delay, TLB flushes, RCU callbacks, idle
transitions, and sampled kernel/user flame graphs. Exports are SVG, PNG and folded
stacks, with a local HTML gallery. [BPF and graphing guide](docs/bpf-graphing.md).

## Recommended workflow

1. Build and run `probe` on the actual 7.x AWS metal host.
2. Use `plan` to inspect the selected experiment and hardware support.
3. Capture an **untraced baseline/candidate run** for latency comparison.
4. Repeat with `--bpf --bpf-stacks` to investigate its mechanism.
5. Run `graph` on either result directory and inspect validity/sample warnings.

Example diagnostic capture, after selecting real CPU IDs from the inventory:

```sh
make
python3 -m metalbench probe --interface ens5 --bpf --output host.json

sudo python3 -m metalbench run tlb --cpu 24 --noise-cpu 25 \
  --memory-mb 8 --samples 200000 --rounds 3 \
  --bpf --bpf-stacks --graphs --output results/tlb-diagnostic
```

Open `results/tlb-diagnostic/graphs/index.html`. To graph an existing run on a
different machine, copy its complete result directory and run:

```sh
python3 -m metalbench graph results/tlb --output results/tlb-plots
```

BPF is opt-in and requires `bpftrace >= 0.20` plus permission to load BPF/perf
programs, typically root. Graph rendering requires `matplotlib` only on the
machine rendering the graphs. For Ubuntu-based images, the optional packages are:

```sh
sudo apt-get install bpftrace python3-matplotlib
```

The normal benchmark commands work without these packages. The harness probes
individual tracepoints and reports missing groups; an AWS 7.x version string
does not guarantee that RCU tracing or every other probe was compiled in.

## Build and inspect

Requirements: Linux, Python **3.10+**, a C11 compiler, Make and pthreads. Install
`iproute2`, `ethtool`, and an SSH client for network experiments. Build the same
checkout on the sender; it needs the native worker and SSH access, without root.
The default C build includes debug information and frame pointers for sampled
user stacks. Rebuild both sides from the same source when changing build flags.

```sh
make
make test
python3 -m metalbench probe --interface ens5 --output host.json
python3 -m metalbench --help
```

Validation in this workspace: **63 tests passed**, including native UDP tests,
failed-attach cleanup, partial-capture reporting and graph exports. Live event
capture completed all six trials on local Linux **6.17.0-35-generic** with
bpftrace **0.20.2**. Stack sampling also produced flame graphs, with stack-helper
failures explicitly marked partial. Actual **7.x AWS metal validation remains
to be run**; these local checks establish harness behaviour, not tuning gains.

Use the inventory to choose CPUs on the intended NUMA/cache domains. Keep the
victim, interference/poller, sender, and runner on different physical cores.
The runner automatically chooses a non-isolated housekeeping CPU; specify
`--monitor-cpu` to choose one. It refuses an SMT sibling as the noise/poller CPU.

The commands below use example IDs: victim **24**, noise/poller **25**, and remote
sender **2**. Replace them with the actual host topology. Replace `10.0.1.10`,
`sender-host`, the uncore domain, cache mask and NAPI ID with observed values.

## TLB interference

```sh
python3 -m metalbench plan tlb --cpu 24 --noise-cpu 25
python3 -m metalbench run tlb --cpu 24 --noise-cpu 25 \
  --memory-mb 8 --samples 200000 --rounds 5 \
  --churn-interval-us 100 --output results/tlb
```

Each interference cycle toggles a separate 2 MiB mapping read-only/read-write and
touches its pages. The victim walks a random cache-line permutation. Both cases
use the same noise CPU and requested churn interval. The thread shares the
victim's address space; the forked worker has its own address space. A third
variant has no interference. Inspect achieved operations/sec and missed periods:
different interference rates confound the comparison. Fewer than 100 `mprotect`
operations during a trial makes it invalid. `--churn-interval-us 0` requests
unpaced maximum pressure and is a different experiment.

## Intel ELC and per-core idle constraints

```sh
python3 -m metalbench plan elc --cpu 24 \
  --uncore-dir /sys/devices/system/cpu/intel_uncore_frequency/uncore00 \
  --floor-khz 1800000

sudo python3 -m metalbench run elc --cpu 24 \
  --uncore-dir /sys/devices/system/cpu/intel_uncore_frequency/uncore00 \
  --floor-khz 1800000 --elc-low-percent 100 \
  --memory-mb 256 --gap-us 100 --samples 200000 --rounds 5 \
  --apply --output results/elc

sudo python3 -m metalbench run idle --cpu 24 --idle-latency-us 1 \
  --memory-mb 8 --gap-us 100 --samples 200000 --rounds 5 \
  --apply --output results/idle
```

ELC changes only the selected domain's `elc_floor_freq_khz` and
`elc_low_threshold_percent`. It requires a floor within the current min/max
range. Select the domain associated with the victim; the harness does not infer
PCIe/fabric wiring from the AWS SKU. A candidate identical to the current values
is rejected.

The idle experiment changes only the victim's `pm_qos_resume_latency_us`. It
does not remove global boot C-state caps or other applications' PM QoS requests.
Check the before/after idle-state usage/time counters. An already constrained
machine can show no change. The default candidate is **1 microsecond**; Linux
device PM QoS uses special values, so this CLI does not use zero as a request to
disable all idle states. Allowing spare cores deeper sleep requires a separately
prepared baseline without the global cap.

These burst tests can take several minutes. Increase `--trial-timeout` when
`samples × gap` approaches its default 600-second limit. Use different working
set sizes to distinguish cache, translation and DRAM effects.

## Network and NAPI

Build `build/latprobe` on a second host. Its default remote path is
`/opt/core-allocation-pipeline/build/latprobe`; override with `--peer-binary`.
Allow the benchmark's UDP port **41000** through the existing host/network
policy. The harness does not alter firewall or AWS security-group rules.

First identify the NAPI serving the test flow:

```sh
python3 -m metalbench run network --cpu 24 --interface ens5 \
  --address 10.0.1.10 --peer sender-host --peer-cpu 2 \
  --samples 2000 --rounds 1 --output results/flow-discovery

python3 -c 'import json; print(json.load(open("results/flow-discovery/000-current/raw.json"))["first_napi_id"])'
```

Then use that ID, retaining the same addresses and source/destination ports:

```sh
sudo python3 -m metalbench plan napi --cpu 24 --interface ens5 --napi-id 123 \
  --address 10.0.1.10 --peer sender-host --peer-cpu 2

sudo python3 -m metalbench run napi --cpu 24 --interface ens5 --napi-id 123 \
  --address 10.0.1.10 --peer sender-host --peer-cpu 2 \
  --modes irq,software,epoll --gro-ns 20000 --defer-irqs 2 \
  --busy-us 20 --suspend-ns 100000 \
  --samples 200000 --rounds 5 --interval-us 100 \
  --burst 1000 --quiet-us 10000 --apply --output results/napi
```

The receiver uses epoll in every variant. All settings use the generic-netlink
per-NAPI API, so unrelated queues retain their settings. Hardware coalescing,
IRQ affinity, RSS, ring sizes and offloads are recorded and left unchanged.

* `irq`: software deferral and IRQ suspension are zero; epoll busy polling is off.
* `software`: the 20 µs/two-empty-poll software-deferral baseline, without busy polling.
* `epoll`: software deferral plus `EPIOCSPARAMS` busy polling/preference and
  `irq-suspend-timeout`. The ioctl settings are read back too.
* `threaded`: continuous NAPI busy polling with the kernel thread pinned to
  `--noise-cpu`. Add `--modes irq,software,epoll,threaded --noise-cpu 25` to test it.
  The driver must support that mode; a rejected unsupported operation is reported
  as skipped after restoration. Ordinary threaded NAPI is not equivalent to
  continuous busy polling.

The test checks `SO_INCOMING_NAPI_ID` on received packets. A flow reaching a
different queue or changing NAPI IDs makes the trial invalid. Keep the fixed
`--source-port` (default 41001), destination and ports stable across variants.
The receiver's NAPI-ID check adds a syscall per packet equally to all variants;
the measured RTT includes that overhead and the echo operation.

The sender is **open loop**: a slow reply never delays the next scheduled send.
It records send-to-reply RTT, scheduled-send-to-reply time, missed send slots,
send errors, duplicates, reordering and packet loss. It skips overdue slots
instead of generating catch-up bursts. Lost packets remain losses, not invented
latency samples. Any missed send slots, send errors or lost replies invalidate a
trial for the automatic paired comparison; raw results remain available.

The quiet-period subset contains the first successful reply after each scheduled
gap, excluding startup. With 200,000 packets and 1,000-packet bursts it contains
only about 199 samples: use many more gaps or a smaller burst to assess its tail.
RTT needs no cross-host clock synchronisation. It is **not** NIC-to-application
one-way latency or a PHC hardware timestamp measurement.

Local functional check (no tuning changes):

```sh
python3 -m metalbench run network --cpu 1 --local-peer --peer-cpu 2 \
  --samples 1000 --rounds 1 --interval-us 500 --burst 100 \
  --output results/loopback
```

Loopback/local-peer results cannot establish an ENA performance improvement.

## I/O cache allocation

This experiment needs an already mounted `resctrl` exposing `info/L3/io_alloc`
and `io_alloc_cbm`. A host with only ordinary CAT support is skipped. The
harness does not mount filesystems or load modules automatically.

```sh
sudo python3 -m metalbench plan io-cache --cpu 24 --noise-cpu 25 \
  --interface ens5 --address 10.0.1.10 --peer sender-host --peer-cpu 2 \
  --io-mask '0=00ff'

sudo python3 -m metalbench run io-cache --cpu 24 --noise-cpu 25 \
  --interface ens5 --address 10.0.1.10 --peer sender-host --peer-cpu 2 \
  --io-mask '0=00ff' --memory-mb 8 --samples 200000 --rounds 5 \
  --interval-us 10 --packet-size 1400 --load-seconds 10 \
  --apply --output results/io-cache
```

Choose the actual cache ID and allowed mask from the inventory; `0=00ff` is
only an example. Other cache IDs' masks are preserved. The candidate enables
I/O allocation if needed, but refuses to do so while other resctrl control
groups exist because enabling it can consume an allocation class.

The victim warms its working set before the remote load starts. Measurement is
released only after the UDP receiver observes traffic. The remote load must
outlast the memory measurement; otherwise the trial is invalid. Increase
`--load-seconds` for longer or gapped memory tests. Per-measurement NIC counters
are saved in `load-before.json` and `load-after.json`; compare achieved receive
rates across variants. The background stream is one-way and does not echo.

Readback proves the allocation setting was accepted. Whether ENA DMA actually
participates in that platform's cache-injection mechanism still needs hardware
counter evidence. A null result is not proof that ENA used the configured ways.

## RCU polling across boots

`rcu_nocb_poll` is treated as a boot-time treatment. This harness never edits
GRUB, reboots a host, or pretends to toggle it at runtime. Keep the kernel,
instance, isolation lists and all other boot/runtime tuning identical.

On a boot with `rcu_nocbs`/`nohz_full` covering CPU 24, without `rcu_nocb_poll`:

```sh
python3 -m metalbench run rcu --cpu 24 --rcu-state wake \
  --samples 200000 --rounds 5 --output results/rcu-wake
```

After preparing the otherwise identical boot with `rcu_nocb_poll`:

```sh
python3 -m metalbench run rcu --cpu 24 --rcu-state poll \
  --samples 200000 --rounds 5 --output results/rcu-poll
python3 -m metalbench compare-rcu --baseline results/rcu-wake \
  --candidate results/rcu-poll --output results/rcu-comparison.json
```

The label is checked against the running command line. The comparator rejects
same-boot captures, other boot-argument changes, topology/runtime-policy changes,
different workloads and different benchmark builds. The worker binds UDP
sockets so their lifetime uses the RCU-free path, but measured latency includes
allocation, port binding and closing. Inspect RCU activity and repeat alternating
boots before attributing an improvement to callback polling. Two boots provide
a descriptive comparison, not an independent causal estimate.

## Results, controls and recovery

Every run gets a new directory. Existing output directories are refused.

* `host.json`, `peer.json` where relevant, `parameters.json`, `provenance.json`,
  and `plan.json` record the machine, source hashes and workload.
* `report.md` and `report.json` contain each trial's percentiles, quality flags,
  and paired round changes. Five or more complete rounds also produce a
  bootstrap interval over round-level changes.
* Optional `graphs/index.html`, SVG/PNG plots and `.folded` stack files are
  generated by `--graphs` or the separate `graph` command.
* With BPF enabled, each trial's `bpf/` directory retains the exact program,
  raw JSONL, stderr and decoded `capture.json`, including unavailable probes,
  dropped output and bounded-map overflow warnings.
* Each trial retains raw arrays, stderr, before/after kernel/NIC counters,
  effective controls, and a durable `settings.json` recovery journal.
* A round runs variants forwards and then backwards: `A B B A`, or
  `A B C C B A`. Restore the original settings between every trial.
* Tail estimates with fewer than 20 expected observations beyond the quantile
  are marked. Roughly **200,000 valid samples** are the minimum for that check
  at p99.99; this heuristic does not guarantee statistical confidence.
* `--mlock` requires locking to succeed; it never silently falls back.
  Without it, buffers are prefaulted and faults during measurement are recorded.
* Optional `--telemetry-ms 20` logs frequency observations on the housekeeping
  CPU. Reading those sysfs controls can itself perturb the victim; repeat the
  main comparison with telemetry disabled (the default).

Mutating experiments require `run --apply`. The CLI first records each original
value, flushes the journal to disk, writes the candidate, and checks readback.
It restores and checks the originals on success, failure, SIGINT and SIGTERM.
A restoration failure stops the experiment and remains visible in the journal.
The host lock serializes this harness's tuning runs; it cannot lock out other
administrators or tuning daemons.

SIGKILL or a machine crash cannot run cleanup. After a killed process, recover
its journal **on the same boot**, once its workers are stopped:

```sh
sudo python3 -m metalbench recover results/napi/002-epoll/settings.json --apply
```

Recovery is restricted to the supported sysfs controls and the original
interface/NAPI identity. A prior-boot journal is rejected. Review
`restored: true` after recovery. Use a benchmark host where changing the selected
queue/domain is within the intended test scope.

Exit codes: `0` complete; `2` command/worker/restoration failure; `3` unsupported
experiment; `4` results include invalid or skipped trials; `130` interruption.
Code `4` also covers incomplete BPF diagnostics; the raw benchmark data remain
available. A requested BPF collector that fails to attach stops the run rather
than silently substituting an untraced run.
No result is automatically labelled a production tuning recommendation.

See [measurement details and limitations](docs/methodology.md) and
[upstream interfaces](docs/sources.md).
