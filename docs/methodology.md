# Measurement contract

## What is measured

Memory samples time a **batch** of dependent loads (default 64), including two
clock reads. Batch p99.9 divided by 64 is not the p99.9 of an individual load.
The worker fixes its random permutation seed between variants, first-touches
memory after binding to the victim CPU, disables transparent huge pages for its
own allocation, warms the loop, and optionally locks pages. It does not change
the host THP policy. Existing NUMA memory policy/cpuset constraints can override
first-touch locality; inspect the host configuration when that matters.

For gapped memory tests, `batch_ns` starts after the sleep returns.
`wake_lateness_ns` measures how late that return is relative to the requested
absolute wake time. `wakeup_plus_batch_ns` includes both. This distinguishes
idle/scheduler wake delay from the cost of the subsequent memory accesses.
No timing-overhead subtraction is performed.
`sample_offset_ns` records each batch's completion offset using the already-read
end timestamp. UDP `reply_offset_ns` uses the sender's received timestamp. These
coordinates are excluded from latency percentiles and used only for graph axes.

The TLB control changes mappings in an arena distinct from the victim data.
Both workloads run on two physical cores. Moving the noise to another process
removes its shared-mm invalidation requirement but does not remove shared cache,
memory-bandwidth, kernel-global or IRQ interference. The experiment therefore
tests a practical architecture change, not an isolated instruction cost. Compare
`noise_ops_per_second` and `noise_missed_periods`, and use TLB/IPI tracing in a
separate diagnostic pass to establish the mechanism.

ELC is exercised by intermittent random memory batches. An effect may depend on
the idle gap, cache footprint and whether the selected domain's fabric serves
that CPU/memory path. The harness does not claim that a writable ELC file implies
a particular AWS firmware implementation or a measurable change in frequency.

The idle test applies a per-CPU request and reads idle-state counters around each
trial. It does not override a stricter global request, a firmware limit, or a
boot-time C-state cap. Keep the runner and agents away from the victim to permit
real idle residency. This implementation tests constraining the victim; a
package-power/turbo experiment with unconstrained spare cores needs a separately
prepared global policy.

I/O cache trials use actual remote incoming packets, wait for traffic before
releasing the memory victim, and reject a load generator that finishes too soon.
The selected cache ID must be relevant to the victim and DMA path. ENA/PCIe
locality, cache-injection support, mask effectiveness and achieved receive rate
are additional experimental evidence; configuration readback alone is insufficient.

Network RTT is measured entirely using the sender's monotonic clock. It includes
both network directions, sender kernel overhead, receiver processing and the
echo. It does not isolate a receiver-side improvement from changes in the sender
or AWS fabric. Use the same peer, route, placement, ports and load pattern for
all variants, and repeat the experiment at different times.

Packets include a run cookie and sequence number; old replies cannot satisfy a
new run. A fixed source port preserves the flow hash across worker restarts.
The receiver reads its incoming NAPI ID on every packet and returns it in the
reply. Its epoll context contains one socket, meeting the same-NAPI requirement.
The server performs one receive/echo per epoll iteration. This is a deliberate
reference workload, not a model of arbitrary application batching.

The sender transmits according to an independent schedule. It records missed
slots instead of compressing them into a burst. Samples exist only for received
replies. Both missing sends and dropped replies are visible and disqualify the
trial from automatic paired statistics. Tail loss can otherwise make a tuning
look faster. A no-reply trial has zero samples, never zero latency.

Quiet-period samples are identified from the sender's schedule and use the
first sequence number of each burst after startup. If that packet is lost or
its slot is missed, that quiet period contributes no latency sample. Inspect
loss and sample counts; the metric is not a corrected estimate for missed
first packets.

The RCU worker creates, binds and closes UDP sockets on the selected CPU.
Upstream UDP binding marks sockets for RCU freeing. It exercises callback
enqueue/lifetime work but its latency also includes allocation and bind-table
work. RCU callback batching, grace-period progress and housekeeping load may
vary across boots. The report deliberately calls the two-boot comparison
descriptive. Collect trace/counter evidence and multiple alternating boots before
attributing a production result to `rcu_nocb_poll`.

## Statistical interpretation

Quantiles use the nearest-rank definition. There is no histogram truncation,
outlier deletion, normal-distribution assumption, or interpolation that invents
subnanosecond measurements. Raw sample order is preserved in JSON arrays.

Each round has two observations per variant in a palindromic order. The paired
comparison uses each variant's median trial p99.9 within that round, then the
candidate/baseline percentage change. A round must have both valid replicates
of each compared variant. With five rounds, a deterministic 2,000-resample
bootstrap over complete round-level percentage changes supplies a descriptive
95% interval. It is not a correction for time drift or autocorrelated rounds.
Run longer, alternate order across separate runs, and examine each trial.

The primary metric differs by experiment; secondary metrics are retained.
Reports never pool all runs into one percentile or automatically promote a
candidate. The p99.99 minimum-tail heuristic only checks sample count. Rate
equivalence, CPU frequency, temperature, service demand and observed interference
still matter.

## Operational boundaries

The harness does not change boot arguments, NIC hardware coalescing, RSS, IRQ
affinity, routing, security groups, governors, SMT, mitigations, hugepage pools,
or filesystem mounts. It only changes controls explicitly listed by `plan`.
Threaded NAPI's thread affinity is included in snapshot/restoration. No raw MSR
writes or guessed SKU-to-topology mapping are used.

Netlink request errors, readback mismatches, missing interfaces, malformed replies,
partial dumps and restoration failures are explicit errors. Unsupported features
are reported without substituting an unrelated tuning. A mutation journal is
synced before each write. Child workers are terminated and waited for before
normal cleanup. SIGKILL requires manual same-boot journal recovery after stopping
remaining workers. Remote senders have bounded workloads; killing the local SSH
client does not constitute a guarantee that a remote process has exited.

This development environment can exercise memory, socket, pacing, recovery and
report logic. It cannot validate AWS metal-only controls or infer production
latency improvements. Run the documented capability-gated experiments on the
actual 7.x AWS kernel/ENA/instance combination.

Optional BPF captures are diagnostic runs with additional observer effects.
See [BPF graphing](bpf-graphing.md) for probe semantics, clock boundaries, bounded
aggregation, unavailable signals and flame-graph interpretation.
