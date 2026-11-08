# tlb benchmark

Status: **complete**

Latency units: nanoseconds. Each row is one trial; batch latency is not single-load latency.

| Trial | Variant | Status | Samples | p50 | p99 | p99.9 | p99.99 | Max |
|---|---|---|---:|---:|---:|---:|---:|---:|
| 0 | shared-mm | ok | 2000 | 1,824 | 11,604 | 13,407* | 20,017* | 20,017 |
| 1 | separate-mm | ok | 2000 | 1,888 | 11,181 | 15,940* | 24,892* | 24,892 |
| 2 | quiet | ok | 2000 | 891 | 11,088 | 12,870* | 15,116* | 15,116 |
| 3 | quiet | ok | 2000 | 1,175 | 11,150 | 14,273* | 24,674* | 24,674 |
| 4 | separate-mm | ok | 2000 | 1,460 | 11,250 | 17,347* | 27,485* | 27,485 |
| 5 | shared-mm | ok | 2000 | 1,460 | 10,462 | 12,055* | 17,262* | 17,262 |

*Asterisk: fewer than 20 expected observations beyond that quantile; exploratory only.*

victim CPU is not boot-isolated; scheduler noise may dominate

this host is not running the target 7.x kernel; local results are harness validation only

BPF diagnostic run: probe hooks and profile interrupts change timing; repeat without tracing for acceptance

Trial 0 (shared-mm): mapping churn missed scheduled periods; compare achieved interference rates; batch_ns: insufficient samples for p99.9, p99.99; wake_lateness_ns: insufficient samples for p99.9, p99.99; wakeup_plus_batch_ns: insufficient samples for p99.9, p99.99.

Trial 1 (separate-mm): mapping churn missed scheduled periods; compare achieved interference rates; batch_ns: insufficient samples for p99.9, p99.99; wake_lateness_ns: insufficient samples for p99.9, p99.99; wakeup_plus_batch_ns: insufficient samples for p99.9, p99.99.

Trial 2 (quiet): batch_ns: insufficient samples for p99.9, p99.99; wake_lateness_ns: insufficient samples for p99.9, p99.99; wakeup_plus_batch_ns: insufficient samples for p99.9, p99.99.

Trial 3 (quiet): batch_ns: insufficient samples for p99.9, p99.99; wake_lateness_ns: insufficient samples for p99.9, p99.99; wakeup_plus_batch_ns: insufficient samples for p99.9, p99.99.

Trial 4 (separate-mm): mapping churn missed scheduled periods; compare achieved interference rates; batch_ns: insufficient samples for p99.9, p99.99; wake_lateness_ns: insufficient samples for p99.9, p99.99; wakeup_plus_batch_ns: insufficient samples for p99.9, p99.99.

Trial 5 (shared-mm): mapping churn missed scheduled periods; compare achieved interference rates; batch_ns: insufficient samples for p99.9, p99.99; wake_lateness_ns: insufficient samples for p99.9, p99.99; wakeup_plus_batch_ns: insufficient samples for p99.9, p99.99.

Paired round comparison (candidate relative to baseline):

```json
{
  "paired_rounds": 1,
  "round_changes_percent": [
    30.73207132197
  ],
  "median_change_percent": 30.73207132197,
  "negative_means": "lower latency",
  "interpretation": "fewer than five independent rounds; descriptive comparison only"
}
```

Raw measurements, effective settings, recovery journals and host counters are in the trial directories.
No synthetic benchmark result alone establishes a production latency improvement.
