"""Offline statistics; no averaging of percentiles across pooled raw samples."""
import json
import math
from pathlib import Path
import random
import statistics

QUANTILES = {"p50": .5, "p99": .99, "p99.9": .999, "p99.99": .9999}


def distribution(values):
    if not values:
        return {"count": 0}
    if any(not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("invalid latency sample")
    ordered = sorted(values)
    n = len(ordered)
    result = {"count": n, "mean": statistics.fmean(ordered), "min": ordered[0], "max": ordered[-1]}
    for name, q in QUANTILES.items():
        result[name] = ordered[max(0, math.ceil(q * n) - 1)]
    result["insufficient_tail_samples"] = [name for name, q in QUANTILES.items()
                                            if q > .5 and n * (1 - q) < 20 - 1e-8]
    return result


def summarize(raw, minimum_noise=100):
    metrics = {key: distribution(value) for key, value in raw.items()
               if key.endswith("_ns") and isinstance(value, list)
               and key not in {"sample_offset_ns", "reply_offset_ns"}}
    warnings = []
    if raw.get("sent") is not None:
        if raw.get("lost", 0):
            warnings.append("packet loss: successful-reply latency is censored")
        if raw.get("send_errors", 0) or raw.get("skipped_slots", 0):
            warnings.append("sender missed the requested offered load")
        if raw.get("received") == 0 and raw.get("kind") == "udp-client":
            warnings.append("no replies received")
    if raw.get("noise") in {"thread", "process"} and raw.get("noise_operations", 0) < minimum_noise:
        warnings.append(f"interference too weak: fewer than {minimum_noise} mprotect operations during measurement")
    if raw.get("noise_missed_periods"):
        warnings.append("mapping churn missed scheduled periods; compare achieved interference rates")
    if raw.get("timed_major_faults", 0):
        warnings.append("major page faults occurred in measurement")
    if raw.get("timed_minor_faults", 0):
        warnings.append("minor page faults occurred in measurement")
    if raw.get("napi_id_changes", 0):
        warnings.append("receive NAPI ID changed during the trial")
    for name, metric in metrics.items():
        if metric.get("insufficient_tail_samples"):
            warnings.append(f"{name}: insufficient samples for " + ", ".join(metric["insufficient_tail_samples"]))
    return {"metrics": metrics, "warnings": warnings,
            "loss_rate": raw.get("lost", 0) / raw["sent"] if raw.get("sent") else None,
            "noise_ops_per_second": (raw.get("noise_operations", 0) * 1e9 / raw["elapsed_ns"]
                                      if raw.get("elapsed_ns") else None)}


def paired_effect(trials, baseline, candidate, metric, percentile="p99.9"):
    """Bootstrap round-level paired changes, keeping the ABBA block together."""
    rounds = sorted({t["round"] for t in trials})
    changes = []
    for round_id in rounds:
        groups = {}
        for variant in (baseline, candidate):
            matches = [t for t in trials if t["round"] == round_id and t["variant"] == variant
                       and t["status"] == "ok"]
            values = [t["summary"]["metrics"].get(metric, {}).get(percentile) for t in matches]
            groups[variant] = statistics.median(values) if len(values) == 2 and all(v is not None for v in values) else None
        b, c = groups[baseline], groups[candidate]
        if b is not None and c is not None and b > 0:
            changes.append(100 * (c / b - 1))
    if not changes:
        return {"paired_rounds": 0, "interpretation": "no comparable completed rounds"}
    result = {"paired_rounds": len(changes), "round_changes_percent": changes,
              "median_change_percent": statistics.median(changes), "negative_means": "lower latency"}
    if len(changes) >= 5:
        rng = random.Random(8675309)
        boot = sorted(statistics.median(rng.choices(changes, k=len(changes))) for _ in range(2000))
        result["bootstrap_95pct_interval"] = [boot[49], boot[1949]]
    else:
        result["interpretation"] = "fewer than five independent rounds; descriptive comparison only"
    return result


def markdown(report):
    lines = [f"# {report['case']} benchmark", "", f"Status: **{report['status']}**", "",
             "Latency units: nanoseconds. Each row is one trial; batch latency is not single-load latency.", "",
             "| Trial | Variant | Status | Samples | p50 | p99 | p99.9 | p99.99 | Max |",
             "|---|---|---|---:|---:|---:|---:|---:|---:|"]
    metric = report["primary_metric"]
    for trial in report.get("trials", []):
        stats = trial.get("summary", {}).get("metrics", {}).get(metric, {})
        fields = [str(trial["index"]), trial["variant"], trial["status"], str(stats.get("count", 0))]
        for key in ("p50", "p99", "p99.9", "p99.99", "max"):
            value = stats.get(key)
            fields.append("—" if value is None else f"{value:,.0f}" +
                          ("*" if key in stats.get("insufficient_tail_samples", []) else ""))
        lines.append("| " + " | ".join(fields) + " |")
    lines += ["", "*Asterisk: fewer than 20 expected observations beyond that quantile; exploratory only.*", ""]
    for warning in report.get("warnings", []) + report.get("reasons", []):
        lines += [warning, ""]
    for trial in report.get("trials", []):
        warnings = trial.get("summary", {}).get("warnings", []) + trial.get("warnings", [])
        if trial.get("error"):
            warnings = [trial["error"]] + warnings
        if warnings:
            lines.append(f"Trial {trial['index']} ({trial['variant']}): " + "; ".join(warnings) + ".")
            lines.append("")
    if report.get("comparison"):
        lines += ["Paired round comparison (candidate relative to baseline):", "", "```json",
                  json.dumps(report["comparison"], indent=2), "```", ""]
    lines += ["Raw measurements, effective settings, recovery journals and host counters are in the trial directories.",
              "No synthetic benchmark result alone establishes a production latency improvement.", ""]
    return "\n".join(lines)


def write_report(directory, report):
    from .state import atomic_json
    atomic_json(Path(directory) / "report.json", report)
    (Path(directory) / "report.md").write_text(markdown(report))
