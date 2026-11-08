"""Offline SVG/PNG reports and sampled-stack flame graphs (optional matplotlib)."""
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import statistics

from .bpf import SERIES
from .state import atomic_json


def envelope(values, coordinates=None, limit=1000):
    """Keep every bin's maximum so downsampling cannot hide a latency spike."""
    if not values:
        return [], [], []
    stride = max(1, math.ceil(len(values) / limit))
    x, median, peak = [], [], []
    for i in range(0, len(values), stride):
        segment = values[i:i + stride]
        end = i + len(segment) - 1
        x.append(coordinates[end] if coordinates is not None else end)
        median.append(statistics.median(segment))
        peak.append(max(segment))
    return x, median, peak


def fold_stacks(stacks):
    """bpftrace perf stacks are leaf-first; folded stacks are root-first."""
    result = {}
    for stack, weight in stacks.items():
        if not isinstance(stack, str) or not isinstance(weight, int) or weight <= 0:
            continue
        frames = []
        for frame in stack.splitlines():
            frame = frame.strip()
            if not frame:
                continue
            # Keep unresolved addresses; never invent a function name.
            match = re.match(r"(?:0x)?[0-9a-fA-F]{8,16}\s+(.+)", frame)
            if match:
                frame = match[1]
            frame = frame.replace(";", ":").replace("\t", " ")
            frames.append(frame)
        if not frames:
            frames = ["[empty or unavailable stack]"]
        key = ";".join(reversed(frames))
        result[key] = result.get(key, 0) + weight
    return result


def flame_tree(folded):
    root = {"name": "all samples", "value": 0, "children": {}}
    for path, weight in folded.items():
        node = root
        node["value"] += weight
        for frame in path.split(";"):
            node = node["children"].setdefault(frame, {"name": frame, "value": 0, "children": {}})
            node["value"] += weight
    return root


def series_points(capture, name, cpu):
    """Normalise the final short bucket; leave gaps in incomplete captures."""
    data = {r["bin"]: r["value"] for r in capture["series"][name] if r["cpu"] == cpu}
    if not data:
        return [], []
    width = capture["config"]["bin_ms"] / 1000
    markers = capture.get("markers", {})
    duration = (markers.get("END", 0) - markers.get("READY", 0)) / 1e9
    xs, ys = [], []
    for bucket in range(max(data) + 1):
        span = min(width, duration - bucket * width) if duration > 0 else width
        if span <= 0:
            continue
        value = data.get(bucket, 0 if capture["status"] == "complete" else math.nan)
        xs.append(bucket * width + span / 2)
        value /= 1 if name == "runq_max" else span
        ys.append(value / 1000 if SERIES[name][1] == "ns" else value)
    return xs, ys


def render_flame(plt, folded, title):
    from matplotlib.patches import Rectangle
    tree = flame_tree(folded)
    depth = max((len(k.split(";")) for k in folded), default=1)
    fig, ax = plt.subplots(figsize=(14, max(3, min(16, depth * .35 + 1.5))))
    total = tree["value"] or 1
    def draw(node, left, level):
        color = "#" + hashlib.sha256(node["name"].encode()).hexdigest()[:6]
        width = node["value"]
        ax.add_patch(Rectangle((left, level), width, .93, facecolor=color, edgecolor="white", linewidth=.4))
        fraction = width / total
        if fraction > .035:
            text = f"{node['name']} ({width})"
            ax.text(left + width * .01, level + .45, text[:max(6, int(fraction * 150))],
                    fontsize=7, va="center", color="black", clip_on=True,
                    bbox={"facecolor": "white", "alpha": .6, "pad": .2, "edgecolor": "none"})
        offset = left
        for child in sorted(node["children"].values(), key=lambda n: n["name"]):
            draw(child, offset, level + 1)
            offset += child["value"]
    draw(tree, 0, 0)
    ax.set(xlim=(0, total), ylim=(0, depth + 1), xlabel="Stack samples (width is count, not latency)", title=title)
    ax.set_yticks([])
    fig.tight_layout()
    return fig


def generate(run_directory, output=None):
    run_directory = Path(run_directory).resolve()
    report = json.loads((run_directory / "report.json").read_text())
    output = Path(output).resolve() if output else run_directory / "graphs"
    output.mkdir(parents=True, exist_ok=False)
    os.environ.setdefault("MPLCONFIGDIR", str(output / ".mpl-cache"))
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("graph rendering needs matplotlib; install python3-matplotlib on the rendering host") from exc
    plt.rcParams.update({"svg.fonttype": "none", "font.size": 10, "axes.grid": True, "grid.alpha": .2})
    manifest = {"schema": 1, "run": str(run_directory), "case": report["case"], "status": report["status"],
                "diagnostic": bool(report.get("diagnostic")), "plots": [], "warnings": list(report.get("warnings", []))}

    def save(fig, name, description):
        fig.savefig(output / f"{name}.svg", bbox_inches="tight")
        fig.savefig(output / f"{name}.png", dpi=150, bbox_inches="tight")
        plt.close(fig)
        manifest["plots"].append({"svg": name + ".svg", "png": name + ".png", "description": description})

    metric = report["primary_metric"]
    trials = report.get("trials", [])
    fig, ax = plt.subplots(figsize=(13, 5))
    any_points = False
    for key in ("p50", "p99", "p99.9", "p99.99"):
        points = [(t["index"], t.get("summary", {}).get("metrics", {}).get(metric, {}).get(key)) for t in trials]
        points = [(x, y) for x, y in points if y is not None and y > 0]
        if points:
            any_points = True
            ax.plot([p[0] for p in points], [p[1] for p in points], marker="o", label=key)
    for t in trials:
        if t["status"] != "ok":
            ax.axvspan(t["index"] - .4, t["index"] + .4, color="red", alpha=.12)
    ax.set_xticks([t["index"] for t in trials], [f"{t['index']} {t['variant']}" for t in trials], rotation=65, ha="right")
    if any_points:
        ax.set_yscale("log"); ax.legend()
    else:
        ax.text(.5, .5, "No completed latency samples", transform=ax.transAxes, ha="center")
    ax.set(ylabel=f"{metric} (ns, logarithmic)", title=f"{report['case']} — trial percentiles ({report['status']})")
    fig.tight_layout()
    save(fig, "overview", "Per-trial percentiles; red bands mark non-ok trials. Check report.md for underpowered tails.")

    for trial in trials:
        manifest["warnings"] += [f"Trial {trial['index']}: {w}" for w in
                                 trial.get("summary", {}).get("warnings", []) + trial.get("warnings", [])]
        trial_dir = (run_directory / trial["directory"]).resolve()
        if not trial_dir.is_relative_to(run_directory):
            raise ValueError("trial directory escapes run directory")
        prefix = f"trial-{trial['index']:03d}"
        raw_path = trial_dir / "raw.json"
        raw = json.loads(raw_path.read_text()) if raw_path.exists() else {}
        values = raw.get(metric, [])
        if values:
            offset_name = "reply_offset_ns" if raw.get("kind") == "udp-client" else "sample_offset_ns"
            offsets = raw.get(offset_name)
            coords = [n / 1e9 for n in offsets] if offsets is not None and len(offsets) == len(values) else None
            if coords is not None:
                # UDP samples are stored by packet sequence; arrivals may be reordered.
                ordered = sorted(zip(coords, values))
                coords, values = [p[0] for p in ordered], [p[1] for p in ordered]
            xs, med, peak = envelope(values, coords)
            fig, ax = plt.subplots(figsize=(13, 4))
            ax.plot(xs, peak, color="#c44e52", label="Maximum in each display bin")
            ax.plot(xs, med, color="#4c72b0", label="Median in each display bin")
            if min(values) > 0:
                ax.set_yscale("log")
            clock_label = "sender" if raw.get("kind") == "udp-client" else "receiver"
            ax.set(xlabel=f"Seconds since {clock_label} measurement start" if coords else "Sample index (timestamps unavailable)",
                   ylabel=f"{metric} (ns)", title=f"Trial {trial['index']} · {trial['variant']} · {trial['status']}")
            ax.legend(); fig.tight_layout()
            save(fig, prefix + "-latency", "Spike-preserving display bins; raw samples are retained. Remote RTT uses the sender's clock.")
        capture_path = trial_dir / "bpf/capture.json"
        if not capture_path.exists():
            continue
        capture = json.loads(capture_path.read_text())
        manifest["warnings"] += [f"Trial {trial['index']} BPF: {w}" for w in capture.get("warnings", [])]
        manifest["warnings"].append(f"Trial {trial['index']} BPF status: {capture['status']}")
        if capture.get("config", {}).get("skipped"):
            manifest["warnings"].append(f"Trial {trial['index']} unavailable BPF groups: " + ", ".join(capture["config"]["skipped"]))
        series = {name: rows for name, rows in capture.get("series", {}).items() if name in SERIES and rows}
        if series:
            count_names = [n for n in series if SERIES[n][1] == "count"]
            time_names = [n for n in series if SERIES[n][1] == "ns" and n != "runq_max"]
            maximum_names = ["runq_max"] if "runq_max" in series else []
            fig, axes = plt.subplots(3, 1, figsize=(13, 10), sharex=True)
            for ax, names in zip(axes, (count_names, time_names, maximum_names)):
                for name in names:
                    rows = series[name]
                    for cpu in sorted({r["cpu"] for r in rows}):
                        xs, ys = series_points(capture, name, cpu)
                        label = f"{SERIES[name][0]} · CPU {cpu}" + (" (µs maximum)" if name == "runq_max" else "")
                        ax.plot(xs, ys, marker=".", markersize=3, label=label)
                if names:
                    ax.legend(fontsize=7, loc="upper right")
                ax.set_yscale("symlog", linthresh=1)
            axes[0].set(ylabel="Events / second", title=f"Trial {trial['index']} BPF · {capture['status']} · receiver clock")
            axes[1].set(ylabel="Completed interval time (µs/s)")
            axes[2].set(ylabel="Maximum wake-to-run delay (µs)", xlabel="Seconds since BPF receiver capture started")
            if raw.get("kind") in {"memory", "rcu"} and raw.get("start_monotonic_ns") and capture.get("markers", {}).get("READY"):
                start = (raw["start_monotonic_ns"] - capture["markers"]["READY"]) / 1e9
                end = start + raw["elapsed_ns"] / 1e9
                for ax in axes:
                    ax.axvspan(start, end, alpha=.08, color="green")
            fig.tight_layout()
            save(fig, prefix + "-bpf", "Receiver-side kernel events. Green span marks a local memory/RCU measurement; remote RTT is not clock-aligned. Times can overlap.")
        for name in ("kernel_stacks", "user_stacks"):
            stacks = capture.get("stacks", {}).get(name, {})
            folded = fold_stacks(stacks)
            if not folded:
                continue
            (output / f"{prefix}-{name}.folded").write_text("".join(f"{k} {v}\n" for k, v in sorted(folded.items())))
            fig = render_flame(plt, folded, f"Trial {trial['index']} · {trial['variant']} · {name} · {capture['status']}")
            save(fig, prefix + "-" + name, "Sampled CPU stacks: width is sample count, not elapsed latency or an off-CPU profile. Folded stacks are exported alongside.")
        if not series and not any(capture.get("stacks", {}).values()):
            manifest["warnings"].append(f"Trial {trial['index']}: no BPF samples; no empty activity graph was fabricated")

    manifest["warnings"] = sorted(set(manifest["warnings"]))
    atomic_json(output / "manifest.json", manifest)
    sections = ["<!doctype html><html lang='en'><meta charset='utf-8'><title>Metalbench graphs</title>",
                "<style>body{font:16px system-ui;max-width:1400px;margin:2rem auto;padding:0 1rem;background:#fafafa;color:#17212b}"
                "img{width:100%;background:white;border:1px solid #ddd}li{margin:.4rem 0}figure{margin:2rem 0}a{color:#145fa1}</style>",
                f"<h1>{html.escape(report['case'])} benchmark graphs</h1>",
                f"<p>Run status: <strong>{html.escape(report['status'])}</strong>. "
                + ("BPF diagnostic run; tracing changes workload timing." if manifest["diagnostic"] else "Inspect the report's validity and sample-count warnings.") + "</p>",
                "<p>Static, offline SVG and PNG artifacts. No external scripts, fonts or network requests.</p>"]
    if manifest["warnings"]:
        sections += ["<ul>"] + [f"<li>{html.escape(w)}</li>" for w in manifest["warnings"]] + ["</ul>"]
    for plot in manifest["plots"]:
        sections.append(f"<figure><a href='{plot['svg']}'><img src='{plot['svg']}' alt='{html.escape(plot['description'], quote=True)}'></a>"
                        f"<figcaption>{html.escape(plot['description'])} <a href='{plot['png']}'>PNG</a> · <a href='{plot['svg']}'>SVG</a></figcaption></figure>")
    sections.append("</html>")
    (output / "index.html").write_text("\n".join(sections))
    return output / "index.html"
