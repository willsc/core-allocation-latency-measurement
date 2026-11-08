"""Read-only inventories; missing privileges/features are recorded, never inferred."""
import fcntl
import os
from pathlib import Path
import platform
import select
import shutil
import socket
import struct
import subprocess

from .netlink import Netdev
from .state import boot_id


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def command(argv):
    if not shutil.which(argv[0]):
        return {"error": f"{argv[0]} not installed"}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}


def cpu_info(cpu):
    base = Path(f"/sys/devices/system/cpu/cpu{cpu}")
    return {"cpu": cpu, "package": read(base / "topology/physical_package_id"),
            "core": read(base / "topology/core_id"),
            "siblings": read(base / "topology/thread_siblings_list"),
            "numa_nodes": [p.name for p in base.glob("node[0-9]*")],
            "caches": [{"id": read(p / "id"), "level": read(p / "level"),
                        "type": read(p / "type"), "size": read(p / "size"),
                        "shared_cpu_list": read(p / "shared_cpu_list")}
                       for p in sorted((base / "cache").glob("index*"))],
            "governor": read(base / "cpufreq/scaling_governor"),
            "scaling_cur_freq": read(base / "cpufreq/scaling_cur_freq"),
            "resume_latency_us": read(base / "power/pm_qos_resume_latency_us"),
            "idle_states": [{"name": read(p / "name"), "latency": read(p / "latency"),
                             "disable": read(p / "disable"), "usage": read(p / "usage"),
                             "time": read(p / "time")} for p in sorted((base / "cpuidle").glob("state*"))]}


def probe(interface=None):
    data = {"kernel": platform.release(), "machine": platform.machine(),
            "hostname": platform.node(), "boot_id": boot_id(),
            "cmdline": read("/proc/cmdline"), "cpuinfo": read("/proc/cpuinfo"),
            "allowed_cpus": sorted(os.sched_getaffinity(0)),
            "isolated": read("/sys/devices/system/cpu/isolated"),
            "nohz_full": read("/sys/devices/system/cpu/nohz_full"),
            "online": read("/sys/devices/system/cpu/online"),
            "uncore": {}, "resctrl": {}, "interface": None,
            "global_busy_poll": read("/proc/sys/net/core/busy_poll"),
            "global_busy_read": read("/proc/sys/net/core/busy_read"),
            "rcu_nocb_poll": "rcu_nocb_poll" in (read("/proc/cmdline") or "").split(),
            "rcu_threads": command(["ps", "-eLo", "pid,tid,psr,comm"])}
    data["dmi"] = {name: read(f"/sys/class/dmi/id/{name}") for name in
                   ("product_uuid", "product_name", "sys_vendor", "bios_version")}
    data["cpus"] = [cpu_info(c) for c in data["allowed_cpus"]]
    for p in sorted(Path("/sys/devices/system/cpu/intel_uncore_frequency").glob("*")):
        if p.is_dir():
            data["uncore"][str(p)] = {f.name: read(f) for f in p.iterdir() if f.is_file()}
    for name in ("io_alloc", "io_alloc_cbm", "cbm_mask", "min_cbm_bits", "shareable_bits", "bit_usage"):
        data["resctrl"][name] = read(f"/sys/fs/resctrl/info/L3/{name}")
    try:
        with select.epoll() as ep:
            # _IOR(0x8a, 2, struct epoll_params), eight-byte Linux UAPI struct.
            result = fcntl.ioctl(ep.fileno(), 0x80088a02, bytes(8))
            data["epoll_params"] = dict(zip(("busy_poll_usecs", "busy_poll_budget", "prefer_busy_poll", "pad"),
                                             struct.unpack("=IHBB", result)))
    except OSError as exc:
        data["epoll_params"] = {"error": str(exc)}
    if interface:
        idx = socket.if_nametoindex(interface)
        base = Path("/sys/class/net") / interface
        nic = {"name": interface, "ifindex": idx, "numa_node": read(base / "device/numa_node"),
               "gro_flush_timeout": read(base / "gro_flush_timeout"),
               "napi_defer_hard_irqs": read(base / "napi_defer_hard_irqs"),
               "driver": command(["ethtool", "-i", interface]),
               "coalescing": command(["ethtool", "-c", interface]),
               "channels": command(["ethtool", "-l", interface]),
               "rss": command(["ethtool", "-x", interface]),
               "offloads": command(["ethtool", "-k", interface]),
               "rings": command(["ethtool", "-g", interface]),
               "route": command(["ip", "-j", "address", "show", "dev", interface])}
        try:
            with Netdev() as dev:
                nic["napis"] = dev.napis(idx)
        except (OSError, ValueError) as exc:
            nic["napis_error"] = str(exc)
        data["interface"] = nic
    return data


def fingerprint(host):
    """Stable fields that should match between RCU boots (exclude counters/frequencies)."""
    return {"dmi": host.get("dmi"),
            "cpu_models": sorted({line for line in (host.get("cpuinfo") or "").splitlines()
                                  if line.split(":", 1)[0].strip() in
                                  {"vendor_id", "cpu family", "model", "model name", "stepping", "microcode"}}),
            "cpus": [{key: cpu.get(key) for key in ("cpu", "package", "core", "siblings", "numa_nodes", "caches", "governor", "resume_latency_us")}
                     | {"idle_states": [{key: state.get(key) for key in ("name", "latency", "disable")}
                                        for state in cpu.get("idle_states", [])]}
                     for cpu in host["cpus"]],
            "uncore": {path: {k: v for k, v in values.items() if k != "current_freq_khz"}
                       for path, values in host["uncore"].items()},
            "resctrl": host["resctrl"], "global_busy_read": host.get("global_busy_read"),
            "global_busy_poll": host.get("global_busy_poll")}


def counters(interface=None, cpus=()):
    paths = ["/proc/interrupts", "/proc/softirqs", "/proc/vmstat", "/proc/net/snmp",
             "/proc/net/softnet_stat", "/proc/stat"]
    data = {p: read(p) for p in paths}
    data["cpus"] = [cpu_info(cpu) for cpu in cpus]
    data["uncore_frequencies"] = {str(p): read(p) for p in
                                  Path("/sys/devices/system/cpu/intel_uncore_frequency").glob("*/current_freq_khz")}
    if interface:
        data["ethtool_stats"] = command(["ethtool", "-S", interface])
        data["nic"] = {p.name: read(p) for p in (Path("/sys/class/net") / interface / "statistics").glob("*")}
    return data
