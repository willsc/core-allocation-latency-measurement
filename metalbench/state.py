"""Read-back-verified changes with a durable, same-boot recovery journal."""
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import time

from .netlink import Netdev, WRITABLE


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def normalize(value):
    value = str(value).strip()
    if value in {"enabled", "disabled"}:
        return {"enabled": "1", "disabled": "0"}[value]
    if re.fullmatch(r"[0-9]+=([0-9a-fA-F]+)(;[0-9]+=[0-9a-fA-F]+)*", value):
        parts = [part.split("=") for part in value.split(";")]
        return ";".join(f"{int(k)}={int(v, 16):x}" for k, v in sorted(parts, key=lambda p: int(p[0])))
    if re.fullmatch(r"[0-9]+", value):
        return str(int(value))
    return value


def matches(actual, expected):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and matches(actual[k], v)
                                               for k, v in expected.items())
    return actual == expected


class Backend:
    FILES = re.compile(
        r"/sys/devices/system/cpu/(?:intel_uncore_frequency/[^/.]+/"
        r"(?:min_freq_khz|elc_floor_freq_khz|elc_low_threshold_percent)|"
        r"cpu[0-9]+/power/pm_qos_resume_latency_us)\Z|"
        r"/sys/fs/resctrl/info/L3/(?:io_alloc|io_alloc_cbm)\Z")

    def __init__(self, root=Path("/")):
        self.root = Path(root)

    def file_path(self, spec):
        path = spec["path"]
        if not self.FILES.fullmatch(path):
            raise ValueError(f"setting outside supported controls: {path}")
        return self.root / path.lstrip("/")

    def read(self, spec):
        if spec["kind"] == "file":
            return normalize(self.file_path(spec).read_text())
        if spec["kind"] != "napi":
            raise ValueError("unknown setting type")
        with Netdev() as dev:
            data = dev.get(spec["id"])
        if data.get("ifindex") != spec["ifindex"]:
            raise ValueError("NAPI ID moved to another interface")
        affinity = sorted(os.sched_getaffinity(data["pid"])) if data.get("pid") else None
        return {"settings": {k: data[k] for k in WRITABLE if k in data}, "affinity": affinity}

    def write(self, spec, value):
        if spec["kind"] == "file":
            with self.file_path(spec).open("w") as stream:
                stream.write(str(value) + "\n")
            return
        if spec["kind"] != "napi":
            raise ValueError("unknown setting type")
        with Netdev() as dev:
            if dev.get(spec["id"]).get("ifindex") != spec["ifindex"]:
                raise ValueError("NAPI interface changed")
            dev.set(spec["id"], value["settings"])
            if value.get("affinity") is not None:
                deadline = time.monotonic() + 3
                while True:
                    data = dev.get(spec["id"])
                    if data.get("pid"):
                        os.sched_setaffinity(data["pid"], value["affinity"])
                        break
                    if time.monotonic() > deadline:
                        raise OSError("threaded NAPI did not expose its PID")
                    time.sleep(.01)


class Transaction:
    def __init__(self, path, backend=None):
        self.path = Path(path)
        if self.path.exists():
            raise FileExistsError(self.path)
        self.backend = backend or Backend()
        self.data = {"schema": 1, "boot_id": boot_id(), "restored": False, "entries": []}
        self.save()

    def save(self):
        atomic_json(self.path, self.data)

    def apply(self, spec, value):
        if spec["kind"] == "file":
            value = normalize(value)
        entry = next((e for e in self.data["entries"] if e["resource"] == spec), None)
        if entry is None:
            entry = {"resource": spec, "original": self.backend.read(spec)}
            self.data["entries"].append(entry)
        entry.update(requested=value, restored=False)
        self.save()  # MUST reach disk before a kernel write, including failed writes.
        self.backend.write(spec, value)
        effective = self.backend.read(spec)
        entry["effective"] = effective
        self.save()
        if not matches(effective, value):
            raise OSError(f"readback mismatch for {spec}: requested {value}, got {effective}")
        return effective

    def restore(self):
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            self._restore()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)

    def _restore(self):
        errors = []
        for entry in reversed(self.data["entries"]):
            if entry.get("restored"):
                continue
            try:
                if self.backend.read(entry["resource"]) != entry["original"]:
                    self.backend.write(entry["resource"], entry["original"])
                actual = self.backend.read(entry["resource"])
                if actual != entry["original"]:
                    raise OSError(f"restore readback mismatch: {actual}")
                entry["restored"] = True
                entry.pop("restore_error", None)
            except Exception as exc:
                entry["restore_error"] = str(exc)
            self.save()
        # A later dependent restore can alter an earlier resource (e.g. mode switches).
        # Verify the whole final state, not just each intermediate write.
        for entry in self.data["entries"]:
            try:
                if self.backend.read(entry["resource"]) != entry["original"]:
                    raise OSError("final state differs from original")
                entry["restored"] = True
                entry.pop("restore_error", None)
            except Exception as exc:
                entry["restored"] = False
                entry["restore_error"] = str(exc)
                errors.append(f"{entry['resource']}: {exc}")
        self.data["restored"] = not errors
        self.save()
        if errors:
            raise RuntimeError("RESTORATION FAILED; retain journal and use recover: " + "; ".join(errors))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.restore()

    @classmethod
    def recover(cls, path, backend=None):
        obj = cls.__new__(cls)
        obj.path, obj.backend = Path(path), backend or Backend()
        obj.data = json.loads(obj.path.read_text())
        if obj.data.get("schema") != 1 or obj.data.get("boot_id") != boot_id():
            raise ValueError("recovery requires a schema-1 journal from this boot")
        obj.restore()
        return obj.data


class HostLock:
    def __enter__(self):
        self.fd = os.open("/tmp/metalbench-host.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            raise RuntimeError("another metalbench mutation run holds the host lock")
        return self

    def __exit__(self, *_):
        os.close(self.fd)
