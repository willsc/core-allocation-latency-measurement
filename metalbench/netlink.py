"""Small netdev generic-netlink client for the Linux 7.x UAPI.

Numbers are stable UAPI values from include/uapi/linux/netdev.h and
Documentation/netlink/specs/netdev.yaml. Unsupported operations fail closed.
"""
import errno
import socket
import struct

NAPI_FIELDS = {"ifindex": 1, "id": 2, "irq": 3, "pid": 4,
               "defer-hard-irqs": 5, "gro-flush-timeout": 6,
               "irq-suspend-timeout": 7, "threaded": 8}
WRITABLE = {"defer-hard-irqs", "gro-flush-timeout", "irq-suspend-timeout", "threaded"}


def attribute(kind, data):
    length = 4 + len(data)
    return struct.pack("=HH", length, kind) + data + bytes((-length) % 4)


def decode_attributes(data):
    result = {}
    while data:
        if len(data) < 4:
            raise ValueError("truncated netlink attribute")
        length, kind = struct.unpack_from("=HH", data)
        if length < 4 or length > len(data):
            raise ValueError("invalid netlink attribute length")
        result[kind & 0x3fff] = data[4:length]
        data = data[(length + 3) & ~3:]
    return result


def number(data):
    if len(data) not in (2, 4, 8):
        raise ValueError("unexpected netlink integer width")
    return int.from_bytes(data, byteorder=__import__("sys").byteorder)


def integer(kind, value, wide=False):
    return attribute(kind, struct.pack("=Q" if wide else "=I", value))


class Netdev:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
        self.sock.settimeout(3)
        self.sock.bind((0, 0))
        self.sequence = 0
        try:
            replies = self.request(0x10, 3, attribute(2, b"netdev\0"))
            self.family = number(replies[0][1])
        except BaseException:
            self.close()
            raise

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def request(self, family, command, attrs=b"", dump=False):
        self.sequence += 1
        flags = 1 | (0x300 if dump else 4)  # REQUEST + DUMP or ACK
        body = struct.pack("=BBH", command, 1, 0) + attrs
        packet = struct.pack("=IHHII", 16 + len(body), family, flags,
                             self.sequence, 0) + body
        self.sock.sendto(packet, (0, 0))
        result = []
        while True:
            data, _, msgflags, addr = self.sock.recvmsg(1 << 20)
            if addr[0] != 0 or msgflags & socket.MSG_TRUNC:
                raise OSError("untrusted or truncated netlink response")
            while data:
                if len(data) < 16:
                    raise ValueError("truncated netlink message")
                size, kind, flags, seq, _ = struct.unpack_from("=IHHII", data)
                if size < 16 or size > len(data):
                    raise ValueError("invalid netlink message length")
                payload, data = data[16:size], data[(size + 3) & ~3:]
                if seq != self.sequence:
                    continue
                if flags & 0x10:  # NLM_F_DUMP_INTR: never accept a partial dump
                    raise OSError(errno.EAGAIN, "interrupted netlink dump")
                if kind == 2:
                    code = struct.unpack_from("=i", payload)[0]
                    if code:
                        raise OSError(-code, __import__("os").strerror(-code))
                    return result
                if kind == 3:
                    if len(payload) >= 4 and struct.unpack_from("=i", payload)[0]:
                        raise OSError("netlink dump failed")
                    return result
                if kind == family:
                    result.append(decode_attributes(payload[4:]))

    def napis(self, ifindex):
        replies = self.request(self.family, 11, integer(1, ifindex), dump=True)
        return [{key: number(attrs[idx]) for key, idx in NAPI_FIELDS.items() if idx in attrs}
                for attrs in replies if number(attrs.get(1, bytes(4))) == ifindex]

    def get(self, napi_id):
        replies = self.request(self.family, 11, integer(2, napi_id))
        if len(replies) != 1:
            raise OSError("NAPI ID did not resolve uniquely")
        return {key: number(replies[0][idx]) for key, idx in NAPI_FIELDS.items()
                if idx in replies[0]}

    def set(self, napi_id, values):
        if not values or set(values) - WRITABLE:
            raise ValueError("invalid NAPI settings")
        attrs = integer(2, napi_id)
        for key, value in values.items():
            attrs += integer(NAPI_FIELDS[key], value,
                             wide=key in {"gro-flush-timeout", "irq-suspend-timeout"})
        self.request(self.family, 14, attrs)
