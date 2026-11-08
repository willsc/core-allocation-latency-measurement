# Interface references

The implementation uses documented Linux UAPIs and checks their actual presence.
These links explain the controls; they are not assertions that AWS exposes every
feature on every metal SKU.

* [Intel uncore frequency and ELC](https://docs.kernel.org/admin-guide/pm/intel_uncore_frequency_scaling.html):
  domain layout, frequency bounds, low-utilisation floor and ELC thresholds.
* [CPU idle and PM QoS](https://docs.kernel.org/admin-guide/pm/cpuidle.html):
  per-CPU constraints, interaction with global requests and idle-state controls.
* [Resource control](https://docs.kernel.org/filesystems/resctrl.html):
  `io_alloc`, allocation masks, hardware/CPU sharing and allocation-class use.
* [NAPI](https://docs.kernel.org/networking/napi.html): software deferral,
  epoll busy polling, IRQ suspension and threaded busy polling.
* [netdev UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netdev.h)
  and [netdev schema](https://github.com/torvalds/linux/blob/master/Documentation/netlink/specs/netdev.yaml):
  generic-netlink command/attribute numbers and integer widths.
* [epoll UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/eventpoll.h):
  eight-byte `epoll_params`, `EPIOCSPARAMS`, and `EPIOCGPARAMS`.
* [Kernel boot parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html):
  `rcu_nocbs`, `nohz_full`, and `rcu_nocb_poll`.
* [UDP socket binding](https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c)
  and [socket destruction](https://github.com/torvalds/linux/blob/master/net/core/sock.c):
  the bound-socket `SOCK_RCU_FREE` path exercised by the RCU worker.
* [Cache/TLB flushing](https://docs.kernel.org/core-api/cachetlb.html):
  address-space membership and cross-CPU invalidation.
* [AWS ENA latency guidance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-improve-network-latency-linux.html):
  hardware interrupt moderation and baseline network considerations.

The generic-netlink and epoll constants are stable ABI values rather than a
dependency on the host's installed development-header version. Runtime ioctl,
netlink capability and readback checks remain authoritative on the 7.x AWS build.
