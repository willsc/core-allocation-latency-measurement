/* Linux native measurement workers. All allocation/output is outside timed loops.
 * No cycle->nanosecond conversion or cross-host clock synchronisation is assumed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Linux UAPI, usable with older libc development headers on 7.x AWS kernels. */
struct bench_epoll_params {
    uint32_t busy_poll_usecs;
    uint16_t busy_poll_budget;
    uint8_t prefer_busy_poll, pad;
};
#define BENCH_EPIOCSPARAMS _IOW(0x8a, 1, struct bench_epoll_params)
#define BENCH_EPIOCGPARAMS _IOR(0x8a, 2, struct bench_epoll_params)
#ifndef SO_INCOMING_NAPI_ID
#define SO_INCOMING_NAPI_ID 56
#endif

static volatile sig_atomic_t stopped;
static void stop_handler(int sig) { (void)sig; stopped = 1; }
static void fail(const char *what) { perror(what); exit(2); }
static void invalid(const char *what) { fprintf(stderr, "%s\n", what); exit(2); }
static uint64_t now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) fail("clock_gettime");
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static void until(uint64_t ns) {
    struct timespec ts = {.tv_sec = (time_t)(ns / 1000000000),
                          .tv_nsec = (long)(ns % 1000000000)};
    int rc;
    do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL); }
    while (rc == EINTR && !stopped);
    if (rc && rc != EINTR) { errno = rc; fail("clock_nanosleep"); }
}
static void relax_cpu(void) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("yield" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}
static void pin(int cpu) {
    cpu_set_t mask;
    if (cpu < 0 || cpu >= CPU_SETSIZE) invalid("CPU exceeds worker CPU_SETSIZE");
    CPU_ZERO(&mask); CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask)) fail("sched_setaffinity");
}
static void *allocate(size_t bytes, bool lock) {
    void *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) fail("mmap");
    if (madvise(p, bytes, MADV_NOHUGEPAGE)) fail("MADV_NOHUGEPAGE");
    memset(p, 0, bytes);
    if (lock && mlock(p, bytes)) fail("mlock (raise RLIMIT_MEMLOCK or omit --mlock)");
    return p;
}
static uint64_t rng(uint64_t *s) {
    *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; return *s;
}
static uint64_t parse_uint(const char *s) {
    char *end; errno = 0;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || !*s || *s == '-' || *end) invalid("expected unsigned integer");
    return n;
}
struct options {
    uint64_t samples, loads, size_mb, gap_us, interval_us, burst, quiet_us;
    uint64_t warmup_ms, timeout_ms, duration_ms, churn_interval_us;
    int cpu, noise_cpu, port, source_port, packet_size, busy_us, budget, prefer;
    bool lock;
    const char *noise, *address, *ready, *start, *traffic;
};
static struct options opt = {.samples=100000, .loads=64, .size_mb=64,
    .interval_us=100, .burst=1000, .quiet_us=10000, .warmup_ms=500,
    .timeout_ms=1000, .duration_ms=10000, .churn_interval_us=100, .cpu=0, .noise_cpu=1,
    .port=41000, .source_port=41001, .packet_size=64, .budget=64,
    .noise="none", .address="127.0.0.1"};

static void marker(const char *path) {
    if (!path) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) fail("create readiness marker");
    if (dprintf(fd, "%ld\n", (long)getpid()) < 0) fail("write readiness marker");
    if (close(fd)) fail("close readiness marker");
}
static void ready(void) {
    marker(opt.ready);
    uint64_t deadline = now() + 60000000000ULL;
    while (opt.start && access(opt.start, F_OK) && !stopped) {
        if (now() > deadline) invalid("start gate timed out");
        until(now() + 1000000);
    }
}
static void array(const char *name, const uint64_t *a, size_t n) {
    printf(",\"%s\":[", name);
    for (size_t i=0; i<n; i++) printf("%s%" PRIu64, i ? "," : "", a[i]);
    putchar(']');
}
static void usage_stats(const struct rusage *start, const struct rusage *finish) {
    struct rusage end=*finish;
    double cpu = (end.ru_utime.tv_sec - start->ru_utime.tv_sec) +
        (end.ru_stime.tv_sec - start->ru_stime.tv_sec) +
        (end.ru_utime.tv_usec - start->ru_utime.tv_usec +
         end.ru_stime.tv_usec - start->ru_stime.tv_usec) / 1e6;
    printf(",\"rusage_scope\":\"measuring_thread\",\"cpu_seconds\":%.9f,\"minor_faults\":%ld,\"major_faults\":%ld,"
           "\"voluntary_switches\":%ld,\"involuntary_switches\":%ld",
           cpu, end.ru_minflt-start->ru_minflt, end.ru_majflt-start->ru_majflt,
           end.ru_nvcsw-start->ru_nvcsw, end.ru_nivcsw-start->ru_nivcsw);
}

struct noise_control { atomic_int ready, stop, error; atomic_uint_fast64_t ops, missed; };
static struct noise_control *noise_ctl;
static void *mapping_noise(void *unused) {
    (void)unused;
    pin(opt.noise_cpu);
    const size_t size = 2 * 1024 * 1024;
    unsigned char *p = allocate(size, false);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    atomic_store(&noise_ctl->ready, 1);
    uint64_t next=now();
    while (!atomic_load(&noise_ctl->stop) && !stopped) {
        if (mprotect(p, size, PROT_READ) || mprotect(p, size, PROT_READ | PROT_WRITE)) {
            atomic_store(&noise_ctl->error, errno); break;
        }
        for (size_t i=0; i<size; i+=page) p[i]++;
        atomic_fetch_add_explicit(&noise_ctl->ops, 2, memory_order_relaxed);
        if(opt.churn_interval_us) {
            next+=opt.churn_interval_us*1000;
            uint64_t current=now();
            if(current>next) {
                uint64_t missed=(current-next)/(opt.churn_interval_us*1000)+1;
                atomic_fetch_add_explicit(&noise_ctl->missed,missed,memory_order_relaxed);
                next+=missed*opt.churn_interval_us*1000;
            }
            until(next);
        }
    }
    munmap(p, size);
    return NULL;
}
static void rcu_operation(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) fail("socket");
    struct sockaddr_in a = {.sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if (bind(fd, (struct sockaddr *)&a, sizeof(a))) fail("bind");
    if (close(fd)) fail("close");
}
static void **chase(void **p) {
    for (uint64_t j=0; j<opt.loads; j++) p = *(void *volatile *)p;
    __asm__ volatile("" : "+r"(p) :: "memory");
    return p;
}
static int memory_worker(bool rcu) {
    pin(opt.cpu);
    size_t bytes = (size_t)opt.size_mb << 20;
    void **ptr = NULL;
    if (!rcu) {
        char *buf = allocate(bytes, opt.lock);
        size_t count=bytes/64, *order=malloc(count*sizeof(*order));
        if (!order) fail("allocate permutation");
        for (size_t i=0; i<count; i++) order[i]=i;
        uint64_t seed=0x9e3779b97f4a7c15ULL;
        for (size_t i=count-1; i>0; i--) {
            size_t j=(size_t)(rng(&seed)%(i+1)), tmp=order[i];
            order[i]=order[j]; order[j]=tmp;
        }
        for (size_t i=0; i<count; i++)
            *(void **)(buf+64*order[i])=buf+64*order[(i+1)%count];
        ptr=(void **)(buf+64*order[0]); free(order);
    }
    pid_t child=0; pthread_t thread;
    bool noisy=strcmp(opt.noise,"none")!=0, forked=strcmp(opt.noise,"process")==0;
    if (noisy) {
        if (opt.noise_cpu == opt.cpu) invalid("noise CPU must differ from victim CPU");
        noise_ctl=mmap(NULL, sizeof(*noise_ctl), PROT_READ|PROT_WRITE,
                       MAP_ANONYMOUS|MAP_SHARED, -1, 0);
        if (noise_ctl==MAP_FAILED) fail("noise control mmap");
        atomic_init(&noise_ctl->ready,0); atomic_init(&noise_ctl->stop,0);
        atomic_init(&noise_ctl->error,0); atomic_init(&noise_ctl->ops,0);
        atomic_init(&noise_ctl->missed,0);
        if (forked) {
            pid_t parent=getpid(); child=fork();
            if (child<0) fail("fork");
            if (!child) {
                if (prctl(PR_SET_PDEATHSIG, SIGKILL)) _exit(2);
                if (getppid()!=parent) _exit(2);
                mapping_noise(NULL); _exit(0);
            }
        } else {
            int rc=pthread_create(&thread,NULL,mapping_noise,NULL);
            if (rc) {errno=rc; fail("pthread_create");}
        }
        uint64_t deadline=now()+10000000000ULL;
        while (!atomic_load(&noise_ctl->ready) && !stopped) {
            if (now()>deadline) invalid("noise worker failed to become ready");
            until(now()+1000000);
        }
    }
    /* Allocate after fork to avoid COW faults in the measured sample buffers. */
    uint64_t *values=allocate(opt.samples*sizeof(*values), opt.lock);
    uint64_t *wake=allocate(opt.samples*sizeof(*wake), opt.lock);
    uint64_t *total=allocate(opt.samples*sizeof(*total), opt.lock);
    uint64_t *offsets=allocate(opt.samples*sizeof(*offsets), opt.lock);
    uint64_t warm_end=now()+opt.warmup_ms*1000000;
    while (now()<warm_end && !stopped) {
        if (rcu) rcu_operation(); else ptr=chase(ptr);
    }
    ready();
    struct rusage ru;
    if (getrusage(RUSAGE_THREAD,&ru)) fail("getrusage");
    uint64_t ops_start=noisy?atomic_load(&noise_ctl->ops):0;
    uint64_t missed_start=noisy?atomic_load(&noise_ctl->missed):0, start=now(), n=0;
    for (;n<opt.samples && !stopped;n++) {
        uint64_t deadline=0;
        if (opt.gap_us) { deadline=now()+opt.gap_us*1000; until(deadline); }
        uint64_t before=now();
        if (rcu) rcu_operation(); else ptr=chase(ptr);
        uint64_t end=now();
        values[n]=end-before;
        wake[n]=deadline && before>deadline ? before-deadline : 0;
        total[n]=values[n]+wake[n];
        offsets[n]=end-start;
    }
    uint64_t elapsed=now()-start;
    uint64_t noise_ops=noisy?atomic_load(&noise_ctl->ops)-ops_start:0;
    uint64_t noise_missed=noisy?atomic_load(&noise_ctl->missed)-missed_start:0;
    struct rusage endru;
    if (getrusage(RUSAGE_THREAD,&endru)) fail("getrusage");
    if (noisy) {
        atomic_store(&noise_ctl->stop,1);
        if (forked) {
            int status;
            if (waitpid(child,&status,0)<0) fail("waitpid");
            if (!WIFEXITED(status)||WEXITSTATUS(status)) invalid("noise process failed");
        } else if (pthread_join(thread,NULL)) invalid("noise thread failed");
        if (atomic_load(&noise_ctl->error)) invalid("mapping churn failed");
    }
    printf("{\"kind\":\"%s\",\"cpu\":%d,\"samples\":%" PRIu64
           ",\"loads_per_batch\":%" PRIu64 ",\"memory_bytes\":%zu,"
           "\"noise\":\"%s\",\"noise_cpu\":%d,\"noise_operations\":%" PRIu64
           ",\"elapsed_ns\":%" PRIu64 ",\"gap_us\":%" PRIu64
           ",\"mlocked\":%s,\"page_policy\":\"MADV_NOHUGEPAGE\"",
           rcu?"rcu":"memory",opt.cpu,n,rcu?1:opt.loads,rcu?0:bytes,
           opt.noise,opt.noise_cpu,noise_ops,elapsed,opt.gap_us,opt.lock?"true":"false");
    usage_stats(&ru,&endru);
    printf(",\"start_monotonic_ns\":%"PRIu64",\"noise_missed_periods\":%"PRIu64
           ",\"churn_interval_us\":%"PRIu64,start,noise_missed,opt.churn_interval_us);
    printf(",\"timed_minor_faults\":%ld,\"timed_major_faults\":%ld",
           endru.ru_minflt-ru.ru_minflt,endru.ru_majflt-ru.ru_majflt);
    array(rcu?"operation_ns":"batch_ns",values,n);
    array("sample_offset_ns",offsets,n);
    if (opt.gap_us) {array("wake_lateness_ns",wake,n); array("wakeup_plus_batch_ns",total,n);}
    puts("}");
    return stopped?130:0;
}

struct packet {uint64_t magic,run,seq; uint32_t napi,flags; uint64_t service;};
#define MAGIC UINT64_C(0x4d4554414c424e43)
static int udp_socket(bool server) {
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (fd<0) fail("UDP socket");
    int buffer=4*1024*1024;
    if (setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&buffer,sizeof(buffer))) fail("SO_RCVBUF");
    struct sockaddr_in a={.sin_family=AF_INET,
        .sin_port=htons((uint16_t)(server?opt.port:opt.source_port))};
    if (server && inet_pton(AF_INET,opt.address,&a.sin_addr)!=1) invalid("IPv4 address required");
    if (bind(fd,(struct sockaddr *)&a,sizeof(a))) fail("UDP bind");
    if (!server) {
        a.sin_port=htons((uint16_t)opt.port);
        if (inet_pton(AF_INET,opt.address,&a.sin_addr)!=1) invalid("IPv4 address required");
        if (connect(fd,(struct sockaddr *)&a,sizeof(a))) fail("UDP connect");
    }
    return fd;
}
static int echo_worker(void) {
    pin(opt.cpu);
    int fd=udp_socket(true), ep=epoll_create1(EPOLL_CLOEXEC), one=1;
    if (ep<0) fail("epoll_create1");
    if (setsockopt(fd,SOL_SOCKET,SO_RXQ_OVFL,&one,sizeof(one))) fail("SO_RXQ_OVFL");
    struct bench_epoll_params params={.busy_poll_usecs=(uint32_t)opt.busy_us,
        .busy_poll_budget=(uint16_t)opt.budget,.prefer_busy_poll=(uint8_t)opt.prefer};
    if (ioctl(ep,BENCH_EPIOCSPARAMS,&params)) fail("EPIOCSPARAMS");
    struct bench_epoll_params readback={0};
    if (ioctl(ep,BENCH_EPIOCGPARAMS,&readback)) fail("EPIOCGPARAMS");
    if (memcmp(&params,&readback,sizeof(params))) invalid("epoll readback mismatch");
    struct epoll_event ev={.events=EPOLLIN,.data.fd=fd};
    if (epoll_ctl(ep,EPOLL_CTL_ADD,fd,&ev)) fail("epoll_ctl");
    ready();
    uint64_t packets=0, invalids=0, sent=0, errors=0, id_changes=0;
    uint32_t first_id=0, last_id=0, drops=0;
    struct rusage ru; if(getrusage(RUSAGE_THREAD,&ru))fail("getrusage");
    uint64_t start=now();
    while (!stopped) {
        int n=epoll_wait(ep,&ev,1,100);
        if (n<0) {if(errno==EINTR)continue; fail("epoll_wait");}
        if (!n) continue;
        char buffer[9000], control[128]; struct sockaddr_in from;
        struct iovec iov={.iov_base=buffer,.iov_len=sizeof(buffer)};
        struct msghdr msg={.msg_name=&from,.msg_namelen=sizeof(from),
            .msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        ssize_t size=recvmsg(fd,&msg,MSG_DONTWAIT);
        if (size<0) {if(errno==EAGAIN||errno==EINTR)continue; fail("recvmsg");}
        uint64_t begin=now();
        if (size<(ssize_t)sizeof(struct packet) || (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC))) {invalids++;continue;}
        struct packet p; memcpy(&p,buffer,sizeof(p));
        if (be64toh(p.magic)!=MAGIC) {invalids++;continue;}
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c))
            if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SO_RXQ_OVFL&&c->cmsg_len>=CMSG_LEN(sizeof(drops)))
                memcpy(&drops,CMSG_DATA(c),sizeof(drops));
        uint32_t id=0; socklen_t len=sizeof(id);
        if(getsockopt(fd,SOL_SOCKET,SO_INCOMING_NAPI_ID,&id,&len))fail("SO_INCOMING_NAPI_ID");
        if(!packets) {first_id=id;marker(opt.traffic);}
        else if(id!=last_id)id_changes++;
        last_id=id; packets++;
        if(ntohl(p.flags)&2)continue;  /* background DMA load has no reply */
        p.napi=htonl(id); p.service=htobe64(now()-begin); memcpy(buffer,&p,sizeof(p));
        if(sendto(fd,buffer,(size_t)size,MSG_DONTWAIT,(struct sockaddr *)&from,sizeof(from))==size)sent++;
        else errors++;
    }
    struct rusage endru;if(getrusage(RUSAGE_THREAD,&endru))fail("getrusage");
    printf("{\"kind\":\"echo\",\"cpu\":%d,\"packets\":%"PRIu64
        ",\"replies\":%"PRIu64",\"send_errors\":%"PRIu64",\"invalid_packets\":%"PRIu64
        ",\"socket_drops\":%u,\"first_napi_id\":%u,\"last_napi_id\":%u,"
        "\"napi_id_changes\":%"PRIu64",\"elapsed_ns\":%"PRIu64
        ",\"busy_poll_usecs\":%u,\"busy_poll_budget\":%u,\"prefer_busy_poll\":%u",
        opt.cpu,packets,sent,errors,invalids,drops,first_id,last_id,id_changes,now()-start,
        readback.busy_poll_usecs,readback.busy_poll_budget,readback.prefer_busy_poll);
    usage_stats(&ru,&endru); puts("}"); close(ep);close(fd);return 0;
}
static uint64_t schedule(uint64_t i) {
    return i*opt.interval_us*1000 + (i/opt.burst)*opt.quiet_us*1000;
}
static int client_worker(bool load) {
    pin(opt.cpu); int fd=udp_socket(false);
    char buffer[9000]={0};
    uint64_t *tx=NULL,*rx=NULL,*rtt=NULL,*scheduled=NULL,*late=NULL,*first=NULL;
    uint64_t *service=NULL;
    if(!load) {
        tx=allocate(opt.samples*sizeof(*tx),opt.lock);
        rx=allocate(opt.samples*sizeof(*rx),opt.lock);
        rtt=allocate(opt.samples*sizeof(*rtt),opt.lock);
        scheduled=allocate(opt.samples*sizeof(*scheduled),opt.lock);
        late=allocate(opt.samples*sizeof(*late),opt.lock);
        first=allocate(opt.samples*sizeof(*first),opt.lock);
        service=allocate(opt.samples*sizeof(*service),opt.lock);
    }
    ready();
    struct rusage ru;if(getrusage(RUSAGE_THREAD,&ru))fail("getrusage");
    uint64_t start=now()+10000000, cookie=start^((uint64_t)getpid()<<32);
    uint64_t deadline=load?start+opt.duration_ms*1000000:
        start+schedule(opt.samples-1)+opt.timeout_ms*1000000;
    uint64_t index=0,sent=0,received=0,skipped=0,errors=0,duplicates=0,reordered=0,highest=0;
    uint64_t nsamples=0,first_n=0,first_id=0,id_changes=0,last_id=0;
    while(!stopped) {
        uint64_t current=now();
        if(current>=deadline)break;
        uint64_t due=start+(load?index*opt.interval_us*1000:schedule(index));
        if((load||index<opt.samples)&&current>=due) {
            /* Do not create an artificial catch-up burst when the sender stalls. */
            if(current-due>opt.interval_us*1000) {skipped++;index++;continue;}
            struct packet p={.magic=htobe64(MAGIC),.run=htobe64(cookie),
                .seq=htobe64(index),.flags=htonl(load?2:0)};
            memcpy(buffer,&p,sizeof(p));
            ssize_t n=send(fd,buffer,(size_t)opt.packet_size,MSG_DONTWAIT);
            if(n==opt.packet_size) {if(!load)tx[index]=current;sent++;}
            else errors++;
            index++;
        }
        if(load) {relax_cpu();continue;}
        /* Bounded drain lets sending keep its independent open-loop schedule. */
        for(int j=0;j<16;j++) {
            ssize_t n=recv(fd,buffer,sizeof(buffer),MSG_DONTWAIT);
            uint64_t arrival=now();
            if(n<0) {
                if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=ECONNREFUSED&&errno!=EINTR)fail("UDP recv");
                break;
            }
            if(n<(ssize_t)sizeof(struct packet))continue;
            struct packet p;memcpy(&p,buffer,sizeof(p));
            uint64_t seq=be64toh(p.seq);
            if(be64toh(p.magic)!=MAGIC||be64toh(p.run)!=cookie||seq>=opt.samples||!tx[seq])continue;
            if(rx[seq]){duplicates++;continue;}
            if(received&&seq<highest)reordered++;
            if(seq>highest)highest=seq;
            rx[seq]=arrival;received++;
            uint64_t id=ntohl(p.napi);
            if(received==1)first_id=id;
            else if(id!=last_id)id_changes++;
            last_id=id;
            service[seq]=be64toh(p.service);
        }
        if(index==opt.samples && received==sent)break;
        relax_cpu();
    }
    uint64_t finished=now(),elapsed=finished>start?finished-start:0;
    struct rusage endru;if(getrusage(RUSAGE_THREAD,&endru))fail("getrusage");
    printf("{\"kind\":\"%s\",\"cpu\":%d,\"sent\":%"PRIu64
        ",\"received\":%"PRIu64",\"scheduled\":%"PRIu64",\"skipped_slots\":%"PRIu64
        ",\"send_errors\":%"PRIu64",\"duplicates\":%"PRIu64",\"reordered\":%"PRIu64
        ",\"lost\":%"PRIu64",\"first_napi_id\":%"PRIu64",\"last_napi_id\":%"PRIu64
        ",\"napi_id_changes\":%"PRIu64",\"elapsed_ns\":%"PRIu64
        ",\"interval_us\":%"PRIu64",\"burst\":%"PRIu64",\"quiet_us\":%"PRIu64,
        load?"udp-load":"udp-client",opt.cpu,sent,received,load?index:opt.samples,skipped,
        errors,duplicates,reordered,load?0:sent-received,first_id,last_id,id_changes,
        elapsed,opt.interval_us,opt.burst,opt.quiet_us);
    usage_stats(&ru,&endru);
    printf(",\"start_monotonic_ns\":%"PRIu64,start);
    if(!load) {
        uint64_t late_n=0;
        for(uint64_t i=0;i<opt.samples;i++) {
            if(tx[i])late[late_n++]=tx[i]-(start+schedule(i));
            if(!rx[i])continue;
            rtt[nsamples]=rx[i]-tx[i];scheduled[nsamples]=rx[i]-(start+schedule(i));
            service[nsamples]=service[i];
            if(opt.quiet_us&&i>0&&i%opt.burst==0)first[first_n++]=rtt[nsamples];
            rx[nsamples]=rx[i]-start;
            nsamples++;
        }
        array("rtt_ns",rtt,nsamples);array("scheduled_to_reply_ns",scheduled,nsamples);
        array("send_lateness_ns",late,late_n);array("first_after_quiet_rtt_ns",first,first_n);
        array("server_service_ns",service,nsamples);
        array("reply_offset_ns",rx,nsamples);
    }
    puts("}");close(fd);return stopped?130:0;
}

int main(int argc,char **argv) {
    if(argc<2)invalid("usage: latprobe memory|rcu|echo|udp-client|udp-load [options]");
    const char *mode=argv[1];
    if(!strcmp(mode,"identity")) {
        struct utsname u;if(uname(&u))fail("uname");
        /* Linux uname fields are normally printable host labels; reject JSON metacharacters. */
        if(strpbrk(u.release,"\"\\\n")||strpbrk(u.machine,"\"\\\n")||strpbrk(u.nodename,"\"\\\n"))
            invalid("unsupported characters in uname");
        printf("{\"protocol\":1,\"kernel\":\"%s\",\"machine\":\"%s\",\"hostname\":\"%s\"}\n",
               u.release,u.machine,u.nodename);return 0;
    }
    enum {SAMPLES=1000,LOADS,SIZE,GAP,INTERVAL,BURST,QUIET,WARM,TIMEOUT,DURATION,
          CPU,NOISECPU,PORT,SOURCE,SIZEPKT,BUSY,BUDGET,PREFER,LOCK,NOISE,ADDRESS,READY,START,TRAFFIC,CHURN};
    const struct option opts[]={
        {"samples",1,0,SAMPLES},{"loads",1,0,LOADS},{"size-mb",1,0,SIZE},
        {"gap-us",1,0,GAP},{"interval-us",1,0,INTERVAL},{"burst",1,0,BURST},
        {"quiet-us",1,0,QUIET},{"warmup-ms",1,0,WARM},{"timeout-ms",1,0,TIMEOUT},
        {"duration-ms",1,0,DURATION},{"cpu",1,0,CPU},{"noise-cpu",1,0,NOISECPU},
        {"port",1,0,PORT},{"source-port",1,0,SOURCE},{"packet-size",1,0,SIZEPKT},
        {"busy-us",1,0,BUSY},{"budget",1,0,BUDGET},{"prefer",1,0,PREFER},
        {"mlock",0,0,LOCK},{"noise",1,0,NOISE},{"address",1,0,ADDRESS},
        {"ready",1,0,READY},{"start",1,0,START},{"traffic",1,0,TRAFFIC},
        {"churn-interval-us",1,0,CHURN},{0,0,0,0}};
    optind=2;int c;
    while((c=getopt_long(argc,argv,"",opts,NULL))!=-1) {
        uint64_t n=0;
        if(c>=SAMPLES&&c<=PREFER)n=parse_uint(optarg);
        if(c>=CPU&&c<=PREFER&&n>INT32_MAX)invalid("integer option too large");
        switch(c) {
        case SAMPLES:opt.samples=n;break;case LOADS:opt.loads=n;break;case SIZE:opt.size_mb=n;break;
        case GAP:opt.gap_us=n;break;case INTERVAL:opt.interval_us=n;break;case BURST:opt.burst=n;break;
        case QUIET:opt.quiet_us=n;break;case WARM:opt.warmup_ms=n;break;case TIMEOUT:opt.timeout_ms=n;break;
        case DURATION:opt.duration_ms=n;break;case CPU:opt.cpu=(int)n;break;case NOISECPU:opt.noise_cpu=(int)n;break;
        case PORT:opt.port=(int)n;break;case SOURCE:opt.source_port=(int)n;break;case SIZEPKT:opt.packet_size=(int)n;break;
        case BUSY:opt.busy_us=(int)n;break;case BUDGET:opt.budget=(int)n;break;case PREFER:opt.prefer=(int)n;break;
        case LOCK:opt.lock=true;break;case NOISE:opt.noise=optarg;break;case ADDRESS:opt.address=optarg;break;
        case READY:opt.ready=optarg;break;case START:opt.start=optarg;break;case TRAFFIC:opt.traffic=optarg;break;
        case CHURN:opt.churn_interval_us=parse_uint(optarg);break;
        default:invalid("unknown option");
        }
    }
    if(optind!=argc)invalid("unexpected positional argument");
    if(!opt.samples||opt.samples>10000000||!opt.loads||opt.loads>1000000||!opt.size_mb||opt.size_mb>16384||
       !opt.interval_us||opt.interval_us>10000000||!opt.burst||opt.burst>10000000||opt.quiet_us>10000000||
       opt.gap_us>10000000||opt.warmup_ms>600000||opt.timeout_ms>60000||opt.duration_ms>3600000||
       opt.port<1||opt.port>65535||opt.source_port<1||opt.source_port>65535||opt.packet_size<(int)sizeof(struct packet)||
       opt.packet_size>9000||opt.budget<1||opt.budget>65535||opt.prefer>1||opt.busy_us>1000000||opt.churn_interval_us>1000000)
        invalid("option out of supported range");
    if(strcmp(opt.noise,"none")&&strcmp(opt.noise,"thread")&&strcmp(opt.noise,"process"))invalid("invalid noise mode");
    signal(SIGINT,stop_handler);signal(SIGTERM,stop_handler);
    if(!strcmp(mode,"memory"))return memory_worker(false);
    if(!strcmp(mode,"rcu"))return memory_worker(true);
    if(!strcmp(mode,"echo"))return echo_worker();
    if(!strcmp(mode,"udp-client"))return client_worker(false);
    if(!strcmp(mode,"udp-load"))return client_worker(true);
    invalid("unknown worker mode");return 2;
}
