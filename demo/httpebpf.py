from bcc import BPF
import socket
import struct

# eBPF C program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <net/sock.h>

struct data_t {
    u32 pid;
    u64 ts;
    u32 len;
    char comm[TASK_COMM_LEN];
    char buf[256];
};
BPF_PERF_OUTPUT(events);

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int flags, int addr_len) {
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), ((char *)sk) + offsetof(struct inet_sock, inet_dport));
    dport = ntohs(dport);

    // Filter port 80 (HTTP)
    if (dport != 80) {
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    data.len = len;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Read iov_base pointer from msghdr
    struct iovec iov;
    bpf_probe_read_kernel(&iov, sizeof(iov), (void *)msg->msg_iter.iov);

    size_t bytes_to_read = len;
    if (bytes_to_read > sizeof(data.buf)) {
        bytes_to_read = sizeof(data.buf);
    }

    bpf_probe_read_kernel(&data.buf, bytes_to_read, iov.iov_base);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=bpf_program)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"\nPID {event.pid} COMM {event.comm.decode()} LEN {event.len}")
    print("Payload:")
    print(event.buf[:event.len].decode(errors="replace"))

print("Attaching kprobe to tcp_recvmsg... (Ctrl-C to stop)")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching...")

