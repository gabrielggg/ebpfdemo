#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import ctypes

# eBPF program with HTTP body capture
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define MAX_BODY_SIZE 256

// Structure for connection events
struct conn_event_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

// Structure for data events
struct data_event_t {
    u32 pid;
    int fd;
    u8 direction;  // 0=send, 1=recv
    char buffer[MAX_BODY_SIZE];
    u32 buffer_len;
};

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(conn_events);
BPF_PERF_OUTPUT(data_events);

// Store HTTP connections
BPF_HASH(http_connections, u32, struct conn_event_t);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid();
    currsock.update(&pid, &sk);
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&pid);
    if (!skpp) return 0;

    if (PT_REGS_RC(ctx) != 0) {
        currsock.delete(&pid);
        return 0;
    }

    struct sock *skp = *skpp;
    struct conn_event_t conn = {};
    conn.pid = pid >> 32;
    conn.saddr = skp->__sk_common.skc_rcv_saddr;
    conn.daddr = skp->__sk_common.skc_daddr;
    conn.dport = ntohs(skp->__sk_common.skc_dport);
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));
    
    http_connections.update(&pid, &conn);
    conn_events.perf_submit(ctx, &conn, sizeof(conn));
    currsock.delete(&pid);
    return 0;
}

// Capture send data
int trace_send(struct pt_regs *ctx, int fd, void *buf, size_t len) {
    struct data_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.fd = fd;
    event.direction = 0;
    event.buffer_len = len > MAX_BODY_SIZE ? MAX_BODY_SIZE : len;
    bpf_get_current_comm(&event.buffer, sizeof(event.buffer));
    bpf_probe_read_user(event.buffer, event.buffer_len, buf);
    data_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Capture recv data
int trace_recv(struct pt_regs *ctx, int fd, void *buf, size_t len) {
    struct data_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.fd = fd;
    event.direction = 1;
    event.buffer_len = len > MAX_BODY_SIZE ? MAX_BODY_SIZE : len;
    bpf_get_current_comm(&event.buffer, sizeof(event.buffer));
    bpf_probe_read_user(event.buffer, event.buffer_len, buf);
    data_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)

# Attach kprobes for send/recv
send_fn = b.get_syscall_fnname("send")
b.attach_kprobe(event=send_fn, fn_name="trace_send")

recv_fn = b.get_syscall_fnname("recv")
b.attach_kprobe(event=recv_fn, fn_name="trace_recv")

# Define event printers
def print_conn_event(cpu, data, size):
    event = b["conn_events"].event(data)
    printb(b"%-6d %-12.12s %-16s %-16s %-4d" % (
        event.pid,
        event.comm,
        inet_ntoa(event.saddr),
        inet_ntoa(event.daddr),
        event.dport
    ))

def print_data_event(cpu, data, size):
    event = b["data_events"].event(data)
    direction = "SEND" if event.direction == 0 else "RECV"
    body = bytes(event.buffer[:event.buffer_len]).decode('utf-8', errors='replace')
    printb(b"%-6d %-12.12s %-4s FD:%-3d %.*s" % (
        event.pid,
        event.buffer,
        direction.encode(),
        event.fd,
        min(event.buffer_len, 120),
        body.encode()
    ))

# Helper function to convert IP addresses
def inet_ntoa(addr):
    return b'.'.join([str(addr >> i & 0xff).encode() for i in [0, 8, 16, 24][::-1]])

# Print headers
print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR", "DPORT"))
b["conn_events"].open_perf_buffer(print_conn_event)
print("\n%-6s %-12s %-4s %-5s %s" % ("PID", "COMM", "DIR", "FD", "BODY"))
b["data_events"].open_perf_buffer(print_data_event)

# Poll both perf buffers
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
