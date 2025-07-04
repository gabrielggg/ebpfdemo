from bcc import BPF

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/net.h>

struct val_t {
    void *buf;
};

struct data_t {
    u32 pid;
    u64 ts;
    u32 len;
    char comm[TASK_COMM_LEN];
    char buf[256];
};

BPF_HASH(active_reads, u64, struct val_t);
BPF_PERF_OUTPUT(events);

int kprobe__sys_recvfrom(struct pt_regs *ctx, int fd, void __user *ubuf, size_t size,
                         unsigned flags, struct sockaddr __user *addr, int __user *addrlen) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct val_t val = {};
    val.buf = ubuf;

    active_reads.update(&pid_tgid, &val);
    return 0;
}

int kretprobe__sys_recvfrom(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct val_t *valp = active_reads.lookup(&pid_tgid);
    if (valp == 0) {
        return 0; // missed entry
    }

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        active_reads.delete(&pid_tgid);
        return 0;
    }

    struct data_t data = {};
    data.pid = pid_tgid >> 32;
    data.ts = bpf_ktime_get_ns();
    data.len = ret;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    size_t bytes_to_read = ret;
    if (bytes_to_read > sizeof(data.buf)) {
        bytes_to_read = sizeof(data.buf);
    }
    bpf_probe_read_user(&data.buf, bytes_to_read, valp->buf);

    events.perf_submit(ctx, &data, sizeof(data));

    active_reads.delete(&pid_tgid);
    return 0;
}
"""

b = BPF(text=bpf_program)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"\nPID {event.pid} COMM {event.comm.decode()} LEN {event.len}")
    print("Payload:")
    print(event.buf[:event.len].decode(errors='replace'))

print("Attaching probes to sys_recvfrom... (Ctrl-C to stop)")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching...")
