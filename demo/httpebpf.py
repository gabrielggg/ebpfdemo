from bcc import BPF
import socket
import struct

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/net.h>
#include <linux/in.h>

struct data_t {
    u32 pid;
    u64 ts;
    u32 len;
    char comm[TASK_COMM_LEN];
    char buf[256];
};
BPF_PERF_OUTPUT(events);

int kretprobe__sys_recvfrom(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    data.len = ret;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Retrieve arguments of sys_recvfrom
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t bytes_to_read = ret;
    if (bytes_to_read > sizeof(data.buf)) {
        bytes_to_read = sizeof(data.buf);
    }
    bpf_probe_read_user(&data.buf, bytes_to_read, buf);

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

print("Attaching kretprobe to sys_recvfrom... (Ctrl-C to stop)")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching...")
