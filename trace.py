from bcc import BPF
from ctypes import c_int

# eBPF program code
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Data structure to pass information to user space
struct data_t {
    u32 pid;
    int type;   // 0 for send, 1 for recv
    int fd;
    size_t len;
    int flags;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_send(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = 0; // Indicate send syscall
    data.fd = PT_REGS_PARM1(ctx);
    data.len = PT_REGS_PARM3(ctx);
    data.flags = PT_REGS_PARM4(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_recv(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = 1; // Indicate recv syscall
    data.fd = PT_REGS_PARM1(ctx);
    data.len = PT_REGS_PARM3(ctx);
    data.flags = PT_REGS_PARM4(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Load the eBPF program
bpf = BPF(text=bpf_code)

# Attach kprobes to send and recv syscalls
send_fn = bpf.get_syscall_fnname("send")
bpf.attach_kprobe(event=send_fn, fn_name="trace_send")

recv_fn = bpf.get_syscall_fnname("recv")
bpf.attach_kprobe(event=recv_fn, fn_name="trace_recv")

# Define event printer
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    action = "SEND" if event.type == 0 else "RECV"
    print(f"PID: {event.pid:<6} COMM: {event.comm.decode():<12} TYPE: {action:<4} FD: {event.fd:<4} LEN: {event.len:<6} FLAGS: {event.flags}")

print("Tracing send and recv syscalls... Ctrl-C to exit.")

# Read events from the perf buffer
bpf["events"].open_perf_buffer(print_event)
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
