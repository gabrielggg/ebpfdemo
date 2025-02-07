from bcc import BPF

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_BUF_SIZE 1024  // Limit captured data to avoid BPF stack issues

struct data_t {
    u32 pid;
    int type;    // 0=send, 1=recv
    int fd;
    size_t len;  // Original buffer length
    int flags;
    char comm[TASK_COMM_LEN];
    char buffer[MAX_BUF_SIZE];
    u32 buffer_len;  // Actual captured length
};

BPF_PERF_OUTPUT(events);

// Helper to capture buffer data safely
static void capture_buffer(struct pt_regs *ctx, void *buf_ptr, struct data_t *data) {
    data->buffer_len = (data->len > MAX_BUF_SIZE) ? MAX_BUF_SIZE : data->len;
    if (data->buffer_len > 0) {
        bpf_probe_read_user(data->buffer, data->buffer_len, buf_ptr);
    }
}

int trace_send(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = 0;
    data.fd = PT_REGS_PARM1(ctx);   // sockfd
    data.len = PT_REGS_PARM3(ctx);  // len
    data.flags = PT_REGS_PARM4(ctx); // flags

    void *buf = (void *)PT_REGS_PARM2(ctx);  // Buffer pointer
    capture_buffer(ctx, buf, &data);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_recv(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = 1;
    data.fd = PT_REGS_PARM1(ctx);   // sockfd
    data.len = PT_REGS_PARM3(ctx);  // len
    data.flags = PT_REGS_PARM4(ctx); // flags

    void *buf = (void *)PT_REGS_PARM2(ctx);  // Buffer pointer
    capture_buffer(ctx, buf, &data);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Load BPF program
bpf = BPF(text=bpf_code)

# Attach kprobes
send_fn = bpf.get_syscall_fnname("send")
bpf.attach_kprobe(event=send_fn, fn_name="trace_send")

recv_fn = bpf.get_syscall_fnname("recv")
bpf.attach_kprobe(event=recv_fn, fn_name="trace_recv")

# Event printer with HTTP body snippet
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    action = "SEND" if event.type == 0 else "RECV"
    
    # Decode buffer (may contain non-printable chars)
    buf = bytes(event.buffer[:event.buffer_len]).decode('utf-8', errors='replace')
    
    print(f"PID: {event.pid:<6} COMM: {event.comm.decode():<12} TYPE: {action:<4} FD: {event.fd:<4} LEN: {event.len:<6} FLAGS: {event.flags}")
    print(f"BODY: {buf[:120]} [...]\n")  # Print first 120 chars to avoid clutter

print("Tracing send/recv with HTTP snippets... Ctrl-C to exit.")
bpf["events"].open_perf_buffer(print_event)
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
