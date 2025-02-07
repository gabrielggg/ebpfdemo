from bcc import BPF

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_BUF_SIZE 1024

struct data_t {
    u32 pid;
    int type;    // 0=send, 1=recv
    int fd;
    size_t len;
    int flags;
    char comm[TASK_COMM_LEN];
    char buffer[MAX_BUF_SIZE];
    u32 buffer_len;
};

BPF_PERF_OUTPUT(events);

static void capture_buffer(struct pt_regs *ctx, void *buf_ptr, struct data_t *data) {
    data->buffer_len = (data->len > MAX_BUF_SIZE) ? MAX_BUF_SIZE : data->len;
    if (data->buffer_len > 0) {
        bpf_probe_read_user(data->buffer, data->buffer_len, buf_ptr);
    }
}

int trace_send(struct pt_regs *ctx) {
    struct data_t data;

    // Manually initialize all fields (no memset!)
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = 0;
    data.fd = PT_REGS_PARM1(ctx);
    data.len = PT_REGS_PARM3(ctx);
    data.flags = PT_REGS_PARM4(ctx);
    data.buffer_len = 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    capture_buffer(ctx, buf, &data);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_recv(struct pt_regs *ctx) {
    struct data_t data;

    // Manual initialization
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = 1;
    data.fd = PT_REGS_PARM1(ctx);
    data.len = PT_REGS_PARM3(ctx);
    data.flags = PT_REGS_PARM4(ctx);
    data.buffer_len = 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    capture_buffer(ctx, buf, &data);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# The rest of the Python code remains unchanged
bpf = BPF(text=bpf_code)

send_fn = bpf.get_syscall_fnname("send")
bpf.attach_kprobe(event=send_fn, fn_name="trace_send")

recv_fn = bpf.get_syscall_fnname("recv")
bpf.attach_kprobe(event=recv_fn, fn_name="trace_recv")

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    action = "SEND" if event.type == 0 else "RECV"
    buf = bytes(event.buffer[:event.buffer_len]).decode('utf-8', errors='replace')
    print(f"PID: {event.pid:<6} COMM: {event.comm.decode():<12} TYPE: {action:<4} FD: {event.fd:<4} LEN: {event.len:<6} FLAGS: {event.flags}")
    print(f"BODY: {buf[:120]} [...]\n")

print("Tracing send/recv with HTTP snippets... Ctrl-C to exit.")
bpf["events"].open_perf_buffer(print_event)
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
