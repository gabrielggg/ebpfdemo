from bcc import BPF

ebpf_program = """
int trace_send(struct pt_regs *ctx) {
    bpf_trace_printk("send syscall detected!\n");
    return 0;
}

int trace_recv(struct pt_regs *ctx) {
    bpf_trace_printk("recv syscall detected!\n");
    return 0;
}
"""

# Load eBPF program
b = BPF(text=ebpf_program)

# Attach kprobes to sys_sendto and sys_recvfrom
b.attach_kprobe(event="sys_sendto", fn_name="trace_send")
b.attach_kprobe(event="sys_recvfrom", fn_name="trace_recv")

print("Tracing send and recv syscalls... Press Ctrl+C to exit.")

# Print trace output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"{ts}: {msg}")
    except KeyboardInterrupt:
        print("Detaching...")
        break;
