#!/usr/bin/env python3
#
# trace_tls_all.py   Trace all OpenSSL TLS read/write across all processes
#
# USAGE: sudo ./trace_tls_all.py [libssl_path]
#
# Example: sudo ./trace_tls_all.py /usr/lib/x86_64-linux-gnu/libssl.so.1.1

from bcc import BPF
import ctypes as ct
import sys

# -----------------------------------------------------------------------------
# BPF program
# -----------------------------------------------------------------------------
bpf_text = r"""
#include <uapi/linux/ptrace.h>

#define MAX_BUF 4096

struct data_t {
    u32 pid;
    u32 tid;
    u32 len;
    char buf[MAX_BUF];
};

BPF_PERF_OUTPUT(events);

/*
 * SSL_read return probe: arg1 = SSL*, arg2 = buf, arg3 = num
 * return value = number of bytes decrypted into buf
 */
int probe_SSL_read_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0 || ret > MAX_BUF) {
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid();
    data.len = ret;

    // SSL_read: buf pointer is in RDX on x86_64
    void *buf = (void *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user(&data.buf, ret, buf);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/*
 * SSL_write entry probe: arg1 = SSL*, arg2 = buf, arg3 = num
 */
int probe_SSL_write_entry(struct pt_regs *ctx) {
    int len = PT_REGS_PARM3(ctx);
    if (len <= 0 || len > MAX_BUF) {
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid();
    data.len = len;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user(&data.buf, len, buf);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# -----------------------------------------------------------------------------
# userspace: parse events & print
# -----------------------------------------------------------------------------
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("len", ct.c_uint),
        ("buf", ct.c_char * 4096),
    ]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    # Direction: '<' for decrypted read, '>' for plaintext write
    direction = '<' if print_event.is_read else '>'
    payload = event.buf[:event.len].decode('utf-8', errors='replace')
    print(f"{direction} pid={event.pid} tid={event.tid} len={event.len}")
    print(payload)
    print('-' * 40)


# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    lib_path = sys.argv[1] if len(sys.argv) > 1 else "libssl.so"

    # load BPF program
    b = BPF(text=bpf_text)

    # Attach to all processes: no pid filter
    b.attach_uprobe(name=lib_path, sym="SSL_read",
                    fn_name="probe_SSL_read_ret", retprobe=True)
    print_event.is_read = True

    b.attach_uprobe(name=lib_path, sym="SSL_write",
                    fn_name="probe_SSL_write_entry", retprobe=False)
    print_event.is_read = False

    b["events"].open_perf_buffer(print_event)

    print(f"Tracing OpenSSL TLS plaintext globally via {lib_path} (Ctrl-C to exit)")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Detaching…")
