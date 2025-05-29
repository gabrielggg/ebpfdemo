#!/usr/bin/env python3
#
# decrypt_tls.py  Trace OpenSSL TLS read/write to dump plaintext
#
# USAGE: sudo ./decrypt_tls.py <pid> [libssl_path]
#
# Example: sudo ./decrypt_tls.py 1234 /usr/lib/x86_64-linux-gnu/libssl.so.1.1

from bcc import BPF, USDT
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

    // SSL_read(buf) second argument is in RDX on x86_64
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
    direction = "<" if print_event.is_read else ">"
    payload = event.buf[:event.len].decode('utf-8', errors='replace')
    print(f"{direction} pid={event.pid} tid={event.tid} len={event.len}")
    print(payload)
    print("-" * 40)

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pid> [libssl.so path]")
        sys.exit(1)

    target_pid = int(sys.argv[1])
    lib_path = sys.argv[2] if len(sys.argv) >= 3 else "libssl.so"

    # load BPF program
    b = BPF(text=bpf_text)

    # SSL_read retprobe (decrypted data coming in)
    b.attach_uprobe(name=lib_path, sym="SSL_read",
                    fn_name="probe_SSL_read_ret",
                    pid=target_pid, retprobe=True)
    print_event.is_read = True
    b["events"].open_perf_buffer(print_event)

    # SSL_write entry (plaintext about to go out)
    b.attach_uprobe(name=lib_path, sym="SSL_write",
                    fn_name="probe_SSL_write_entry",
                    pid=target_pid, retprobe=False)
    print_event.is_read = False

    print(f"Tracing TLS plaintext on pid {target_pid} (hit Ctrl-C to end)")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Detaching…")
