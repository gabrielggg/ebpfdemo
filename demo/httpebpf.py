#!/usr/bin/env python3

from bcc import BPF
import socket
import struct
import argparse
import sys
import time

# eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/uio.h>

#define MAX_PAYLOAD_SIZE 1024
#define HTTP_PORT 80
#define HTTPS_PORT 443

// Structure to hold HTTP data
struct http_data_t {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 payload_len;
    u8 payload[MAX_PAYLOAD_SIZE];
    u8 direction; // 0 = inbound, 1 = outbound
};

// Map to store HTTP data
BPF_PERF_OUTPUT(http_events);

// Map to store data for retrieval in kretprobe
BPF_HASH(recv_args, u32, struct msghdr*);

// Helper function to check if data contains HTTP
static inline int is_http_data(const char* data, u32 len) {
    if (len < 4) return 0;
    
    // Check for HTTP methods
    if (bpf_strncmp(data, "GET ", 4) == 0 ||
        bpf_strncmp(data, "POST", 4) == 0 ||
        bpf_strncmp(data, "PUT ", 4) == 0 ||
        bpf_strncmp(data, "HEAD", 4) == 0 ||
        bpf_strncmp(data, "DELE", 4) == 0 ||
        bpf_strncmp(data, "PATC", 4) == 0 ||
        bpf_strncmp(data, "OPTI", 4) == 0) {
        return 1;
    }
    
    // Check for HTTP response
    if (len >= 8 && bpf_strncmp(data, "HTTP/1.", 7) == 0) {
        return 1;
    }
    
    return 0;
}

// Helper function to extract data from iov_iter
static inline int extract_iov_data(struct iov_iter *iter, char *buffer, u32 max_len) {
    // Try to read from the iterator based on its type
    if (iter->type & ITER_IOVEC) {
        // For IOVEC type, try to access the iov structure
        struct iovec iov;
        if (bpf_probe_read_kernel(&iov, sizeof(iov), iter->iov) != 0) {
            return 0;
        }
        
        u32 len = iov.iov_len;
        if (len > max_len) len = max_len;
        
        if (bpf_probe_read_user(buffer, len, iov.iov_base) != 0) {
            return 0;
        }
        return len;
    }
    
    return 0;
}

// Alternative approach using socket buffer
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    if (size == 0) return 0;
    
    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 sport = bpf_ntohs(inet->inet_sport);
    u16 dport = bpf_ntohs(inet->inet_dport);
    
    // Filter for HTTP ports
    if (sport != HTTP_PORT && dport != HTTP_PORT && 
        sport != HTTPS_PORT && dport != HTTPS_PORT) {
        return 0;
    }
    
    // Extract data from iov_iter
    char data_buffer[MAX_PAYLOAD_SIZE];
    u32 len = extract_iov_data(&msg->msg_iter, data_buffer, MAX_PAYLOAD_SIZE);
    
    if (len == 0) return 0;
    if (len > size) len = size;
    
    // Check if this is HTTP data
    if (!is_http_data(data_buffer, len)) return 0;
    
    struct http_data_t http_data = {};
    http_data.pid = bpf_get_current_pid_tgid() >> 32;
    http_data.uid = bpf_get_current_uid_gid() & 0xffffffff;
    http_data.saddr = inet->inet_saddr;
    http_data.daddr = inet->inet_daddr;
    http_data.sport = sport;
    http_data.dport = dport;
    http_data.payload_len = len;
    http_data.direction = 1; // outbound
    
    // Copy payload data
    __builtin_memcpy(http_data.payload, data_buffer, len);
    
    http_events.perf_submit(ctx, &http_data, sizeof(http_data));
    return 0;
}

// Store arguments for kretprobe
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    recv_args.update(&pid, &msg);
    return 0;
}

// Kretprobe for tcp_recvmsg to capture received data
int kretprobe__tcp_recvmsg(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct msghdr **msg_ptr = recv_args.lookup(&pid);
    if (!msg_ptr) return 0;
    
    struct msghdr *msg = *msg_ptr;
    recv_args.delete(&pid);
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 sport = bpf_ntohs(inet->inet_sport);
    u16 dport = bpf_ntohs(inet->inet_dport);
    
    // Filter for HTTP ports
    if (sport != HTTP_PORT && dport != HTTP_PORT && 
        sport != HTTPS_PORT && dport != HTTPS_PORT) {
        return 0;
    }
    
    // Extract data from iov_iter
    char data_buffer[MAX_PAYLOAD_SIZE];
    u32 len = extract_iov_data(&msg->msg_iter, data_buffer, MAX_PAYLOAD_SIZE);
    
    if (len == 0) return 0;
    if (len > ret) len = ret;
    
    // Check if this is HTTP data
    if (!is_http_data(data_buffer, len)) return 0;
    
    struct http_data_t http_data = {};
    http_data.pid = pid;
    http_data.uid = bpf_get_current_uid_gid() & 0xffffffff;
    http_data.saddr = inet->inet_saddr;
    http_data.daddr = inet->inet_daddr;
    http_data.sport = sport;
    http_data.dport = dport;
    http_data.payload_len = len;
    http_data.direction = 0; // inbound
    
    // Copy payload data
    __builtin_memcpy(http_data.payload, data_buffer, len);
    
    http_events.perf_submit(ctx, &http_data, sizeof(http_data));
    return 0;
}

// Alternative approach using socket write/read syscalls
int kprobe__sys_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    if (count == 0 || count > MAX_PAYLOAD_SIZE) return 0;
    
    char data[MAX_PAYLOAD_SIZE];
    if (bpf_probe_read_user(data, count, buf) != 0) return 0;
    
    // Check if this looks like HTTP data
    if (!is_http_data(data, count)) return 0;
    
    struct http_data_t http_data = {};
    http_data.pid = bpf_get_current_pid_tgid() >> 32;
    http_data.uid = bpf_get_current_uid_gid() & 0xffffffff;
    http_data.payload_len = count;
    http_data.direction = 1; // outbound
    
    __builtin_memcpy(http_data.payload, data, count);
    
    http_events.perf_submit(ctx, &http_data, sizeof(http_data));
    return 0;
}

int kprobe__sys_read(struct pt_regs *ctx, int fd, char __user *buf, size_t count) {
    return 0;
}

int kretprobe__sys_read(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0 || ret > MAX_PAYLOAD_SIZE) return 0;
    
    char __user *buf = (char __user *)PT_REGS_PARM2(ctx);
    char data[MAX_PAYLOAD_SIZE];
    
    if (bpf_probe_read_user(data, ret, buf) != 0) return 0;
    
    // Check if this looks like HTTP data
    if (!is_http_data(data, ret)) return 0;
    
    struct http_data_t http_data = {};
    http_data.pid = bpf_get_current_pid_tgid() >> 32;
    http_data.uid = bpf_get_current_uid_gid() & 0xffffffff;
    http_data.payload_len = ret;
    http_data.direction = 0; // inbound
    
    __builtin_memcpy(http_data.payload, data, ret);
    
    http_events.perf_submit(ctx, &http_data, sizeof(http_data));
    return 0;
}
"""

class HTTPCapture:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.b = BPF(text=bpf_program)
        
    def print_event(self, cpu, data, size):
        event = self.b["http_events"].event(data)
        
        # Convert IP addresses
        saddr = socket.inet_ntoa(struct.pack("I", event.saddr))
        daddr = socket.inet_ntoa(struct.pack("I", event.daddr))
        
        direction = "OUT" if event.direction == 1 else "IN"
        
        # Extract payload
        payload = event.payload[:event.payload_len].decode('utf-8', errors='ignore')
        
        print(f"\n{'='*60}")
        print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"PID: {event.pid}, UID: {event.uid}")
        print(f"Direction: {direction}")
        print(f"Connection: {saddr}:{event.sport} -> {daddr}:{event.dport}")
        print(f"Payload Length: {event.payload_len} bytes")
        print(f"{'='*60}")
        
        # Pretty print HTTP data
        if payload:
            lines = payload.split('\n')
            for line in lines:
                if line.strip():
                    print(f"  {line}")
        
        if self.verbose:
            print(f"\nRaw payload (hex): {event.payload[:event.payload_len].hex()}")
    
    def run(self):
        print("Starting HTTP payload capture...")
        print("Press Ctrl+C to stop")
        
        # Attach to perf buffer
        self.b["http_events"].open_perf_buffer(self.print_event)
        
        try:
            while True:
                try:
                    self.b.perf_buffer_poll()
                except KeyboardInterrupt:
                    print("\nStopping capture...")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    time.sleep(1)
        finally:
            print("Cleanup complete")

def main():
    parser = argparse.ArgumentParser(description='Capture HTTP payloads using eBPF')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output including hex dumps')
    parser.add_argument('--test', action='store_true',
                       help='Run a simple test to verify the program loads')
    
    args = parser.parse_args()
    
    if args.test:
        print("Testing BPF program compilation...")
        try:
            b = BPF(text=bpf_program)
            print("✓ BPF program compiled successfully")
            return 0
        except Exception as e:
            print(f"✗ BPF compilation failed: {e}")
            return 1
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This program must be run as root")
        return 1
    
    try:
        capture = HTTPCapture(verbose=args.verbose)
        capture.run()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    import os
    sys.exit(main())
