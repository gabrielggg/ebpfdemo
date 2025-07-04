from bcc import BPF
import ctypes as ct
import socket
import struct
from enum import Enum


TASK_COMM_LEN = 16
MAX_PAYLOAD_SIZE = 1024  # Maximum payload size to capture
SOCKETS = {}

class EventType(Enum):
    CONNECTED = 0
    DATA_SENT = 1
    DATA_RECEIVED = 2
    CLOSED = 3
    HTTP_REQUEST = 4
    HTTP_RESPONSE = 5

class SocketInfo(ct.Structure):
    _fields_ = [
        ("tgid", ct.c_uint32),
        ("fdf", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("ip_addr", ct.c_uint32),
        ("ret", ct.c_int),
        ("type", ct.c_uint),
        ("payload_size", ct.c_uint32),
        ("payload", ct.c_char * MAX_PAYLOAD_SIZE),
    ]

def is_http_data(data):
    """Check if data contains HTTP request/response"""
    try:
        data_str = data.decode('utf-8', errors='ignore')
        http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']
        http_responses = ['HTTP/1.0 ', 'HTTP/1.1 ', 'HTTP/2.0 ']
        
        # Check for HTTP request
        if any(data_str.startswith(method) for method in http_methods):
            return True, 'REQUEST'
        
        # Check for HTTP response
        if any(data_str.startswith(resp) for resp in http_responses):
            return True, 'RESPONSE'
            
        return False, None
    except:
        return False, None

def print_http_payload(payload, payload_size, event_type, direction=""):
    """Print HTTP payload in a readable format"""
    try:
        # Convert payload to string
        payload_str = payload[:payload_size].decode('utf-8', errors='ignore')
        
        print(f"\n{'='*60}")
        print(f"HTTP {event_type} {direction} ({payload_size} bytes):")
        print(f"{'='*60}")
        
        # Split into lines for better readability
        lines = payload_str.split('\n')
        for i, line in enumerate(lines[:20]):  # Show first 20 lines
            print(f"{i+1:2d}: {line}")
        
        if len(lines) > 20:
            print(f"... ({len(lines)-20} more lines truncated)")
        
        print(f"{'='*60}\n")
        
    except Exception as e:
        print(f"Error parsing payload: {e}")

def print_event(cpu, data, size):
    e = ct.cast(data, ct.POINTER(SocketInfo)).contents
    comm_id = f"{e.comm.decode()}-{e.tgid}"
    
    match e.type:
        case EventType.CONNECTED.value:
            ip_str = socket.inet_ntoa(struct.pack('I', e.ip_addr))
            print(f"[CONNECT] {comm_id} connected socket FD:{e.fdf} to IP:{ip_str}")
            SOCKETS[comm_id] = e
            
        case EventType.CLOSED.value:
            if comm_id in SOCKETS:
                print(f"[CLOSE] {comm_id} closed socket FD:{e.fdf}")
                del SOCKETS[comm_id]
                
        case EventType.DATA_SENT.value:
            if comm_id in SOCKETS:
                print(f"[SEND] {comm_id} sent {e.ret} bytes through socket FD:{e.fdf}")
                
                # Check if we have payload data
                if e.payload_size > 0:
                    payload_bytes = bytes(e.payload[:e.payload_size])
                    is_http, http_type = is_http_data(payload_bytes)
                    
                    if is_http:
                        print_http_payload(payload_bytes, e.payload_size, http_type, "SENT")
                    else:
                        # Print first 100 bytes as hex for non-HTTP data
                        hex_data = payload_bytes[:100].hex()
                        print(f"[RAW DATA SENT] {hex_data}")

        case EventType.DATA_RECEIVED.value:
            if comm_id in SOCKETS:
                print(f"[RECV] {comm_id} received {e.ret} bytes through socket FD:{e.fdf}")
                
                # Check if we have payload data
                if e.payload_size > 0:
                    payload_bytes = bytes(e.payload[:e.payload_size])
                    is_http, http_type = is_http_data(payload_bytes)
                    
                    if is_http:
                        print_http_payload(payload_bytes, e.payload_size, http_type, "RECEIVED")
                    else:
                        # Print first 100 bytes as hex for non-HTTP data
                        hex_data = payload_bytes[:100].hex()
                        print(f"[RAW DATA RECEIVED] {hex_data}")
                        
        case EventType.HTTP_REQUEST.value:
            if e.payload_size > 0:
                payload_bytes = bytes(e.payload[:e.payload_size])
                print_http_payload(payload_bytes, e.payload_size, "REQUEST", "SENT")
                
        case EventType.HTTP_RESPONSE.value:
            if e.payload_size > 0:
                payload_bytes = bytes(e.payload[:e.payload_size])
                print_http_payload(payload_bytes, e.payload_size, "RESPONSE", "RECEIVED")
                
        case _:
            print("Unknown event")


def main():
    bpf_text = f"""
#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define MAX_PAYLOAD_SIZE {MAX_PAYLOAD_SIZE}

// Enumeration to represent the type of event being recorded
enum event_type {{
    CONNECTED,
    DATA_SENT,
    DATA_RECEIVED,
    CLOSED,
    HTTP_REQUEST,
    HTTP_RESPONSE,
}};

// Structure to hold data that will be sent to user space
struct data_t {{
    u32 tgid;                           // Thread ID
    int fdf;                            // Socket File Descriptor
    char comm[TASK_COMM_LEN];          // The current process name
    u32 ip_addr;                       // IP Address
    int ret;                           // Return Value
    enum event_type type;              // Event Type
    u32 payload_size;                  // Size of payload captured
    char payload[MAX_PAYLOAD_SIZE];    // Actual payload data
}};

BPF_PERF_OUTPUT(sockets);  // Declare a BPF map to transmit data to user space

// Structure to hold temporary data for send/recv syscalls
struct send_info_t {{
    u32 tgid;
    int fdf;
    char comm[TASK_COMM_LEN];
    u32 payload_size;
    char payload[MAX_PAYLOAD_SIZE];
}};

struct recv_info_t {{
    u32 tgid;
    int fdf;
    char comm[TASK_COMM_LEN];
    void *buf;
    size_t len;
}};

BPF_HASH(send_infotmp, u32, struct send_info_t);
BPF_HASH(recv_infotmp, u32, struct recv_info_t);

int syscall__connect(struct pt_regs *ctx, int sockfd, const struct sockaddr *addr, int addrlen) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct sockaddr_in addr_in;
    __builtin_memset(&addr_in, 0, sizeof(addr_in));
    bpf_probe_read_user(&addr_in, sizeof(addr_in), addr);

    // Check if address family is AF_INET
    if (addr_in.sin_family == AF_INET) {{
        struct data_t data;
        __builtin_memset(&data, 0, sizeof(data));
        data.tgid = tgid;
        data.fdf = sockfd;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.ip_addr = addr_in.sin_addr.s_addr;
        data.type = CONNECTED;
        data.payload_size = 0;
        sockets.perf_submit(ctx, &data, sizeof(data));
    }}

    return 0;
}}

int syscall__close(struct pt_regs *ctx, int sockfd) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct data_t data;
    __builtin_memset(&data, 0, sizeof(data));
    data.tgid = tgid;
    data.fdf = sockfd;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = CLOSED;
    data.payload_size = 0;
    sockets.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}

// Helper function to check if data contains HTTP patterns
static inline int is_http_request(char *buf, int size) {{
    if (size < 4) return 0;
    
    // Check for HTTP methods
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') return 1;
    if (size >= 5 && buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ') return 1;
    if (size >= 4 && buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') return 1;
    if (size >= 7 && buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E' && buf[6] == ' ') return 1;
    if (size >= 5 && buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ') return 1;
    if (size >= 8 && buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O' && buf[5] == 'N' && buf[6] == 'S' && buf[7] == ' ') return 1;
    if (size >= 6 && buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' && buf[5] == ' ') return 1;
    
    return 0;
}}

static inline int is_http_response(char *buf, int size) {{
    if (size < 8) return 0;
    
    // Check for HTTP response
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P' && buf[4] == '/' && buf[5] == '1' && buf[6] == '.') return 1;
    if (size >= 8 && buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P' && buf[4] == '/' && buf[5] == '2' && buf[6] == '.') return 1;
    
    return 0;
}}

// SEND syscalls - capture outgoing data
int syscall__sendto(struct pt_regs *ctx, int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, int addrlen) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct send_info_t info;
    __builtin_memset(&info, 0, sizeof(info));
    
    if (bpf_get_current_comm(&info.comm, sizeof(info.comm)) == 0) {{
        info.tgid = tgid;
        info.fdf = sockfd;
        
        // Capture payload data
        int copy_size = len < MAX_PAYLOAD_SIZE ? len : MAX_PAYLOAD_SIZE;
        if (copy_size > 0 && buf != NULL) {{
            bpf_probe_read_user(&info.payload, copy_size, buf);
            info.payload_size = copy_size;
        }} else {{
            info.payload_size = 0;
        }}
        
        send_infotmp.update(&tgid, &info);
    }}

    return 0;
}}

int syscall__send(struct pt_regs *ctx, int sockfd, void *buf, size_t len, int flags) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct send_info_t info;
    __builtin_memset(&info, 0, sizeof(info));
    
    if (bpf_get_current_comm(&info.comm, sizeof(info.comm)) == 0) {{
        info.tgid = tgid;
        info.fdf = sockfd;
        
        // Capture payload data
        int copy_size = len < MAX_PAYLOAD_SIZE ? len : MAX_PAYLOAD_SIZE;
        if (copy_size > 0 && buf != NULL) {{
            bpf_probe_read_user(&info.payload, copy_size, buf);
            info.payload_size = copy_size;
        }} else {{
            info.payload_size = 0;
        }}
        
        send_infotmp.update(&tgid, &info);
    }}

    return 0;
}}

int syscall__write(struct pt_regs *ctx, int fd, void *buf, size_t count) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct send_info_t info;
    __builtin_memset(&info, 0, sizeof(info));
    
    if (bpf_get_current_comm(&info.comm, sizeof(info.comm)) == 0) {{
        info.tgid = tgid;
        info.fdf = fd;
        
        // Capture payload data
        int copy_size = count < MAX_PAYLOAD_SIZE ? count : MAX_PAYLOAD_SIZE;
        if (copy_size > 0 && buf != NULL) {{
            bpf_probe_read_user(&info.payload, copy_size, buf);
            info.payload_size = copy_size;
        }} else {{
            info.payload_size = 0;
        }}
        
        send_infotmp.update(&tgid, &info);
    }}

    return 0;
}}

// RECV syscalls - capture incoming data
int syscall__recvfrom(struct pt_regs *ctx, int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct recv_info_t info;
    __builtin_memset(&info, 0, sizeof(info));
    
    if (bpf_get_current_comm(&info.comm, sizeof(info.comm)) == 0) {{
        info.tgid = tgid;
        info.fdf = sockfd;
        info.buf = buf;
        info.len = len;
        
        recv_infotmp.update(&tgid, &info);
    }}

    return 0;
}}

int syscall__recv(struct pt_regs *ctx, int sockfd, void *buf, size_t len, int flags) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct recv_info_t info;
    __builtin_memset(&info, 0, sizeof(info));
    
    if (bpf_get_current_comm(&info.comm, sizeof(info.comm)) == 0) {{
        info.tgid = tgid;
        info.fdf = sockfd;
        info.buf = buf;
        info.len = len;
        
        recv_infotmp.update(&tgid, &info);
    }}

    return 0;
}}

int syscall__read(struct pt_regs *ctx, int fd, void *buf, size_t count) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct recv_info_t info;
    __builtin_memset(&info, 0, sizeof(info));
    
    if (bpf_get_current_comm(&info.comm, sizeof(info.comm)) == 0) {{
        info.tgid = tgid;
        info.fdf = fd;
        info.buf = buf;
        info.len = count;
        
        recv_infotmp.update(&tgid, &info);
    }}

    return 0;
}}

// Return probe for send syscalls
int trace_send_return(struct pt_regs *ctx) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct data_t data;
    __builtin_memset(&data, 0, sizeof(data));
    struct send_info_t *infop;

    // Lookup the entry for our send
    infop = send_infotmp.lookup(&tgid);
    if (infop == 0) {{
        return 0;
    }}

    data.tgid = infop->tgid;
    data.fdf = infop->fdf;
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), infop->comm);
    data.ret = PT_REGS_RC(ctx);
    
    // Copy payload data
    data.payload_size = infop->payload_size;
    if (data.payload_size > 0) {{
        bpf_probe_read_kernel(&data.payload, data.payload_size, infop->payload);
    }}
    
    // Determine event type based on payload content
    if (data.payload_size > 0) {{
        if (is_http_request(data.payload, data.payload_size)) {{
            data.type = HTTP_REQUEST;
        }} else if (is_http_response(data.payload, data.payload_size)) {{
            data.type = HTTP_RESPONSE;
        }} else {{
            data.type = DATA_SENT;
        }}
    }} else {{
        data.type = DATA_SENT;
    }}
    
    sockets.perf_submit(ctx, &data, sizeof(data));
    send_infotmp.delete(&tgid);
    return 0;
}}

// Return probe for recv syscalls
int trace_recv_return(struct pt_regs *ctx) {{
    u32 tgid = bpf_get_current_pid_tgid();
    struct data_t data;
    __builtin_memset(&data, 0, sizeof(data));
    struct recv_info_t *infop;

    // Lookup the entry for our recv
    infop = recv_infotmp.lookup(&tgid);
    if (infop == 0) {{
        return 0;
    }}

    data.tgid = infop->tgid;
    data.fdf = infop->fdf;
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), infop->comm);
    data.ret = PT_REGS_RC(ctx);
    
    // Only process if we successfully received data
    if (data.ret > 0) {{
        // Capture the received payload
        int copy_size = data.ret < MAX_PAYLOAD_SIZE ? data.ret : MAX_PAYLOAD_SIZE;
        if (copy_size > 0 && infop->buf != NULL) {{
            bpf_probe_read_user(&data.payload, copy_size, infop->buf);
            data.payload_size = copy_size;
        }} else {{
            data.payload_size = 0;
        }}
        
        // Determine event type based on payload content
        if (data.payload_size > 0) {{
            if (is_http_request(data.payload, data.payload_size)) {{
                data.type = HTTP_REQUEST;
            }} else if (is_http_response(data.payload, data.payload_size)) {{
                data.type = HTTP_RESPONSE;
            }} else {{
                data.type = DATA_RECEIVED;
            }}
        }} else {{
            data.type = DATA_RECEIVED;
        }}
        
        sockets.perf_submit(ctx, &data, sizeof(data));
    }}
    
    recv_infotmp.delete(&tgid);
    return 0;
}}
    """

    b = BPF(text=bpf_text)

    # Attach probes to different syscalls
    send_syscalls = ['sendto', 'send', 'write']
    recv_syscalls = ['recvfrom', 'recv', 'read']
    
    connect_e = b.get_syscall_fnname("connect").decode()
    close_e = b.get_syscall_fnname("close").decode()
    
    b.attach_kprobe(event=connect_e, fn_name="syscall__connect")
    b.attach_kprobe(event=close_e, fn_name="syscall__close")
    
    # Attach to send syscalls
    for syscall in send_syscalls:
        try:
            syscall_e = b.get_syscall_fnname(syscall).decode()
            b.attach_kprobe(event=syscall_e, fn_name=f"syscall__{syscall}")
            b.attach_kretprobe(event=syscall_e, fn_name="trace_send_return")
            print(f"Attached to {syscall} syscall (SEND)")
        except Exception as e:
            print(f"Warning: Could not attach to {syscall}: {e}")

    # Attach to recv syscalls
    for syscall in recv_syscalls:
        try:
            syscall_e = b.get_syscall_fnname(syscall).decode()
            b.attach_kprobe(event=syscall_e, fn_name=f"syscall__{syscall}")
            b.attach_kretprobe(event=syscall_e, fn_name="trace_recv_return")
            print(f"Attached to {syscall} syscall (RECV)")
        except Exception as e:
            print(f"Warning: Could not attach to {syscall}: {e}")

    # Set up perf buffer
    b["sockets"].open_perf_buffer(print_event)

    try:
        print("\nHTTP Bidirectional Monitor Started - Press Ctrl+C to exit")
        print("Monitoring HTTP traffic (SEND & RECEIVE) on all processes...")
        print("=" * 60)
        
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nStopping HTTP monitor...")

if __name__ == "__main__":
    main()
