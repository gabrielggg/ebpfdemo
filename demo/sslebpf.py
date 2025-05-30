from bcc import BPF
import sys
import ctypes
 
# Must match the C “#define MAX_DATA_SIZE 4096”
MAX_DATA_SIZE = 4096
# Python-side definition of the C struct:
class SSLDataEvent(ctypes.Structure):
    _fields_ = [
        # enum ssl_data_event_type is a 32-bit int
        ("type",        ctypes.c_int),
        # padding to align the next uint64 to an 8-byte boundary
        ("_pad",        ctypes.c_int),
        # the timestamp in nanoseconds (uint64_t)
        ("timestamp_ns",ctypes.c_ulonglong),
        # pid and tid (each uint32_t)
        ("pid",         ctypes.c_uint),
        ("tid",         ctypes.c_uint),
        # the data buffer
        ("data",        ctypes.c_char * MAX_DATA_SIZE),
        # length of valid data
        ("data_len",    ctypes.c_int),
    ]

# eBPF program in C
bpf_text = """
/*
 * Copyright 2018- The Pixie Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <linux/ptrace.h>

//#include "openssl_tracer_types.h"


#pragma once

#define MAX_DATA_SIZE 4096

enum ssl_data_event_type { kSSLRead, kSSLWrite };

struct ssl_data_event_t {
  enum ssl_data_event_type type;
  uint64_t timestamp_ns;
  uint32_t pid;
  uint32_t tid;
  char data[MAX_DATA_SIZE];
  int32_t data_len;
};

BPF_PERF_OUTPUT(tls_events);

/***********************************************************
 * Internal structs and definitions
 ***********************************************************/

// Key is thread ID (from bpf_get_current_pid_tgid).
// Value is a pointer to the data buffer argument to SSL_write/SSL_read.
BPF_HASH(active_ssl_read_args_map, uint64_t, const char*);
BPF_HASH(active_ssl_write_args_map, uint64_t, const char*);

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
BPF_PERCPU_ARRAY(data_buffer_heap, struct ssl_data_event_t, 1);

/***********************************************************
 * General helper functions
 ***********************************************************/


static __inline struct ssl_data_event_t* create_ssl_data_event(uint64_t current_pid_tgid) {
  uint32_t kZero = 0;
  struct ssl_data_event_t* event = data_buffer_heap.lookup(&kZero);
  if (event == NULL) {
    return NULL;
  }

  const uint32_t kMask32b = 0xffffffff;
  event->timestamp_ns = bpf_ktime_get_ns();
  event->pid = current_pid_tgid >> 32;
  event->tid = current_pid_tgid & kMask32b;

  return event;
}

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/

 #define MAX_DATA_SIZE 4096
 #define MAX_CHUNKS 16   // support up to 16×4096 = 64KiB per syscall

 static int process_SSL_data(struct pt_regs* ctx,
                             uint64_t id,
                             enum ssl_data_event_type type,
                             const char* buf) {
    int total = (int)PT_REGS_RC(ctx);
    if (total < 0) return 0;

    #pragma unroll
    for (int chunk_off = 0; chunk_off < total && chunk_off < MAX_CHUNKS*MAX_DATA_SIZE; 
         chunk_off += MAX_DATA_SIZE) {
      int this_len = total - chunk_off;
      if (this_len > MAX_DATA_SIZE)
        this_len = MAX_DATA_SIZE;

      struct ssl_data_event_t* event = create_ssl_data_event(id);
      if (!event) return 0;

      event->type       = type;
      event->data_len   = this_len;
      // you may want to add an `offset` field to your struct so Python can reassemble
      bpf_probe_read(event->data, this_len, buf + chunk_off);
      tls_events.perf_submit(ctx, event, sizeof(*event));
    }

    return 0;
 }


/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/

// Function signature being probed:
// int SSL_write(SSL *ssl, const void *buf, int num);
int probe_entry_SSL_write(struct pt_regs* ctx) {
  uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = current_pid_tgid >> 32;

  //if (pid != TRACE_PID) {
    //return 0;
  //}

  const char* buf = (const char*)PT_REGS_PARM2(ctx);
  //bpf_probe_read(data, len, buf);
  active_ssl_write_args_map.update(&current_pid_tgid, &buf);

  return 0;
}

int probe_ret_SSL_write(struct pt_regs* ctx) {
  uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = current_pid_tgid >> 32;

  //if (pid != TRACE_PID) {
    //return 0;
  //}

  const char** buf = active_ssl_write_args_map.lookup(&current_pid_tgid);
  if (buf != NULL) {
  process_SSL_data(ctx, current_pid_tgid, kSSLWrite, *buf);
  }

  active_ssl_write_args_map.delete(&current_pid_tgid);
  return 0;
}




// Function signature being probed:
// int SSL_read(SSL *s, void *buf, int num)
int probe_entry_SSL_read(struct pt_regs* ctx) {
  uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = current_pid_tgid >> 32;

  //if (pid != TRACE_PID) {
    //return 0;
  //}

  const char* buf = (const char*)PT_REGS_PARM2(ctx);

  active_ssl_read_args_map.update(&current_pid_tgid, &buf);
  return 0;
}

int probe_ret_SSL_read(struct pt_regs* ctx) {
  uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = current_pid_tgid >> 32;

  //if (pid != TRACE_PID) {
    //return 0;
  //}

  const char** buf = active_ssl_read_args_map.lookup(&current_pid_tgid);
  if (buf != NULL) {
    process_SSL_data(ctx, current_pid_tgid, kSSLRead, *buf);
  }

  active_ssl_read_args_map.delete(&current_pid_tgid);
  return 0;
}


"""

# Load the eBPF program
b = BPF(text=bpf_text)

# Attach the uprobe to the 'main' function of /bin/ls
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_write", fn_name="probe_entry_SSL_write")
b.attach_uretprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_write", fn_name="probe_ret_SSL_write")

# Read the counts from the BPF map
#elements = b.get_table("active_ssl_write_args_map")
#def print_event(cpu, data, size):
#    #event = b["tls_events"]
#    event = b["tls_events"].event(data)
#    #print(f"PID: {event.pid}, COMM: {event.comm.decode()}")
#    print(event)

#def print_event(cpu, data, size):
#    # cast the raw perf‐buffer blob into our Python struct
#    event = ctypes.cast(data, ctypes.POINTER(SSLDataEvent)).contents
#    # only print the part of the buffer that's valid
#    buf = bytes(event.data[:event.data_len])
#    print(f"[{event.timestamp_ns}] PID={event.pid} TID={event.tid} "
#          f"{'READ' if event.type==0 else 'WRITE'} len={event.data_len}\n"
#          f"    {buf!r}")

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(SSLDataEvent)).contents
    buf = bytes(event.data[:event.data_len])
    print(
        f"[{event.timestamp_ns}] PID={event.pid} TID={event.tid} "
        f"{'READ' if event.type==0 else 'WRITE'} len={event.data_len}\n"
        f"    {buf!r}"
    )

def lost_event(cpu, count):
    # report how many we dropped
    print(f"*** LOST {count} EVENTS on CPU {cpu} ***", file=sys.stderr)

# bump to 64 pages instead of the default 8, and hook our lost-event handler
b["tls_events"].open_perf_buffer(
    print_event,
    page_cnt=64,
    lost_cb=lost_event
)

#b["tls_events"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
#while 1:
# for k, v in elements.items():
#    print(f"main called {v.value} times")
#    print(elements.items())
