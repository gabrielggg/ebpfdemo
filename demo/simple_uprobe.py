from bcc import BPF

# eBPF program in C
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(counts, u64);

int do_count(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *value = counts.lookup(&key);
    if (value) {
        (*value)++;
    } else {
        u64 init_value = 1;
        counts.update(&key, &init_value);
    }
    return 0;
}
"""

# Load the eBPF program
b = BPF(text=bpf_text)

# Attach the uprobe to the 'main' function of /bin/ls
b.attach_uprobe(name="/home/adminctpl/hello", sym="main.main", fn_name="do_count")

# Read the counts from the BPF map
counts = b.get_table("counts")
while 1:
 for k, v in counts.items():
    print(f"main called {v.value} times")
