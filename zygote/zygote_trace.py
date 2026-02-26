#!/usr/bin/env python3
from bcc import BPF
import ctypes
import argparse

# eBPF program – simplified execve probe (no loop)
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Event structures – reduced sizes to fit stack
struct fork_event_t {
    u32 zygote_pid;
    u32 child_pid;
    char child_comm[TASK_COMM_LEN];
};

struct exec_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[128];      // executable path
    char argv0[128];          // first argument (usually same as filename)
};

BPF_PERF_OUTPUT(fork_events);
BPF_PERF_OUTPUT(exec_events);

// Maps to track state
BPF_HASH(zygote_pids, u32, u32);
BPF_HASH(in_fork, u32, u32);
BPF_HASH(trace_child, u32, u32);

// Fork entry probes
TRACEPOINT_PROBE(syscalls, sys_enter_clone)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *is_zygote = zygote_pids.lookup(&pid);
    if (is_zygote) {
        u32 val = 1;
        in_fork.update(&pid, &val);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fork)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *is_zygote = zygote_pids.lookup(&pid);
    if (is_zygote) {
        u32 val = 1;
        in_fork.update(&pid, &val);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vfork)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *is_zygote = zygote_pids.lookup(&pid);
    if (is_zygote) {
        u32 val = 1;
        in_fork.update(&pid, &val);
    }
    return 0;
}

// Fork exit probes
TRACEPOINT_PROBE(syscalls, sys_exit_clone)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *in_fork_val = in_fork.lookup(&pid);
    if (in_fork_val) {
        u32 child_pid = args->ret;
        if (child_pid > 0) {
            struct fork_event_t event = {};
            event.zygote_pid = pid;
            event.child_pid = child_pid;
            bpf_get_current_comm(event.child_comm, sizeof(event.child_comm));
            fork_events.perf_submit(args, &event, sizeof(event));

            u32 val = 1;
            trace_child.update(&child_pid, &val);
        }
        in_fork.delete(&pid);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fork)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *in_fork_val = in_fork.lookup(&pid);
    if (in_fork_val) {
        u32 child_pid = args->ret;
        if (child_pid > 0) {
            struct fork_event_t event = {};
            event.zygote_pid = pid;
            event.child_pid = child_pid;
            bpf_get_current_comm(event.child_comm, sizeof(event.child_comm));
            fork_events.perf_submit(args, &event, sizeof(event));

            u32 val = 1;
            trace_child.update(&child_pid, &val);
        }
        in_fork.delete(&pid);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_vfork)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *in_fork_val = in_fork.lookup(&pid);
    if (in_fork_val) {
        u32 child_pid = args->ret;
        if (child_pid > 0) {
            struct fork_event_t event = {};
            event.zygote_pid = pid;
            event.child_pid = child_pid;
            bpf_get_current_comm(event.child_comm, sizeof(event.child_comm));
            fork_events.perf_submit(args, &event, sizeof(event));

            u32 val = 1;
            trace_child.update(&child_pid, &val);
        }
        in_fork.delete(&pid);
    }
    return 0;
}

// Execve probe – simplified without loops
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *should_trace = trace_child.lookup(&pid);
    if (should_trace) {
        struct exec_event_t event = {};
        event.pid = pid;
        bpf_get_current_comm(event.comm, sizeof(event.comm));

        // Read filename
        bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)args->filename);

        // Read first argument (argv[0])
        char *arg0 = 0;
        bpf_probe_read_user(&arg0, sizeof(arg0), &args->argv[0]);
        if (arg0 != 0) {
            bpf_probe_read_user_str(event.argv0, sizeof(event.argv0), arg0);
        } else {
            event.argv0[0] = 0;
        }

        exec_events.perf_submit(args, &event, sizeof(event));
        trace_child.delete(&pid);
    }
    return 0;
}
"""

# --- Python part ---
parser = argparse.ArgumentParser(description="Trace Zygote forks and execve")
parser.add_argument("zygote_pids", nargs="+", type=int, help="Zygote PID(s) to trace")
args = parser.parse_args()

b = BPF(text=bpf_program)

for pid in args.zygote_pids:
    b["zygote_pids"][ctypes.c_uint32(pid)] = ctypes.c_uint32(1)
    print(f"Tracing Zygote PID: {pid}")

class ForkEvent(ctypes.Structure):
    _fields_ = [
        ("zygote_pid", ctypes.c_uint),
        ("child_pid", ctypes.c_uint),
        ("child_comm", ctypes.c_char * 16)
    ]

class ExecEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 128),
        ("argv0", ctypes.c_char * 128)
    ]

def print_fork(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(ForkEvent)).contents
    print(f"FORK: Zygote {event.zygote_pid} -> child {event.child_pid} ({event.child_comm.decode()})")

def print_exec(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(ExecEvent)).contents
    print(f"EXEC: PID {event.pid} ({event.comm.decode()}) filename={event.filename.decode()} argv0={event.argv0.decode()}")

b["fork_events"].open_perf_buffer(print_fork)
b["exec_events"].open_perf_buffer(print_exec)

print("Tracing... Press Ctrl+C to stop.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nExiting.")
