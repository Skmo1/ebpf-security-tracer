// SPDX-License-Identifier: GPL-2.0
// Programme eBPF: trace execve() et connect() pour détecter des patterns
// suspects (ex: un process qui exécute un shell peu après une connexion
// réseau sortante — signature classique de reverse shell).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Événement envoyé au userspace via ring buffer
struct event {
    __u32 pid;
    __u32 ppid;
    __u8  type; // 0 = execve, 1 = connect
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN]; // utilisé seulement pour execve
    __u32 daddr;   // adresse IP destination (pour connect, IPv4)
    __u16 dport;   // port destination (pour connect)
};

// Ring buffer pour remonter les événements au userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Trace le syscall execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->type = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Lire le nom du fichier exécuté (premier argument d'execve)
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Trace les connexions réseau sortantes (IPv4 uniquement dans ce starter)
SEC("kprobe/tcp_v4_connect")
int trace_connect(struct pt_regs *ctx)
{
    struct event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Adresse et port de destination depuis la struct sock
    BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
    __u16 dport;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    e->dport = __builtin_bswap16(dport); // network byte order -> host

    bpf_ringbuf_submit(e, 0);
    return 0;
}
