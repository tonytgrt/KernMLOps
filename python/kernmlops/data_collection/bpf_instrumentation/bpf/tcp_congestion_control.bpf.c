#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <uapi/linux/ptrace.h>

#define TCP_CA_NAME_MAX 16
#define TASK_COMM_LEN 16

// Event types
#define EVENT_ASSIGN_CC     1
#define EVENT_INIT_CC       2
#define EVENT_SET_CC        3
#define EVENT_REINIT_CC     4
#define EVENT_CLEANUP_CC    5

struct cc_event {
    u32 pid;
    u32 tgid;
    u64 ts_uptime_us;
    u8 event_type;
    char ca_name[TCP_CA_NAME_MAX];
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_PERF_OUTPUT(cc_events);
BPF_HASH(socket_tracking, struct sock*, struct cc_event);

// Helper to extract connection info from socket
static inline void get_conn_info(struct sock *sk, struct cc_event *event) {
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&event->saddr, sizeof(event->saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&event->daddr, sizeof(event->daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&event->sport, sizeof(event->sport), &inet->inet_sport);
    bpf_probe_read_kernel(&event->dport, sizeof(event->dport), &inet->inet_dport);
}

int trace_assign_cc(struct pt_regs *ctx, struct sock *sk) {
    struct cc_event event = {};
    struct inet_connection_sock *icsk;
    struct tcp_congestion_ops *ca_ops;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
    event.event_type = EVENT_ASSIGN_CC;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    icsk = (struct inet_connection_sock *)sk;
    bpf_probe_read_kernel(&ca_ops, sizeof(ca_ops), &icsk->icsk_ca_ops);
    if (ca_ops) {
        bpf_probe_read_kernel_str(&event.ca_name, sizeof(event.ca_name), &ca_ops->name);
    }
    get_conn_info(sk, &event);
    socket_tracking.update(&sk, &event);
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_init_cc(struct pt_regs *ctx, struct sock *sk) {
    struct cc_event event = {};
    struct inet_connection_sock *icsk;
    struct tcp_congestion_ops *ca_ops;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
    event.event_type = EVENT_INIT_CC;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    icsk = (struct inet_connection_sock *)sk;
    bpf_probe_read_kernel(&ca_ops, sizeof(ca_ops), &icsk->icsk_ca_ops);
    if (ca_ops) {
        bpf_probe_read_kernel_str(&event.ca_name, sizeof(event.ca_name), &ca_ops->name);
    }
    get_conn_info(sk, &event);
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_set_cc(struct pt_regs *ctx, struct sock *sk, const char *name) {
    struct cc_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
    event.event_type = EVENT_SET_CC;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.ca_name, sizeof(event.ca_name), name);
    get_conn_info(sk, &event);
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_reinit_cc(struct pt_regs *ctx, struct sock *sk, struct tcp_congestion_ops *ca) {
    struct cc_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
    event.event_type = EVENT_REINIT_CC;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    if (ca) {
        bpf_probe_read_kernel_str(&event.ca_name, sizeof(event.ca_name), &ca->name);
    }
    get_conn_info(sk, &event);
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_cleanup_cc(struct pt_regs *ctx, struct sock *sk) {
    struct cc_event event = {};
    struct inet_connection_sock *icsk;
    struct tcp_congestion_ops *ca_ops;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
    event.event_type = EVENT_CLEANUP_CC;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    icsk = (struct inet_connection_sock *)sk;
    bpf_probe_read_kernel(&ca_ops, sizeof(ca_ops), &icsk->icsk_ca_ops);
    if (ca_ops) {
        bpf_probe_read_kernel_str(&event.ca_name, sizeof(event.ca_name), &ca_ops->name);
    }
    get_conn_info(sk, &event);
    socket_tracking.delete(&sk);
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
