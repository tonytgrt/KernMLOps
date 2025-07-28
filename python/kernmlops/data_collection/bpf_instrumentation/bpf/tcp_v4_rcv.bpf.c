#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>

// Branch types for TCP receive processing
#define TCP_BRANCH_ENTRY        0
#define TCP_BRANCH_NOT_FOR_HOST 1
#define TCP_BRANCH_NO_SOCKET    2
#define TCP_BRANCH_TIME_WAIT    3
#define TCP_BRANCH_CHECKSUM_ERR 4
#define TCP_BRANCH_LISTEN       5
#define TCP_BRANCH_SOCKET_BUSY  6
#define TCP_BRANCH_XFRM_DROP    7
#define TCP_BRANCH_NEW_SYN_RECV 8
// New branch types
#define TCP_BRANCH_PKT_TOO_SMALL 9
#define TCP_BRANCH_MIN_TTL_DROP  10
#define TCP_BRANCH_SOCKET_FILTER 11
#define TCP_BRANCH_DO_RCV_CALL   12
#define TCP_BRANCH_MD5_FAIL      13
#define TCP_BRANCH_BACKLOG_ADD   14
#define TCP_BRANCH_REQ_STOLEN    15
#define TCP_BRANCH_LISTEN_DROP   16
#define TCP_BRANCH_RST_SENT      17
#define TCP_BRANCH_ESTABLISHED   18

// Drop reasons (from include/net/dropreason.h)
#define SKB_DROP_REASON_NOT_SPECIFIED 2
#define SKB_DROP_REASON_NO_SOCKET     3
#define SKB_DROP_REASON_PKT_TOO_SMALL 4
#define SKB_DROP_REASON_TCP_CSUM      5
#define SKB_DROP_REASON_SOCKET_FILTER 6
#define SKB_DROP_REASON_XFRM_POLICY   14
#define SKB_DROP_REASON_TCP_MINTTL    70

typedef struct tcp_branch_event {
  u32 pid;
  u32 tgid;
  u64 ts_uptime_us;
  u8 branch_type;
  u8 drop_reason;
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  char comm[TASK_COMM_LEN];
} tcp_branch_event_t;

BPF_PERF_OUTPUT(tcp_branch_events);

// Main entry - track all packets
int trace_tcp_v4_rcv(struct pt_regs* ctx, struct sk_buff* skb) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_ENTRY;
  event.drop_reason = 0;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  // Try to extract packet info from skb
  struct iphdr* ip = NULL;
  struct tcphdr* tcp = NULL;

  // Read IP header
  ip = (struct iphdr*)(skb->head + skb->network_header);
  bpf_probe_read(&event.saddr, sizeof(event.saddr), &ip->saddr);
  bpf_probe_read(&event.daddr, sizeof(event.daddr), &ip->daddr);

  // Read TCP header
  tcp = (struct tcphdr*)(skb->head + skb->transport_header);
  bpf_probe_read(&event.sport, sizeof(event.sport), &tcp->source);
  bpf_probe_read(&event.dport, sizeof(event.dport), &tcp->dest);

  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track "not for host" branch
int trace_not_for_host(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_NOT_FOR_HOST;
  event.drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track "no socket found" branch
int trace_no_socket(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_NO_SOCKET;
  event.drop_reason = SKB_DROP_REASON_NO_SOCKET;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track TIME_WAIT state
int trace_time_wait(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_TIME_WAIT;
  event.drop_reason = 0;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track checksum error
int trace_checksum_error(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_CHECKSUM_ERR;
  event.drop_reason = SKB_DROP_REASON_TCP_CSUM;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track LISTEN state processing
int trace_listen_state(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_LISTEN;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track socket busy/backlog
int trace_socket_busy(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_SOCKET_BUSY;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track XFRM policy drop
int trace_xfrm_policy_drop(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_XFRM_DROP;
  event.drop_reason = SKB_DROP_REASON_XFRM_POLICY;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track NEW_SYN_RECV state
int trace_new_syn_recv(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_NEW_SYN_RECV;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track packet too small
int trace_pkt_too_small(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_PKT_TOO_SMALL;
  event.drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track min TTL drop
int trace_min_ttl_drop(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_MIN_TTL_DROP;
  event.drop_reason = SKB_DROP_REASON_TCP_MINTTL;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track socket filter drop
int trace_socket_filter_drop(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_SOCKET_FILTER;
  event.drop_reason = SKB_DROP_REASON_SOCKET_FILTER;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track tcp_v4_do_rcv call (direct processing)
int trace_do_rcv_call(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_DO_RCV_CALL;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track MD5 hash failure
int trace_md5_fail(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_MD5_FAIL;
  event.drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track backlog add
int trace_backlog_add(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_BACKLOG_ADD;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track request stolen path
int trace_req_stolen(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_REQ_STOLEN;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track listen overflow/drop
int trace_listen_drop(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_LISTEN_DROP;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track RST sent
int trace_rst_sent(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_RST_SENT;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// NEW: Track established socket processing
int trace_established(struct pt_regs* ctx) {
  tcp_branch_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.branch_type = TCP_BRANCH_ESTABLISHED;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  tcp_branch_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}
