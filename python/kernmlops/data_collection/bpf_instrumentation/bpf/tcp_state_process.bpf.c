#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <uapi/linux/ptrace.h>

// Event types
#define STATE_TRANSITION 0
#define STATE_ERROR      1
#define STATE_PROCESSING 2

// Structure to hold state transition information
typedef struct tcp_state_event {
  u32 pid;
  u32 tgid;
  u64 ts_uptime_us;
  u8 old_state;
  u8 new_state;
  u8 event_type;
  u8 event_subtype; // For specific events like challenge ACK, reset, etc.
  char comm[TASK_COMM_LEN];
} tcp_state_event_t;

// Structure for statistics (stored in hash map)
struct tcp_state_stats {
  u64 total_calls;
  u64 listen_state;
  u64 syn_sent_state;
  u64 syn_recv_to_established;
  u64 fin_wait1_to_fin_wait2;
  u64 to_time_wait;
  u64 to_last_ack;
  u64 challenge_acks;
  u64 resets;
  u64 fast_open_checks;
  u64 ack_processing;
  u64 data_queued;
  u64 abort_on_data;
};

// Maps
BPF_HASH(stats_map, u32, struct tcp_state_stats);
BPF_PERF_OUTPUT(tcp_state_events);
BPF_HASH(state_distribution, u8, u64);

// Event subtypes
#define SUBTYPE_NONE          0
#define SUBTYPE_CHALLENGE_ACK 1
#define SUBTYPE_RESET         2
#define SUBTYPE_FAST_OPEN     3
#define SUBTYPE_ACK_PROCESS   4
#define SUBTYPE_DATA_QUEUE    5
#define SUBTYPE_ABORT_DATA    6

// Helper to get socket state
static u8 get_sk_state(struct sock* sk) {
  u8 state = 0;
  bpf_probe_read(&state, sizeof(state), &sk->sk_state);
  return state;
}

// Main entry - track overall statistics
int trace_tcp_rcv_state_process(struct pt_regs* ctx, struct sock* sk) {
  u32 key = 0;
  struct tcp_state_stats *stats, zero_stats = {};

  stats = stats_map.lookup_or_try_init(&key, &zero_stats);
  if (stats) {
    __sync_fetch_and_add(&stats->total_calls, 1);
  }

  // Track state distribution
  u8 state = get_sk_state(sk);
  u64* count = state_distribution.lookup(&state);
  if (count) {
    __sync_fetch_and_add(count, 1);
  } else {
    u64 init_count = 1;
    state_distribution.update(&state, &init_count);
  }

  return 0;
}

// Track LISTEN state processing
int trace_listen_state(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->listen_state, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.old_state = TCP_LISTEN;
  event.new_state = TCP_LISTEN;
  event.event_type = STATE_PROCESSING;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track SYN_SENT state processing
int trace_syn_sent_state(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->syn_sent_state, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.old_state = TCP_SYN_SENT;
  event.new_state = TCP_SYN_SENT;
  event.event_type = STATE_PROCESSING;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track SYN_RECV to ESTABLISHED transition
int trace_syn_recv_to_established(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->syn_recv_to_established, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.old_state = TCP_SYN_RECV;
  event.new_state = TCP_ESTABLISHED;
  event.event_type = STATE_TRANSITION;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track FIN_WAIT1 to FIN_WAIT2 transition
int trace_fin_wait1_to_fin_wait2(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->fin_wait1_to_fin_wait2, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.old_state = TCP_FIN_WAIT1;
  event.new_state = TCP_FIN_WAIT2;
  event.event_type = STATE_TRANSITION;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track transition to TIME_WAIT
int trace_to_time_wait(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->to_time_wait, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.new_state = TCP_TIME_WAIT;
  event.event_type = STATE_TRANSITION;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track LAST_ACK processing
int trace_last_ack(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->to_last_ack, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.old_state = TCP_LAST_ACK;
  event.new_state = TCP_LAST_ACK;
  event.event_type = STATE_PROCESSING;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track challenge ACK sending
int trace_challenge_ack(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->challenge_acks, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = STATE_ERROR;
  event.event_subtype = SUBTYPE_CHALLENGE_ACK;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track connection resets
int trace_reset(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->resets, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = STATE_ERROR;
  event.event_subtype = SUBTYPE_RESET;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track Fast Open handling
int trace_fast_open(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->fast_open_checks, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = STATE_PROCESSING;
  event.event_subtype = SUBTYPE_FAST_OPEN;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track ACK processing
int trace_ack_processing(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->ack_processing, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = STATE_PROCESSING;
  event.event_subtype = SUBTYPE_ACK_PROCESS;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track data queuing
int trace_data_queue(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->data_queued, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = STATE_PROCESSING;
  event.event_subtype = SUBTYPE_DATA_QUEUE;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track abort on data
int trace_abort_on_data(struct pt_regs* ctx) {
  u32 key = 0;
  struct tcp_state_stats* stats = stats_map.lookup(&key);
  if (stats) {
    __sync_fetch_and_add(&stats->abort_on_data, 1);
  }

  tcp_state_event_t event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = STATE_ERROR;
  event.event_subtype = SUBTYPE_ABORT_DATA;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  tcp_state_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}
