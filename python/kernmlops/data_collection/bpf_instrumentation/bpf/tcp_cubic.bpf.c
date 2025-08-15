#include <linux/bpf.h>
#include <linux/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <uapi/linux/ptrace.h>

// Note: icsk->icsk_ca_state is a bit-field and cannot be directly accessed
// with bpf_probe_read_kernel due to inability to take address of bit-fields.
// CA state tracking has been removed from this implementation.

// CUBIC state structure (based on tcp_cubic.c)
struct bictcp {
  u32 cnt;
  u32 last_max_cwnd;
  u32 last_cwnd;
  u32 last_time;
  u32 bic_origin_point;
  u32 bic_K;
  u32 delay_min;
  u32 epoch_start;
  u32 ack_cnt;
  u32 tcp_cwnd;
  u16 unused;
  u8 sample_cnt;
  u8 found;
  u32 round_start;
  u32 end_seq;
  u32 last_ack;
  u32 curr_rtt;
};

// Event types for different functions
#define EVENT_CONG_AVOID   1
#define EVENT_INIT         2
#define EVENT_SSTHRESH     3
#define EVENT_STATE_CHANGE 4
#define EVENT_CWND_EVENT   5
#define EVENT_ACKED        6
#define EVENT_HYSTART      7

struct cubic_event {
  u32 pid;
  u32 tgid;
  u64 ts_uptime_us;
  u8 event_type;
  char comm[16];

  // Connection info
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;

  // TCP state
  u32 cwnd;
  u32 ssthresh;
  u32 packets_out;
  u32 sacked_out;
  u32 lost_out;
  u32 retrans_out;
  u32 rtt_us;
  u32 min_rtt_us;
  u32 mss_cache;

  // CUBIC state
  u32 cnt;
  u32 last_max_cwnd;
  u32 last_cwnd;
  u32 last_time;
  u32 bic_origin_point;
  u32 bic_K;
  u32 delay_min;
  u32 epoch_start;
  u32 ack_cnt;
  u32 tcp_cwnd;
  u8 found;
  u32 curr_rtt;

  // Additional metrics
  u32 acked;
  u8 in_slow_start;
  u8 is_tcp_friendly;
};

BPF_PERF_OUTPUT(cubic_events);
BPF_HASH(socket_tracking, struct sock*, struct cubic_event);

// Helper to extract connection info
static inline void get_conn_info(struct sock* sk, struct cubic_event* event) {
  struct inet_sock* inet = (struct inet_sock*)sk;
  bpf_probe_read_kernel(&event->saddr, sizeof(u32), &inet->inet_saddr);
  bpf_probe_read_kernel(&event->daddr, sizeof(u32), &inet->inet_daddr);
  bpf_probe_read_kernel(&event->sport, sizeof(u16), &inet->inet_sport);
  bpf_probe_read_kernel(&event->dport, sizeof(u16), &inet->inet_dport);
}

// Helper to extract TCP state
static inline void get_tcp_state(struct sock* sk, struct cubic_event* event) {
  struct tcp_sock* tp = (struct tcp_sock*)sk;

  bpf_probe_read_kernel(&event->cwnd, sizeof(u32), &tp->snd_cwnd);
  bpf_probe_read_kernel(&event->ssthresh, sizeof(u32), &tp->snd_ssthresh);
  bpf_probe_read_kernel(&event->packets_out, sizeof(u32), &tp->packets_out);
  bpf_probe_read_kernel(&event->sacked_out, sizeof(u32), &tp->sacked_out);
  bpf_probe_read_kernel(&event->lost_out, sizeof(u32), &tp->lost_out);
  bpf_probe_read_kernel(&event->retrans_out, sizeof(u32), &tp->retrans_out);
  bpf_probe_read_kernel(&event->rtt_us, sizeof(u32), &tp->srtt_us);
  bpf_probe_read_kernel(&event->min_rtt_us, sizeof(u32), &tp->rtt_min);
  bpf_probe_read_kernel(&event->mss_cache, sizeof(u32), &tp->mss_cache);
}

// Helper to extract CUBIC state
static inline void get_cubic_state(struct sock* sk, struct cubic_event* event) {
  struct inet_connection_sock* icsk = (struct inet_connection_sock*)sk;
  struct bictcp* ca = (struct bictcp*)icsk->icsk_ca_priv;

  if (ca) {
    bpf_probe_read_kernel(&event->cnt, sizeof(u32), &ca->cnt);
    bpf_probe_read_kernel(&event->last_max_cwnd, sizeof(u32), &ca->last_max_cwnd);
    bpf_probe_read_kernel(&event->last_cwnd, sizeof(u32), &ca->last_cwnd);
    bpf_probe_read_kernel(&event->last_time, sizeof(u32), &ca->last_time);
    bpf_probe_read_kernel(&event->bic_origin_point, sizeof(u32), &ca->bic_origin_point);
    bpf_probe_read_kernel(&event->bic_K, sizeof(u32), &ca->bic_K);
    bpf_probe_read_kernel(&event->delay_min, sizeof(u32), &ca->delay_min);
    bpf_probe_read_kernel(&event->epoch_start, sizeof(u32), &ca->epoch_start);
    bpf_probe_read_kernel(&event->ack_cnt, sizeof(u32), &ca->ack_cnt);
    bpf_probe_read_kernel(&event->tcp_cwnd, sizeof(u32), &ca->tcp_cwnd);
    bpf_probe_read_kernel(&event->found, sizeof(u8), &ca->found);
    bpf_probe_read_kernel(&event->curr_rtt, sizeof(u32), &ca->curr_rtt);
  }
}

// Trace cubictcp_cong_avoid
int trace_cong_avoid(struct pt_regs* ctx, struct sock* sk, u32 ack, u32 acked) {
  struct cubic_event event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();

  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = EVENT_CONG_AVOID;
  event.acked = acked;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  get_conn_info(sk, &event);
  get_tcp_state(sk, &event);
  get_cubic_state(sk, &event);

  // Determine if in slow start
  event.in_slow_start = (event.cwnd < event.ssthresh) ? 1 : 0;
  event.is_tcp_friendly = (event.tcp_cwnd > event.cwnd) ? 1 : 0;

  // Update tracking
  socket_tracking.update(&sk, &event);
  cubic_events.perf_submit(ctx, &event, sizeof(event));

  return 0;
}

// Trace cubictcp_init
int trace_init(struct pt_regs* ctx, struct sock* sk) {
  struct cubic_event event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();

  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = EVENT_INIT;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  get_conn_info(sk, &event);
  get_tcp_state(sk, &event);
  get_cubic_state(sk, &event);

  socket_tracking.update(&sk, &event);
  cubic_events.perf_submit(ctx, &event, sizeof(event));

  return 0;
}

// Trace cubictcp_recalc_ssthresh (loss detection)
int trace_recalc_ssthresh(struct pt_regs* ctx, struct sock* sk) {
  struct cubic_event event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();

  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = EVENT_SSTHRESH;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  get_conn_info(sk, &event);
  get_tcp_state(sk, &event);
  get_cubic_state(sk, &event);

  cubic_events.perf_submit(ctx, &event, sizeof(event));

  return 0;
}

// Trace cubictcp_state
int trace_state(struct pt_regs* ctx, struct sock* sk, u8 new_state) {
  struct cubic_event event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();

  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = EVENT_STATE_CHANGE;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  get_conn_info(sk, &event);
  get_tcp_state(sk, &event);
  get_cubic_state(sk, &event);

  cubic_events.perf_submit(ctx, &event, sizeof(event));

  return 0;
}

// Trace cubictcp_cwnd_event
int trace_cwnd_event(struct pt_regs* ctx, struct sock* sk, int event) {
  struct cubic_event ev = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();

  ev.pid = pid_tgid;
  ev.tgid = pid_tgid >> 32;
  ev.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  ev.event_type = EVENT_CWND_EVENT;

  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
  get_conn_info(sk, &ev);
  get_tcp_state(sk, &ev);
  get_cubic_state(sk, &ev);

  cubic_events.perf_submit(ctx, &ev, sizeof(ev));

  return 0;
}

// Trace hystart_update for HyStart detection
int trace_hystart_update(struct pt_regs* ctx, struct sock* sk, u32 delay) {
  struct cubic_event event = {};
  u64 pid_tgid = bpf_get_current_pid_tgid();

  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.event_type = EVENT_HYSTART;
  event.curr_rtt = delay;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  get_conn_info(sk, &event);
  get_tcp_state(sk, &event);
  get_cubic_state(sk, &event);

  cubic_events.perf_submit(ctx, &event, sizeof(event));

  return 0;
}
