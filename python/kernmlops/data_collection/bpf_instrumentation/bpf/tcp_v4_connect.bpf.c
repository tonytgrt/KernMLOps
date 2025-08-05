/* tcp_v4_connect.bpf.c - eBPF program for tracking TCP connection establishment */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>

// Branch types for tcp_v4_connect
#define CONNECT_ENTRY           0
#define CONNECT_INVALID_ADDRLEN 1
#define CONNECT_WRONG_FAMILY    2
#define CONNECT_ROUTE_ERROR     3
#define CONNECT_MULTICAST_BCAST 4
#define CONNECT_NO_SRC_ADDR     5
#define CONNECT_TS_RESET        6
#define CONNECT_REPAIR_MODE     7
#define CONNECT_HASH_ERROR      8
#define CONNECT_FASTOPEN_DEFER  9
#define CONNECT_TCP_CONNECT_ERR 10
#define CONNECT_ENETUNREACH     11
#define CONNECT_NEW_SPORT       12
#define CONNECT_WRITE_SEQ_INIT  13
#define CONNECT_SUCCESS         14
#define CONNECT_SRC_BIND_FAIL   15
#define CONNECT_PORT_EXHAUSTED  16
#define CONNECT_ROUTE_LOOKUP    17
#define CONNECT_PORT_ALLOC      18
#define CONNECT_REGULAR_SYN     19
#define CONNECT_ERROR_PATH      20

// Path types for performance analysis
#define PATH_FAST     0
#define PATH_SLOW     1
#define PATH_ERROR    2
#define PATH_FASTOPEN 3

// Error codes
#define ERR_NONE          0
#define ERR_EINVAL        -22
#define ERR_EAFNOSUPPORT  -97
#define ERR_EADDRINUSE    -98
#define ERR_EADDRNOTAVAIL -99
#define ERR_ENETUNREACH   -101
#define ERR_ENOMEM        -12

typedef struct connect_event {
  u32 pid;
  u32 tgid;
  u64 ts_uptime_us;
  u64 latency_ns;
  u8 branch_type;
  u8 path_type;
  s32 error_code;
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  char comm[TASK_COMM_LEN];
} connect_event_t;

BPF_PERF_OUTPUT(connect_events);
BPF_HASH(connect_start_times, u32, u64);
BPF_HASH(connect_tracking, u32, connect_event_t);

// Statistics tracking
BPF_ARRAY(branch_stats, u64, 32);
BPF_ARRAY(path_stats, u64, 4);
BPF_ARRAY(error_stats, u64, 8);

// Main entry point
int trace_tcp_v4_connect(struct pt_regs* ctx, struct sock* sk, struct sockaddr* uaddr) {
  connect_event_t event = {};
  u32 tid = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();

  // Store start time for latency calculation
  connect_start_times.update(&tid, &ts);

  event.pid = tid;
  event.tgid = tid >> 32;
  event.ts_uptime_us = ts / 1000;
  event.branch_type = CONNECT_ENTRY;
  event.latency_ns = 0;
  event.error_code = ERR_NONE;

  // Try to get destination address
  struct sockaddr_in* sin = (struct sockaddr_in*)uaddr;
  bpf_probe_read(&event.daddr, sizeof(event.daddr), &sin->sin_addr.s_addr);
  bpf_probe_read(&event.dport, sizeof(event.dport), &sin->sin_port);

  // Get source address from socket
  struct inet_sock* inet = (struct inet_sock*)sk;
  bpf_probe_read(&event.saddr, sizeof(event.saddr), &inet->inet_saddr);
  bpf_probe_read(&event.sport, sizeof(event.sport), &inet->inet_sport);

  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  // Store for tracking
  connect_tracking.update(&tid, &event);

  // Submit entry event
  connect_events.perf_submit(ctx, &event, sizeof(event));

  // Update statistics
  u64* count = branch_stats.lookup(&event.branch_type);
  if (count)
    (*count)++;

  return 0;
}

// Invalid address length check (offset 0x4f0)
int trace_invalid_addrlen(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_INVALID_ADDRLEN;
    event->error_code = ERR_EINVAL;
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    u64* err_count = error_stats.lookup_or_init(&(u64){1}, &(u64){0});
    if (err_count)
      (*err_count)++;
  }
  return 0;
}

// Wrong address family (offset 0x4e6)
int trace_wrong_family(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_WRONG_FAMILY;
    event->error_code = ERR_EAFNOSUPPORT;
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    u64* err_count = error_stats.lookup_or_init(&(u64){2}, &(u64){0});
    if (err_count)
      (*err_count)++;
  }
  return 0;
}

// Route lookup (offset 0x17c)
int trace_route_lookup(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_ROUTE_LOOKUP;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;
  }
  return 0;
}

// Route lookup error (offset 0x46c)
int trace_route_error(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_ROUTE_ERROR;
    event->error_code = PT_REGS_RC(ctx);
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    u64* err_count = error_stats.lookup_or_init(&(u64){3}, &(u64){0});
    if (err_count)
      (*err_count)++;
  }
  return 0;
}

// Multicast/broadcast check (offset 0x4fa)
int trace_multicast_bcast(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_MULTICAST_BCAST;
    event->error_code = ERR_ENETUNREACH;
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    u64* err_count = error_stats.lookup_or_init(&(u64){4}, &(u64){0});
    if (err_count)
      (*err_count)++;
  }
  return 0;
}

// No source address branch (offset 0x3fe)
int trace_no_src_addr(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_NO_SRC_ADDR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;
  }
  return 0;
}

// Source binding failure (offset 0x417)
int trace_src_bind_fail(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_SRC_BIND_FAIL;
    event->error_code = PT_REGS_RC(ctx);
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    u64* err_count = error_stats.lookup_or_init(&(u64){5}, &(u64){0});
    if (err_count)
      (*err_count)++;
  }
  return 0;
}

// Port allocation via inet_hash_connect (offset 0x27e)
int trace_port_alloc(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_PORT_ALLOC;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;
  }
  return 0;
}

// inet_hash_connect error (offset 0x283)
int trace_hash_error(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_HASH_ERROR;
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;
  }
  return 0;
}

// Fast open defer (offset 0x3b1)
int trace_fastopen_defer(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_FASTOPEN_DEFER;
    event->path_type = PATH_FASTOPEN;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    u64* path_count = path_stats.lookup_or_init(&event->path_type, &(u64){0});
    if (path_count)
      (*path_count)++;
  }
  return 0;
}

// Regular SYN sending via tcp_connect (offset 0x42d)
int trace_regular_syn(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_REGULAR_SYN;
    event->path_type = PATH_SLOW;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    u64* path_count = path_stats.lookup_or_init(&event->path_type, &(u64){0});
    if (path_count)
      (*path_count)++;
  }
  return 0;
}

// tcp_connect error (offset 0x43a)
int trace_tcp_connect_err(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_TCP_CONNECT_ERR;
    event->error_code = PT_REGS_RC(ctx);
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;
  }
  return 0;
}

// ENETUNREACH specific handling (offset 0x48d)
int trace_enetunreach(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_ENETUNREACH;
    event->error_code = ERR_ENETUNREACH;
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;
  }
  return 0;
}

// New source port selection (offset 0x337)
int trace_new_sport(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_NEW_SPORT;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;
  }
  return 0;
}

// Write sequence initialization (offset 0x372)
int trace_write_seq_init(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_WRITE_SEQ_INIT;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;
  }
  return 0;
}

// Error path - failure label (offset 0x289)
int trace_error_path(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
    }

    event->ts_uptime_us = ts / 1000;
    event->branch_type = CONNECT_ERROR_PATH;
    event->path_type = PATH_ERROR;

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    u64* path_count = path_stats.lookup_or_init(&event->path_type, &(u64){0});
    if (path_count)
      (*path_count)++;
  }
  return 0;
}

// Return probe - capture final result and cleanup
int trace_tcp_v4_connect_return(struct pt_regs* ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  connect_event_t* event = connect_tracking.lookup(&tid);

  if (event) {
    u64 ts = bpf_ktime_get_ns();
    u64* start = connect_start_times.lookup(&tid);
    if (start) {
      event->latency_ns = ts - *start;
      connect_start_times.delete(&tid);
    }

    event->ts_uptime_us = ts / 1000;
    event->error_code = PT_REGS_RC(ctx);

    if (event->error_code == 0) {
      event->branch_type = CONNECT_SUCCESS;
      event->path_type = PATH_FAST;

      u64* path_count = path_stats.lookup_or_init(&(u64){PATH_FAST}, &(u64){0});
      if (path_count)
        (*path_count)++;
    } else {
      // Already set by specific error handlers
      if (event->path_type == 0) {
        event->path_type = PATH_ERROR;
      }
    }

    connect_events.perf_submit(ctx, event, sizeof(*event));

    u64* count = branch_stats.lookup(&event->branch_type);
    if (count)
      (*count)++;

    connect_tracking.delete(&tid);
  }

  return 0;
}
