#include <linux/mm.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

typedef struct page_fault_event {
  u32 pid;
  u32 tgid;
  u64 ts_uptime_us;
  u64 address;
  u32 error_code;
  u8 is_major;
  u8 is_write;
  u8 is_exec;
  char comm[TASK_COMM_LEN];
} page_fault_event_t;

BPF_PERF_OUTPUT(page_fault_events);

// Track page faults via the handle_mm_fault function
int kprobe__handle_mm_fault(struct pt_regs* ctx, struct vm_area_struct* vma, unsigned long address,
                            unsigned int flags) {
  page_fault_event_t event = {};

  u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid;
  event.tgid = pid_tgid >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.address = address;

  // Decode fault flags
  event.is_write = (flags & FAULT_FLAG_WRITE) ? 1 : 0;
  event.is_exec = (flags & FAULT_FLAG_INSTRUCTION) ? 1 : 0;

  // Get process name
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  page_fault_events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

// Track major faults (require disk I/O)
TRACEPOINT_PROBE(exceptions, page_fault_kernel) {
  page_fault_event_t event = {};

  event.pid = bpf_get_current_pid_tgid();
  event.tgid = bpf_get_current_pid_tgid() >> 32;
  event.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  event.address = args->address;
  event.error_code = args->error_code;

  // Check if it's a major fault (page not present)
  event.is_major = (args->error_code & 0x1) ? 0 : 1;
  event.is_write = (args->error_code & 0x2) ? 1 : 0;
  event.is_exec = (args->error_code & 0x10) ? 1 : 0;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  page_fault_events.perf_submit(args, &event, sizeof(event));
  return 0;
}
