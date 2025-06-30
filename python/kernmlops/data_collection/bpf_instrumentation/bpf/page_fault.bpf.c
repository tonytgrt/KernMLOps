#include <linux/mm.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

// Define VM_FAULT flags
#define VM_FAULT_MAJOR 0x0200
#define VM_FAULT_ERROR 0x0001

typedef struct page_fault_info {
  u32 pid;
  u64 address;
  u32 flags;
  u64 ts_start;
} page_fault_info_t;

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

BPF_HASH(fault_entry, u32, page_fault_info_t, 10240);
BPF_PERF_OUTPUT(page_fault_events);

// Entry probe - store fault info
int trace_handle_mm_fault_entry(struct pt_regs* ctx, struct vm_area_struct* vma,
                                unsigned long address, unsigned int flags) {
  u32 pid = bpf_get_current_pid_tgid();

  page_fault_info_t info = {};
  info.pid = pid;
  info.address = address;
  info.flags = flags;
  info.ts_start = bpf_ktime_get_ns();

  fault_entry.update(&pid, &info);
  return 0;
}

// Return probe - check if major fault
int trace_handle_mm_fault_return(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  page_fault_info_t* info = fault_entry.lookup(&pid);
  if (!info)
    return 0;

  // Get return value
  unsigned long ret = PT_REGS_RC(ctx);

  // Only process successful faults
  if (ret & VM_FAULT_ERROR) {
    fault_entry.delete(&pid);
    return 0;
  }

  page_fault_event_t event = {};
  event.pid = info->pid;
  event.tgid = bpf_get_current_pid_tgid() >> 32;
  event.ts_uptime_us = info->ts_start / 1000;
  event.address = info->address;
  event.error_code = 0; // Not used in this approach
  event.is_major = (ret & VM_FAULT_MAJOR) ? 1 : 0;
  event.is_write = (info->flags & FAULT_FLAG_WRITE) ? 1 : 0;
  event.is_exec = (info->flags & FAULT_FLAG_INSTRUCTION) ? 1 : 0;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  page_fault_events.perf_submit(ctx, &event, sizeof(event));
  fault_entry.delete(&pid);

  return 0;
}
