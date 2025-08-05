"""TCP v4 connect hook for tracking connection establishment branches and performance"""

import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable

# Branch type constants
CONNECT_ENTRY = 0
CONNECT_INVALID_ADDRLEN = 1
CONNECT_WRONG_FAMILY = 2
CONNECT_ROUTE_ERROR = 3
CONNECT_MULTICAST_BCAST = 4
CONNECT_NO_SRC_ADDR = 5
CONNECT_TS_RESET = 6
CONNECT_REPAIR_MODE = 7
CONNECT_HASH_ERROR = 8
CONNECT_FASTOPEN_DEFER = 9
CONNECT_TCP_CONNECT_ERR = 10
CONNECT_ENETUNREACH = 11
CONNECT_NEW_SPORT = 12
CONNECT_WRITE_SEQ_INIT = 13
CONNECT_SUCCESS = 14
CONNECT_SRC_BIND_FAIL = 15
CONNECT_PORT_EXHAUSTED = 16
CONNECT_ROUTE_LOOKUP = 17
CONNECT_PORT_ALLOC = 18
CONNECT_REGULAR_SYN = 19
CONNECT_ERROR_PATH = 20

BRANCH_NAMES = {
    CONNECT_ENTRY: "entry",
    CONNECT_INVALID_ADDRLEN: "invalid_addrlen",
    CONNECT_WRONG_FAMILY: "wrong_family",
    CONNECT_ROUTE_ERROR: "route_error",
    CONNECT_MULTICAST_BCAST: "multicast_bcast",
    CONNECT_NO_SRC_ADDR: "no_src_addr",
    CONNECT_TS_RESET: "ts_reset",
    CONNECT_REPAIR_MODE: "repair_mode",
    CONNECT_HASH_ERROR: "hash_error",
    CONNECT_FASTOPEN_DEFER: "fastopen_defer",
    CONNECT_TCP_CONNECT_ERR: "tcp_connect_err",
    CONNECT_ENETUNREACH: "enetunreach",
    CONNECT_NEW_SPORT: "new_sport",
    CONNECT_WRITE_SEQ_INIT: "write_seq_init",
    CONNECT_SUCCESS: "success",
    CONNECT_SRC_BIND_FAIL: "src_bind_fail",
    CONNECT_PORT_EXHAUSTED: "port_exhausted",
    CONNECT_ROUTE_LOOKUP: "route_lookup",
    CONNECT_PORT_ALLOC: "port_alloc",
    CONNECT_REGULAR_SYN: "regular_syn",
    CONNECT_ERROR_PATH: "error_path",
}

# Path types
PATH_FAST = 0
PATH_SLOW = 1
PATH_ERROR = 2
PATH_FASTOPEN = 3

PATH_NAMES = {
    PATH_FAST: "fast",
    PATH_SLOW: "slow",
    PATH_ERROR: "error",
    PATH_FASTOPEN: "fastopen",
}

# Error codes
ERROR_NAMES = {
    0: "none",
    -12: "ENOMEM",
    -22: "EINVAL",
    -97: "EAFNOSUPPORT",
    -98: "EADDRINUSE",
    -99: "EADDRNOTAVAIL",
    -101: "ENETUNREACH",
}


@dataclass(frozen=True)
class TcpConnectEvent:
    cpu: int
    pid: int
    tgid: int
    ts_uptime_us: int
    latency_ns: int
    branch_type: int
    branch_name: str
    path_type: int
    path_name: str
    error_code: int
    error_name: str
    saddr: str
    daddr: str
    sport: int
    dport: int
    comm: str


class TcpV4ConnectBPFHook(BPFProgram):

    @classmethod
    def name(cls) -> str:
        return "tcp_v4_connect"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/tcp_v4_connect.bpf.c", "r").read()
        self.bpf_text = bpf_text
        self.connect_events = list[TcpConnectEvent]()

        # Branch offsets for kernel-specific tracking
        self.branch_offsets = {
            "trace_invalid_addrlen": 0x4f0,
            "trace_wrong_family": 0x4e6,
            "trace_route_lookup": 0x17c,
            "trace_route_error": 0x46c,
            "trace_multicast_bcast": 0x4fa,
            "trace_no_src_addr": 0x3fe,
            "trace_src_bind_fail": 0x417,
            "trace_port_alloc": 0x27e,
            "trace_hash_error": 0x283,
            "trace_fastopen_defer": 0x3b1,
            "trace_regular_syn": 0x42d,
            "trace_tcp_connect_err": 0x43a,
            "trace_enetunreach": 0x48d,
            "trace_new_sport": 0x337,
            "trace_write_seq_init": 0x372,
            "trace_error_path": 0x289,
        }

    def load(self, collection_id: str):
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)

        # Attach main entry and return probes
        self.bpf.attach_kprobe(event=b"tcp_v4_connect", fn_name=b"trace_tcp_v4_connect")
        self.bpf.attach_kretprobe(event=b"tcp_v4_connect", fn_name=b"trace_tcp_v4_connect_return")

        # Attach offset-based probes for branches
        attached_count = 0
        failed_count = 0

        for fn_name, offset in self.branch_offsets.items():
            try:
                self.bpf.attach_kprobe(
                    event=b"tcp_v4_connect",
                    fn_name=fn_name.encode(),
                    event_off=offset
                )
                attached_count += 1
            except Exception:
                # Kernel version differences may cause some offsets to fail
                failed_count += 1

        if failed_count > 0:
            print(f"Warning: {failed_count} offset probes failed to attach (kernel version mismatch)")

        # Open perf buffer
        self.bpf["connect_events"].open_perf_buffer(
            self._connect_event_handler, page_cnt=64
        )

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def _connect_event_handler(self, cpu, data, size):
        event = self.bpf["connect_events"].event(data)

        # Convert addresses to readable format
        saddr = socket.inet_ntoa(struct.pack('I', event.saddr)) if event.saddr else "0.0.0.0"
        daddr = socket.inet_ntoa(struct.pack('I', event.daddr)) if event.daddr else "0.0.0.0"
        sport = socket.ntohs(event.sport) if event.sport else 0
        dport = socket.ntohs(event.dport) if event.dport else 0

        self.connect_events.append(
            TcpConnectEvent(
                cpu=cpu,
                pid=event.pid,
                tgid=event.tgid,
                ts_uptime_us=event.ts_uptime_us,
                latency_ns=event.latency_ns,
                branch_type=event.branch_type,
                branch_name=BRANCH_NAMES.get(event.branch_type, f"unknown_{event.branch_type}"),
                path_type=event.path_type,
                path_name=PATH_NAMES.get(event.path_type, f"unknown_path_{event.path_type}"),
                error_code=event.error_code,
                error_name=ERROR_NAMES.get(event.error_code, f"err_{event.error_code}"),
                saddr=saddr,
                daddr=daddr,
                sport=sport,
                dport=dport,
                comm=event.comm.decode('utf-8', 'ignore'),
            )
        )

    def data(self) -> list[CollectionTable]:
        from data_schema.tcp_v4_connect import TcpConnectStatsTable, TcpV4ConnectTable

        # Main events table
        events_df = pl.DataFrame(self.connect_events)

        # Calculate statistics
        if len(self.connect_events) > 0:
            branch_stats = self.bpf["branch_stats"]
            path_stats = self.bpf["path_stats"]
            error_stats = self.bpf["error_stats"]

            # Collect branch statistics
            branch_counts = {}
            for i in range(32):
                count = branch_stats[i].value
                if count > 0:
                    branch_name = BRANCH_NAMES.get(i, f"unknown_{i}")
                    branch_counts[branch_name] = count

            # Collect path statistics
            path_counts = {}
            for i in range(4):
                count = path_stats[i].value
                if count > 0:
                    path_name = PATH_NAMES.get(i, f"unknown_path_{i}")
                    path_counts[path_name] = count

            # Collect error statistics
            error_counts = {}
            for i in range(8):
                count = error_stats[i].value
                if count > 0:
                    error_counts[f"error_type_{i}"] = count

            stats_df = pl.DataFrame({
                "collection_id": [self.collection_id],
                "total_connections": [len(self.connect_events)],
                "successful_connections": [branch_counts.get("success", 0)],
                "failed_connections": [sum(1 for e in self.connect_events if e.error_code != 0)],
                "fast_path_count": [path_counts.get("fast", 0)],
                "slow_path_count": [path_counts.get("slow", 0)],
                "error_path_count": [path_counts.get("error", 0)],
                "fastopen_count": [path_counts.get("fastopen", 0)],
                "avg_latency_ns": [sum(e.latency_ns for e in self.connect_events) / len(self.connect_events) if self.connect_events else 0],
            })

            return [
                TcpV4ConnectTable.from_df_id(events_df, collection_id=self.collection_id),
                TcpConnectStatsTable.from_df_id(stats_df, collection_id=self.collection_id),
            ]
        else:
            return []

    def clear(self):
        self.connect_events.clear()

    def pop_data(self) -> list[CollectionTable]:
        tables = self.data()
        self.clear()
        return tables
