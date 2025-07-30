import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable

# Branch type constants - expanded set
TCP_BRANCH_ENTRY = 0
TCP_BRANCH_NOT_FOR_HOST = 1
TCP_BRANCH_NO_SOCKET = 2
TCP_BRANCH_TIME_WAIT = 3
TCP_BRANCH_CHECKSUM_ERR = 4
TCP_BRANCH_LISTEN = 5
TCP_BRANCH_SOCKET_BUSY = 6
TCP_BRANCH_XFRM_DROP = 7
TCP_BRANCH_NEW_SYN_RECV = 8
# New branch types
TCP_BRANCH_PKT_TOO_SMALL = 9
TCP_BRANCH_MIN_TTL_DROP = 10
TCP_BRANCH_SOCKET_FILTER = 11
TCP_BRANCH_DO_RCV_CALL = 12
TCP_BRANCH_MD5_FAIL = 13
TCP_BRANCH_BACKLOG_ADD = 14
TCP_BRANCH_REQ_STOLEN = 15
TCP_BRANCH_LISTEN_DROP = 16
TCP_BRANCH_RST_SENT = 17
TCP_BRANCH_ESTABLISHED = 18

BRANCH_NAMES = {
    TCP_BRANCH_ENTRY: "entry",
    TCP_BRANCH_NOT_FOR_HOST: "not_for_host",
    TCP_BRANCH_NO_SOCKET: "no_socket",
    TCP_BRANCH_TIME_WAIT: "time_wait",
    TCP_BRANCH_CHECKSUM_ERR: "checksum_error",
    TCP_BRANCH_LISTEN: "listen_state",
    TCP_BRANCH_SOCKET_BUSY: "socket_busy",
    TCP_BRANCH_XFRM_DROP: "xfrm_policy_drop",
    TCP_BRANCH_NEW_SYN_RECV: "new_syn_recv",
    # New branches
    TCP_BRANCH_PKT_TOO_SMALL: "pkt_too_small",
    TCP_BRANCH_MIN_TTL_DROP: "min_ttl_drop",
    TCP_BRANCH_SOCKET_FILTER: "socket_filter_drop",
    TCP_BRANCH_DO_RCV_CALL: "do_rcv_direct",
    TCP_BRANCH_MD5_FAIL: "md5_hash_fail",
    TCP_BRANCH_BACKLOG_ADD: "backlog_add",
    TCP_BRANCH_REQ_STOLEN: "req_stolen",
    TCP_BRANCH_LISTEN_DROP: "listen_overflow",
    TCP_BRANCH_RST_SENT: "rst_sent",
    TCP_BRANCH_ESTABLISHED: "established_proc"
}

DROP_REASON_NAMES = {
    0: "none",
    2: "not_specified",
    3: "no_socket",
    4: "pkt_too_small",
    5: "tcp_csum",
    6: "socket_filter",
    14: "xfrm_policy",
    70: "tcp_minttl"
}


@dataclass(frozen=True)
class TcpBranchData:
    cpu: int
    pid: int
    tgid: int
    ts_uptime_us: int
    branch_type: int
    branch_name: str
    drop_reason: int
    drop_reason_name: str
    saddr: str
    daddr: str
    sport: int
    dport: int
    comm: str


class TcpV4RcvBPFHook(BPFProgram):

    @classmethod
    def name(cls) -> str:
        return "tcp_v4_rcv"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/tcp_v4_rcv.bpf.c", "r").read()
        self.bpf_text = bpf_text
        self.tcp_branch_data = list[TcpBranchData]()

        # Kernel-specific offsets for branch points
        # Original offsets
        self.branch_offsets = {
            "trace_not_for_host": 0x73,
            "trace_no_socket": 0x722,
            "trace_time_wait": 0x279,
            "trace_checksum_error": 0x2e8,
            "trace_listen_state": 0xedf,
            "trace_socket_busy": 0xec2,
            "trace_xfrm_policy_drop": 0x8e5,
            "trace_new_syn_recv": 0x5db,
            "trace_pkt_too_small": 0x632,     # Header too small check
            "trace_min_ttl_drop": 0xc93,      # Min TTL drop location
            "trace_socket_filter_drop": 0x9e4, # Socket filter drop
            "trace_do_rcv_call": 0x9b5,       # tcp_v4_do_rcv call
            "trace_md5_fail": 0x60e,           # MD5 hash check failure
            "trace_backlog_add": 0xbcc,        # tcp_add_backlog call
            "trace_req_stolen": 0xa0a,         # Request stolen path
            "trace_listen_drop": 0xbfe,        # Listen state drop
            "trace_rst_sent": 0x76f,           # tcp_v4_send_reset call
            "trace_established": 0xc6e         # Established socket path
        }

    def load(self, collection_id: str):
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)

        # Attach main entry probe
        self.bpf.attach_kprobe(event=b"tcp_v4_rcv", fn_name=b"trace_tcp_v4_rcv")
        print("✓ Attached main entry probe")

        # Attach offset-based probes
        attached_count = 0
        failed_count = 0

        for fn_name, offset in self.branch_offsets.items():
            try:
                self.bpf.attach_kprobe(
                    event=b"tcp_v4_rcv",
                    fn_name=fn_name.encode(),
                    event_off=offset
                )
                attached_count += 1
            except Exception as e:
                print(f"Warning: Failed to attach {fn_name} at offset 0x{offset:x}: {e}")
                failed_count += 1

        print(f"✓ Successfully attached {attached_count} offset probes")
        if failed_count > 0:
            print(f"⚠ Failed to attach {failed_count} offset probes (kernel version mismatch)")

        # Open perf buffer
        self.bpf["tcp_branch_events"].open_perf_buffer(
            self._tcp_branch_handler, page_cnt=64
        )

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def _int_to_ip(self, addr):
        """Convert integer IP to string format"""
        return socket.inet_ntoa(struct.pack("!I", addr))

    def _tcp_branch_handler(self, cpu, data, size):
        event = self.bpf["tcp_branch_events"].event(data)

        # Convert IPs and ports to proper format
        saddr = self._int_to_ip(event.saddr) if event.saddr else "0.0.0.0"
        daddr = self._int_to_ip(event.daddr) if event.daddr else "0.0.0.0"
        sport = socket.ntohs(event.sport) if event.sport else 0
        dport = socket.ntohs(event.dport) if event.dport else 0

        self.tcp_branch_data.append(
            TcpBranchData(
                cpu=cpu,
                pid=event.pid,
                tgid=event.tgid,
                ts_uptime_us=event.ts_uptime_us,
                branch_type=event.branch_type,
                branch_name=BRANCH_NAMES.get(event.branch_type, "unknown"),
                drop_reason=event.drop_reason,
                drop_reason_name=DROP_REASON_NAMES.get(event.drop_reason, "unknown"),
                saddr=saddr,
                daddr=daddr,
                sport=sport,
                dport=dport,
                comm=event.comm.decode('utf-8', 'replace')
            )
        )

    def data(self) -> list[CollectionTable]:
        from data_schema.tcp_v4_rcv import TcpV4RcvTable
        if len(self.tcp_branch_data) == 0:
            return []
        return [
            TcpV4RcvTable.from_df_id(
                pl.DataFrame(self.tcp_branch_data),
                collection_id=self.collection_id
            )
        ]

    def clear(self):
        self.tcp_branch_data.clear()

    def pop_data(self) -> list[CollectionTable]:
        tables = self.data()
        self.clear()
        return tables

    def get_statistics(self) -> dict:
        """Get current statistics for monitoring"""
        if not self.tcp_branch_data:
            return {}

        df = pl.DataFrame(self.tcp_branch_data)

        # Branch distribution
        branch_stats = df.group_by("branch_name").count().sort("count", descending=True)

        # Drop statistics
        drops = df.filter(pl.col("drop_reason") > 0)
        drop_stats = drops.group_by("drop_reason_name").count() if len(drops) > 0 else None

        # Process statistics
        process_stats = df.group_by("comm").count().sort("count", descending=True).head(10)

        return {
            "total_events": len(df),
            "branch_distribution": branch_stats,
            "drop_statistics": drop_stats,
            "top_processes": process_stats,
            "unique_connections": df.select(["saddr", "daddr", "sport", "dport"]).unique().height
        }
