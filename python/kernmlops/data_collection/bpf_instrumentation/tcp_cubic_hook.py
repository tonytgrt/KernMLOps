import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable

# Event type mappings
EVENT_TYPES = {
    1: "CONG_AVOID",
    2: "INIT",
    3: "SSTHRESH",
    4: "STATE_CHANGE",
    5: "CWND_EVENT",
    6: "ACKED",
    7: "HYSTART",
}


@dataclass(frozen=True)
class TcpCubicEvent:
    cpu: int
    pid: int
    tgid: int
    ts_uptime_us: int
    event_type: int
    event_type_name: str
    comm: str

    # Connection info
    saddr: str
    daddr: str
    sport: int
    dport: int

    # TCP state
    cwnd: int
    ssthresh: int
    packets_out: int
    sacked_out: int
    lost_out: int
    retrans_out: int
    rtt_us: int
    min_rtt_us: int
    mss_cache: int

    # CUBIC state
    cnt: int
    last_max_cwnd: int
    last_cwnd: int
    last_time: int
    bic_origin_point: int
    bic_K: int
    delay_min: int
    epoch_start: int
    ack_cnt: int
    tcp_cwnd: int
    found: int
    curr_rtt: int

    # Additional metrics
    acked: int
    in_slow_start: int
    is_tcp_friendly: int


class TcpCubicBPFHook(BPFProgram):

    @classmethod
    def name(cls) -> str:
        return "tcp_cubic"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/tcp_cubic.bpf.c", "r").read()
        self.bpf_text = bpf_text
        self.events = list[TcpCubicEvent]()
        self.cubic_functions_available = []

    def load(self, collection_id: str):
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)

        # Try to attach to all available CUBIC functions
        cubic_functions = [
            ("cubictcp_cong_avoid", "trace_cong_avoid"),
            ("cubictcp_init", "trace_init"),
            ("cubictcp_recalc_ssthresh", "trace_recalc_ssthresh"),
            ("cubictcp_state", "trace_state"),
            ("cubictcp_cwnd_event", "trace_cwnd_event"),
            ("cubictcp_acked", "trace_acked"),
            ("hystart_update", "trace_hystart_update"),
        ]

        # Also try generic TCP CUBIC function names (may vary by kernel)
        alternate_names = [
            ("tcp_cubic_cong_avoid", "trace_cong_avoid"),
            ("bictcp_cong_avoid", "trace_cong_avoid"),
        ]

        for kernel_func, bpf_func in cubic_functions + alternate_names:
            try:
                self.bpf.attach_kprobe(event=kernel_func.encode(), fn_name=bpf_func.encode())
                self.cubic_functions_available.append(kernel_func)
            except Exception:
                # Function may not exist in this kernel version
                pass

        if not self.cubic_functions_available:
            # Try to at least attach to generic TCP congestion control points
            try:
                self.bpf.attach_kprobe(event=b"tcp_cong_avoid_ai", fn_name=b"trace_cong_avoid")
                self.cubic_functions_available.append("tcp_cong_avoid_ai")
            except Exception:
                pass

        # Open perf buffer
        self.bpf["cubic_events"].open_perf_buffer(self._event_handler, page_cnt=64)

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def _event_handler(self, cpu, data, size):
        event = self.bpf["cubic_events"].event(data)

        # Convert IP addresses
        saddr = socket.inet_ntoa(struct.pack('I', event.saddr)) if event.saddr else "0.0.0.0"
        daddr = socket.inet_ntoa(struct.pack('I', event.daddr)) if event.daddr else "0.0.0.0"
        sport = socket.ntohs(event.sport) if event.sport else 0
        dport = socket.ntohs(event.dport) if event.dport else 0

        # Decode comm
        comm = event.comm.decode('utf-8', 'replace')

        # Get event type name
        event_type_name = EVENT_TYPES.get(event.event_type, f"UNKNOWN_{event.event_type}")

        cubic_event = TcpCubicEvent(
            cpu=cpu,
            pid=event.pid,
            tgid=event.tgid,
            ts_uptime_us=event.ts_uptime_us,
            event_type=event.event_type,
            event_type_name=event_type_name,
            comm=comm,
            saddr=saddr,
            daddr=daddr,
            sport=sport,
            dport=dport,
            cwnd=event.cwnd,
            ssthresh=event.ssthresh,
            packets_out=event.packets_out,
            sacked_out=event.sacked_out,
            lost_out=event.lost_out,
            retrans_out=event.retrans_out,
            rtt_us=event.rtt_us,
            min_rtt_us=event.min_rtt_us,
            mss_cache=event.mss_cache,
            cnt=event.cnt,
            last_max_cwnd=event.last_max_cwnd,
            last_cwnd=event.last_cwnd,
            last_time=event.last_time,
            bic_origin_point=event.bic_origin_point,
            bic_K=event.bic_K,
            delay_min=event.delay_min,
            epoch_start=event.epoch_start,
            ack_cnt=event.ack_cnt,
            tcp_cwnd=event.tcp_cwnd,
            found=event.found,
            curr_rtt=event.curr_rtt,
            acked=event.acked,
            in_slow_start=event.in_slow_start,
            is_tcp_friendly=event.is_tcp_friendly,
        )

        self.events.append(cubic_event)

    def data(self) -> list[CollectionTable]:
        # Import here to avoid circular dependency
        from data_schema.tcp_cubic import TcpCubicTable

        if not self.events:
            return []

        # Convert events to DataFrame
        df_data = []
        for event in self.events:
            df_data.append({
                "ts_uptime_us": event.ts_uptime_us,
                "pid": event.pid,
                "tgid": event.tgid,
                "event_type": event.event_type,
                "event_type_name": event.event_type_name,
                "comm": event.comm,
                "saddr": event.saddr,
                "daddr": event.daddr,
                "sport": event.sport,
                "dport": event.dport,
                "cwnd": event.cwnd,
                "ssthresh": event.ssthresh,
                "packets_out": event.packets_out,
                "sacked_out": event.sacked_out,
                "lost_out": event.lost_out,
                "retrans_out": event.retrans_out,
                "rtt_us": event.rtt_us,
                "min_rtt_us": event.min_rtt_us,
                "mss_cache": event.mss_cache,
                "cnt": event.cnt,
                "last_max_cwnd": event.last_max_cwnd,
                "last_cwnd": event.last_cwnd,
                "last_time": event.last_time,
                "bic_origin_point": event.bic_origin_point,
                "bic_K": event.bic_K,
                "delay_min": event.delay_min,
                "epoch_start": event.epoch_start,
                "ack_cnt": event.ack_cnt,
                "tcp_cwnd": event.tcp_cwnd,
                "found": event.found,
                "curr_rtt": event.curr_rtt,
                "acked": event.acked,
                "in_slow_start": event.in_slow_start,
                "is_tcp_friendly": event.is_tcp_friendly,
            })

        df = pl.DataFrame(df_data)
        return [TcpCubicTable.from_df_id(df, collection_id=self.collection_id)]

    def clear(self):
        self.events.clear()

    def pop_data(self) -> list[CollectionTable]:
        tables = self.data()
        self.clear()
        return tables
