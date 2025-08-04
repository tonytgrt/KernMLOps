from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable

# TCP state constants
TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV"
}

# Event types
EVENT_TYPES = {
    0: "TRANSITION",
    1: "ERROR",
    2: "PROCESSING"
}

# Event subtypes
EVENT_SUBTYPES = {
    0: "NONE",
    1: "CHALLENGE_ACK",
    2: "RESET",
    3: "FAST_OPEN",
    4: "ACK_PROCESS",
    5: "DATA_QUEUE",
    6: "ABORT_DATA"
}

@dataclass(frozen=True)
class TcpStateEvent:
    cpu: int
    pid: int
    tgid: int
    ts_uptime_us: int
    old_state: int
    new_state: int
    old_state_name: str
    new_state_name: str
    event_type: int
    event_type_name: str
    event_subtype: int
    event_subtype_name: str
    comm: str


class TcpStateProcessBPFHook(BPFProgram):

    @classmethod
    def name(cls) -> str:
        return "tcp_state_process"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/tcp_state_process.bpf.c", "r").read()
        self.bpf_text = bpf_text
        self.tcp_state_events = list[TcpStateEvent]()
        self.skip_offsets = False  # Can be made configurable

        # Branch offsets (from the original script)
        self.offsets = {
            "trace_listen_state": 0x12d,
            "trace_syn_sent_state": 0x52,
            "trace_syn_recv_to_established": 0x301,
            "trace_fin_wait1_to_fin_wait2": 0xe7d,
            "trace_to_time_wait": 0x769,
            "trace_last_ack": 0xb3d,
            "trace_challenge_ack": 0x714,
            "trace_reset": 0x8fc,
            "trace_fast_open": 0x67f,
            "trace_ack_processing": 0x4f3,
            "trace_data_queue": 0x5be,
            "trace_abort_on_data": 0xfd9
        }

    def load(self, collection_id: str):
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)

        # Attach main kprobe
        self.bpf.attach_kprobe(
            event=b"tcp_rcv_state_process",
            fn_name=b"trace_tcp_rcv_state_process"
        )

        # Attach offset-based probes if not skipped
        if not self.skip_offsets:
            attached_count = 0
            failed_count = 0

            for fn_name, offset in self.offsets.items():
                try:
                    self.bpf.attach_kprobe(
                        event=b"tcp_rcv_state_process",
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
        self.bpf["tcp_state_events"].open_perf_buffer(
            self._tcp_state_handler, page_cnt=64
        )

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def _tcp_state_handler(self, cpu, data, size):
        event = self.bpf["tcp_state_events"].event(data)

        self.tcp_state_events.append(
            TcpStateEvent(
                cpu=cpu,
                pid=event.pid,
                tgid=event.tgid,
                ts_uptime_us=event.ts_uptime_us,
                old_state=event.old_state,
                new_state=event.new_state,
                old_state_name=TCP_STATES.get(event.old_state, f"STATE_{event.old_state}"),
                new_state_name=TCP_STATES.get(event.new_state, f"STATE_{event.new_state}"),
                event_type=event.event_type,
                event_type_name=EVENT_TYPES.get(event.event_type, "UNKNOWN"),
                event_subtype=event.event_subtype,
                event_subtype_name=EVENT_SUBTYPES.get(event.event_subtype, "UNKNOWN"),
                comm=event.comm.decode('utf-8', 'replace')
            )
        )

    def data(self) -> list[CollectionTable]:
        from data_schema.tcp_state_process import TcpStateProcessTable

        if len(self.tcp_state_events) == 0:
            return []

        # Also collect aggregated statistics from the BPF maps
        stats_data = self._get_aggregated_stats()

        tables = [
            TcpStateProcessTable.from_df_id(
                pl.DataFrame(self.tcp_state_events),
                collection_id=self.collection_id
            )
        ]

        # Add statistics table if available
        if stats_data:
            from data_schema.tcp_state_process import TcpStateStatsTable
            tables.append(
                TcpStateStatsTable.from_df_id(
                    pl.DataFrame([stats_data]),
                    collection_id=self.collection_id
                )
            )

        return tables

    def clear(self):
        self.tcp_state_events.clear()

    def pop_data(self) -> list[CollectionTable]:
        tables = self.data()
        self.clear()
        return tables

    def _get_aggregated_stats(self) -> dict:
        """Get aggregated statistics from BPF maps"""
        try:
            stats_map = self.bpf["stats_map"]
            key = 0
            stats = stats_map.get(key)

            if not stats:
                return {}

            return {
                "total_calls": stats.total_calls,
                "listen_state": stats.listen_state,
                "syn_sent_state": stats.syn_sent_state,
                "syn_recv_to_established": stats.syn_recv_to_established,
                "fin_wait1_to_fin_wait2": stats.fin_wait1_to_fin_wait2,
                "to_time_wait": stats.to_time_wait,
                "to_last_ack": stats.to_last_ack,
                "challenge_acks": stats.challenge_acks,
                "resets": stats.resets,
                "fast_open_checks": stats.fast_open_checks,
                "ack_processing": stats.ack_processing,
                "data_queued": stats.data_queued,
                "abort_on_data": stats.abort_on_data
            }
        except Exception:
            return {}

    def get_state_distribution(self) -> pl.DataFrame:
        """Get state distribution from BPF maps"""
        try:
            state_dist_map = self.bpf["state_distribution"]
            state_data = []

            for state in range(1, 13):  # TCP states 1-12
                count = state_dist_map.get(state, 0)
                if count > 0:
                    state_data.append({
                        "state": state,
                        "state_name": TCP_STATES.get(state, f"STATE_{state}"),
                        "count": count
                    })

            return pl.DataFrame(state_data) if state_data else pl.DataFrame()
        except Exception:
            return pl.DataFrame()
