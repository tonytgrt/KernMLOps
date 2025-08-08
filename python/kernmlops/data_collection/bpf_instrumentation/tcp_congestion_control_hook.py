from dataclasses import dataclass
from pathlib import Path
import socket
import struct

import polars as pl
from bcc import BPF

from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable

EVENT_NAMES = {
    1: "ASSIGN",
    2: "INIT",
    3: "SET",
    4: "REINIT",
    5: "CLEANUP",
}


@dataclass(frozen=True)
class TcpCongestionEvent:
    cpu: int
    pid: int
    tgid: int
    ts_uptime_us: int
    event_type: int
    event_type_name: str
    ca_name: str
    saddr: str
    daddr: str
    sport: int
    dport: int
    comm: str


class TcpCongestionControlBPFHook(BPFProgram):

    @classmethod
    def name(cls) -> str:
        return "tcp_congestion_control"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/tcp_congestion_control.bpf.c", "r").read()
        self.bpf_text = bpf_text
        self.events = list[TcpCongestionEvent]()

    def load(self, collection_id: str):
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)

        # Attach core congestion control functions
        self.bpf.attach_kprobe(event=b"tcp_assign_congestion_control", fn_name=b"trace_assign_cc")
        self.bpf.attach_kprobe(event=b"tcp_init_congestion_control", fn_name=b"trace_init_cc")
        self.bpf.attach_kprobe(event=b"tcp_set_congestion_control", fn_name=b"trace_set_cc")
        try:
            self.bpf.attach_kprobe(event=b"tcp_reinit_congestion_control", fn_name=b"trace_reinit_cc")
        except Exception:
            pass
        self.bpf.attach_kprobe(event=b"tcp_cleanup_congestion_control", fn_name=b"trace_cleanup_cc")

        self.bpf["cc_events"].open_perf_buffer(self._event_handler, page_cnt=64)

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def _event_handler(self, cpu, data, size):
        event = self.bpf["cc_events"].event(data)

        saddr = socket.inet_ntoa(struct.pack('I', event.saddr)) if event.saddr else "0.0.0.0"
        daddr = socket.inet_ntoa(struct.pack('I', event.daddr)) if event.daddr else "0.0.0.0"
        sport = socket.ntohs(event.sport) if event.sport else 0
        dport = socket.ntohs(event.dport) if event.dport else 0
        ca_name = event.ca_name.decode('utf-8', 'replace').rstrip('\x00')
        comm = event.comm.decode('utf-8', 'replace').rstrip('\x00')

        self.events.append(
            TcpCongestionEvent(
                cpu=cpu,
                pid=event.pid,
                tgid=event.tgid,
                ts_uptime_us=event.ts_uptime_us,
                event_type=event.event_type,
                event_type_name=EVENT_NAMES.get(event.event_type, f"EVENT_{event.event_type}"),
                ca_name=ca_name,
                saddr=saddr,
                daddr=daddr,
                sport=sport,
                dport=dport,
                comm=comm,
            )
        )

    def data(self) -> list[CollectionTable]:
        from data_schema.tcp_congestion_control import TcpCongestionControlTable
        if len(self.events) == 0:
            return []
        events_df = pl.DataFrame(self.events)
        return [
            TcpCongestionControlTable.from_df_id(events_df, collection_id=self.collection_id)
        ]

    def clear(self):
        self.events.clear()

    def pop_data(self) -> list[CollectionTable]:
        tables = self.data()
        self.clear()
        return tables
