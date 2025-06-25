from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable


@dataclass(frozen=True)
class PageFaultData:
    cpu: int
    pid: int
    tgid: int
    ts_uptime_us: int
    address: int
    error_code: int
    is_major: bool
    is_write: bool
    is_exec: bool
    comm: str


class PageFaultBPFHook(BPFProgram):

    @classmethod
    def name(cls) -> str:
        return "page_fault"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/page_fault.bpf.c", "r").read()

        # Handle kernel version differences
        if BPF.kernel_struct_has_field(b'vm_fault', b'flags') == 1:
            bpf_text = bpf_text.replace('FAULT_FLAG_WRITE', '0x01')
            bpf_text = bpf_text.replace('FAULT_FLAG_INSTRUCTION', '0x100')
        else:
            bpf_text = bpf_text.replace('FAULT_FLAG_WRITE', '0x01')
            bpf_text = bpf_text.replace('FAULT_FLAG_INSTRUCTION', '0x20')

        self.bpf_text = bpf_text
        self.page_fault_data = list[PageFaultData]()

    def load(self, collection_id: str):
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)
        self.bpf["page_fault_events"].open_perf_buffer(
            self._page_fault_handler, page_cnt=128
        )

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def _page_fault_handler(self, cpu, data, size):
        event = self.bpf["page_fault_events"].event(data)
        try:
            self.page_fault_data.append(
                PageFaultData(
                    cpu=cpu,
                    pid=event.pid,
                    tgid=event.tgid,
                    ts_uptime_us=event.ts_uptime_us,
                    address=event.address,
                    error_code=event.error_code,
                    is_major=bool(event.is_major),
                    is_write=bool(event.is_write),
                    is_exec=bool(event.is_exec),
                    comm=event.comm.decode('utf-8', 'replace')
                )
            )
        except Exception:
            pass

    def data(self) -> list[CollectionTable]:
        from data_schema.page_fault import PageFaultTable
        if len(self.page_fault_data) == 0:
            return []
        return [
            PageFaultTable.from_df_id(
                pl.DataFrame(self.page_fault_data),
                collection_id=self.collection_id
            )
        ]

    def clear(self):
        self.page_fault_data.clear()

    def pop_data(self) -> list[CollectionTable]:
        tables = self.data()
        self.clear()
        return tables
