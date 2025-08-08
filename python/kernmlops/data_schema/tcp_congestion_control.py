import polars as pl
from data_schema.schema import (
    UPTIME_TIMESTAMP,
    CollectionGraph,
    CollectionTable,
)


class TcpCongestionControlTable(CollectionTable):
    """Table for TCP congestion control events"""

    @classmethod
    def name(cls) -> str:
        return "tcp_congestion_control"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            UPTIME_TIMESTAMP: pl.Int64(),
            "pid": pl.Int32(),
            "tgid": pl.Int32(),
            "event_type": pl.Int8(),
            "event_type_name": pl.Utf8(),
            "ca_name": pl.Utf8(),
            "saddr": pl.Utf8(),
            "daddr": pl.Utf8(),
            "sport": pl.Int32(),
            "dport": pl.Int32(),
            "comm": pl.Utf8(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "TcpCongestionControlTable":
        return TcpCongestionControlTable(table=table)

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return []
