import polars as pl
from data_schema.schema import (
    UPTIME_TIMESTAMP,
    CollectionGraph,
    CollectionTable,
)


class TcpCubicTable(CollectionTable):
    """Table for TCP CUBIC congestion control events and metrics"""

    @classmethod
    def name(cls) -> str:
        return "tcp_cubic"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            UPTIME_TIMESTAMP: pl.Int64(),
            "pid": pl.Int32(),
            "tgid": pl.Int32(),
            "event_type": pl.Int8(),
            "event_type_name": pl.Utf8(),
            "comm": pl.Utf8(),

            # Connection info
            "saddr": pl.Utf8(),
            "daddr": pl.Utf8(),
            "sport": pl.Int32(),
            "dport": pl.Int32(),

            # TCP state
            "cwnd": pl.Int32(),
            "ssthresh": pl.Int32(),
            "packets_out": pl.Int32(),
            "sacked_out": pl.Int32(),
            "lost_out": pl.Int32(),
            "retrans_out": pl.Int32(),
            "rtt_us": pl.Int32(),
            "min_rtt_us": pl.Int32(),
            "mss_cache": pl.Int32(),

            # CUBIC state
            "cnt": pl.Int32(),
            "last_max_cwnd": pl.Int32(),
            "last_cwnd": pl.Int32(),
            "last_time": pl.Int32(),
            "bic_origin_point": pl.Int32(),
            "bic_K": pl.Int32(),
            "delay_min": pl.Int32(),
            "epoch_start": pl.Int32(),
            "ack_cnt": pl.Int32(),
            "tcp_cwnd": pl.Int32(),
            "found": pl.Int8(),
            "curr_rtt": pl.Int32(),

            # Additional metrics
            "acked": pl.Int32(),
            "in_slow_start": pl.Int8(),
            "is_tcp_friendly": pl.Int8(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "TcpCubicTable":
        return TcpCubicTable(table=table)

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return []

    def get_cubic_summary(self) -> pl.DataFrame:
        """Get summary of CUBIC events and metrics"""
        if len(self.table) == 0:
            return pl.DataFrame()

        # Group by event type
        event_summary = self.table.group_by("event_type_name").agg([
            pl.count().alias("count"),
            pl.col("cwnd").mean().alias("avg_cwnd"),
            pl.col("rtt_us").mean().alias("avg_rtt_us"),
            pl.col("cnt").mean().alias("avg_cnt"),
        ]).sort("count", descending=True)

        return event_summary

    def get_connection_summary(self) -> pl.DataFrame:
        """Get per-connection CUBIC metrics"""
        if len(self.table) == 0:
            return pl.DataFrame()

        # Group by connection tuple
        conn_summary = self.table.group_by(["saddr", "daddr", "sport", "dport"]).agg([
            pl.count().alias("event_count"),
            pl.col("cwnd").max().alias("max_cwnd"),
            pl.col("cwnd").mean().alias("avg_cwnd"),
            pl.col("ssthresh").mean().alias("avg_ssthresh"),
            pl.col("rtt_us").mean().alias("avg_rtt_us"),
            pl.col("min_rtt_us").min().alias("min_rtt_us"),
            pl.col("retrans_out").max().alias("max_retrans"),
            pl.col("in_slow_start").mean().alias("slow_start_ratio"),
            pl.col("is_tcp_friendly").mean().alias("tcp_friendly_ratio"),
        ]).sort("event_count", descending=True)

        return conn_summary

    def get_slow_start_analysis(self) -> pl.DataFrame:
        """Analyze slow start behavior"""
        if len(self.table) == 0:
            return pl.DataFrame()

        slow_start_events = self.table.filter(pl.col("in_slow_start") == 1)
        if len(slow_start_events) == 0:
            return pl.DataFrame()

        return slow_start_events.group_by("comm").agg([
            pl.count().alias("slow_start_events"),
            pl.col("cwnd").mean().alias("avg_cwnd_in_slow_start"),
            pl.col("acked").sum().alias("total_acked_in_slow_start"),
        ]).sort("slow_start_events", descending=True)

    def get_loss_events(self) -> pl.DataFrame:
        """Get loss detection events (ssthresh recalculations)"""
        if len(self.table) == 0:
            return pl.DataFrame()

        loss_events = self.table.filter(pl.col("event_type_name") == "SSTHRESH")
        if len(loss_events) == 0:
            return pl.DataFrame()

        return loss_events.select([
            UPTIME_TIMESTAMP,
            "comm",
            "saddr",
            "daddr",
            "sport",
            "dport",
            "cwnd",
            "ssthresh",
            "lost_out",
            "retrans_out",
        ]).sort(UPTIME_TIMESTAMP)
