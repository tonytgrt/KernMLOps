import polars as pl
from data_schema.schema import (
    UPTIME_TIMESTAMP,
    CollectionGraph,
    CollectionTable,
    GraphEngine,
)


class TcpStateProcessTable(CollectionTable):
    """Table for TCP state process events"""

    @classmethod
    def name(cls) -> str:
        return "tcp_state_process"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            UPTIME_TIMESTAMP: pl.Int64(),
            "pid": pl.Int32(),
            "tgid": pl.Int32(),
            "old_state": pl.Int8(),
            "new_state": pl.Int8(),
            "old_state_name": pl.Utf8(),
            "new_state_name": pl.Utf8(),
            "event_type": pl.Int8(),
            "event_type_name": pl.Utf8(),
            "event_subtype": pl.Int8(),
            "event_subtype_name": pl.Utf8(),
            "comm": pl.Utf8(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "TcpStateProcessTable":
        return TcpStateProcessTable(table=table)

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return [
            TcpStateTransitionGraph,
            TcpEventTypeDistributionGraph,
            TcpStateTimelineGraph
        ]

    def get_transition_summary(self) -> pl.DataFrame:
        """Get summary of state transitions"""
        transitions = self.table.filter(pl.col("event_type_name") == "TRANSITION")
        if len(transitions) == 0:
            return pl.DataFrame()

        return transitions.select([
            pl.concat_str([
                pl.col("old_state_name"),
                pl.lit(" → "),
                pl.col("new_state_name")
            ]).alias("transition"),
            pl.col("comm")
        ]).group_by("transition").count().sort("count", descending=True)

    def get_event_summary(self) -> pl.DataFrame:
        """Get summary of all events by type"""
        return self.table.group_by(["event_type_name", "event_subtype_name"]).count().sort("count", descending=True)

    def get_process_summary(self) -> pl.DataFrame:
        """Get summary by process"""
        return self.table.group_by("comm").agg([
            pl.count().alias("total_events"),
            pl.col("event_type_name").filter(pl.col("event_type_name") == "TRANSITION").count().alias("transitions"),
            pl.col("event_type_name").filter(pl.col("event_type_name") == "ERROR").count().alias("errors"),
            pl.col("event_type_name").filter(pl.col("event_type_name") == "PROCESSING").count().alias("processing")
        ]).sort("total_events", descending=True)


class TcpStateStatsTable(CollectionTable):
    """Table for aggregated TCP state statistics"""

    @classmethod
    def name(cls) -> str:
        return "tcp_state_stats"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            "total_calls": pl.Int64(),
            "listen_state": pl.Int64(),
            "syn_sent_state": pl.Int64(),
            "syn_recv_to_established": pl.Int64(),
            "fin_wait1_to_fin_wait2": pl.Int64(),
            "to_time_wait": pl.Int64(),
            "to_last_ack": pl.Int64(),
            "challenge_acks": pl.Int64(),
            "resets": pl.Int64(),
            "fast_open_checks": pl.Int64(),
            "ack_processing": pl.Int64(),
            "data_queued": pl.Int64(),
            "abort_on_data": pl.Int64(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "TcpStateStatsTable":
        return TcpStateStatsTable(table=table)

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return []


class TcpStateTransitionGraph(CollectionGraph):
    """Graph showing TCP state transitions"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpStateProcessTable)
        if tcp_table is not None:
            transitions = tcp_table.get_transition_summary()
            if len(transitions) > 0:
                return TcpStateTransitionGraph(
                    graph_engine=graph_engine,
                    tcp_table=tcp_table
                )
        return None

    @classmethod
    def base_name(cls) -> str:
        return "TCP State Transitions"

    def name(self) -> str:
        return f"{self.base_name()} - {self.graph_engine.collection_data.benchmark}"

    def __init__(self, graph_engine: GraphEngine, tcp_table: TcpStateProcessTable):
        self.graph_engine = graph_engine
        self.tcp_table = tcp_table

    def x_axis(self) -> str:
        return "State Transition"

    def y_axis(self) -> str:
        return "Count"

    def plot(self) -> None:
        transitions = self.tcp_table.get_transition_summary()
        if len(transitions) == 0:
            return

        # Show top 10 transitions
        transitions = transitions.head(10)

        self.graph_engine.bar(
            transitions["transition"].to_list(),
            transitions["count"].to_list()
        )

    def plot_trends(self) -> None:
        pass


class TcpEventTypeDistributionGraph(CollectionGraph):
    """Graph showing distribution of TCP event types"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpStateProcessTable)
        if tcp_table is not None and len(tcp_table.table) > 0:
            return TcpEventTypeDistributionGraph(
                graph_engine=graph_engine,
                tcp_table=tcp_table
            )
        return None

    @classmethod
    def base_name(cls) -> str:
        return "TCP Event Type Distribution"

    def name(self) -> str:
        return f"{self.base_name()} - {self.graph_engine.collection_data.benchmark}"

    def __init__(self, graph_engine: GraphEngine, tcp_table: TcpStateProcessTable):
        self.graph_engine = graph_engine
        self.tcp_table = tcp_table

    def x_axis(self) -> str:
        return "Event Type"

    def y_axis(self) -> str:
        return "Count"

    def plot(self) -> None:
        # Group by event type for pie chart
        event_summary = self.tcp_table.table.group_by("event_type_name").count()

        if len(event_summary) == 0:
            return

        self.graph_engine.pie(
            event_summary["event_type_name"].to_list(),
            event_summary["count"].to_list()
        )

    def plot_trends(self) -> None:
        pass


class TcpStateTimelineGraph(CollectionGraph):
    """Graph showing TCP state events over time"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpStateProcessTable)
        if tcp_table is not None and len(tcp_table.table) > 0:
            return TcpStateTimelineGraph(
                graph_engine=graph_engine,
                tcp_table=tcp_table
            )
        return None

    @classmethod
    def base_name(cls) -> str:
        return "TCP State Events Timeline"

    def name(self) -> str:
        return f"{self.base_name()} - {self.graph_engine.collection_data.benchmark}"

    def __init__(self, graph_engine: GraphEngine, tcp_table: TcpStateProcessTable):
        self.graph_engine = graph_engine
        self.tcp_table = tcp_table

    def x_axis(self) -> str:
        return "Time (seconds)"

    def y_axis(self) -> str:
        return "Event Count"

    def plot(self) -> None:
        # Create time buckets (1 second intervals)
        df = self.tcp_table.table.with_columns([
            ((pl.col(UPTIME_TIMESTAMP) - pl.col(UPTIME_TIMESTAMP).min()) / 1_000_000).cast(pl.Int32).alias("time_bucket")
        ])

        # Count events per time bucket for each event type
        timeline = df.group_by(["time_bucket", "event_type_name"]).count().sort("time_bucket")

        if len(timeline) == 0:
            return

        # Plot each event type as a separate line
        for event_type in ["TRANSITION", "ERROR", "PROCESSING"]:
            type_data = timeline.filter(pl.col("event_type_name") == event_type)
            if len(type_data) > 0:
                self.graph_engine.plot(
                    type_data["time_bucket"].to_list(),
                    type_data["count"].to_list(),
                    label=event_type.lower()
                )

    def plot_trends(self) -> None:
        pass
