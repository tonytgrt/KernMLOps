import polars as pl
from data_schema.schema import (
    UPTIME_TIMESTAMP,
    CollectionGraph,
    CollectionTable,
    GraphEngine,
)


class TcpV4RcvTable(CollectionTable):

    @classmethod
    def name(cls) -> str:
        return "tcp_v4_rcv"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            UPTIME_TIMESTAMP: pl.Int64(),
            "pid": pl.Int32(),
            "tgid": pl.Int32(),
            "branch_type": pl.Int8(),
            "branch_name": pl.Utf8(),
            "drop_reason": pl.Int8(),
            "drop_reason_name": pl.Utf8(),
            "saddr": pl.Utf8(),
            "daddr": pl.Utf8(),
            "sport": pl.Int32(),
            "dport": pl.Int32(),
            "comm": pl.Utf8(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "TcpV4RcvTable":
        return TcpV4RcvTable(table=table)

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return [TcpBranchDistributionGraph, TcpDropReasonsGraph, TcpProcessingPathGraph]

    def get_statistics(self) -> pl.DataFrame:
        """Get branch statistics summary"""
        total = len(self.table)
        if total == 0:
            return pl.DataFrame()

        # Calculate per-branch statistics
        stats = self.table.group_by("branch_name").agg([
            pl.count().alias("count"),
            (pl.count() * 100.0 / total).alias("percentage")
        ]).sort("count", descending=True)

        return stats

    def get_drop_summary(self) -> pl.DataFrame:
        """Get drop reason summary"""
        drops = self.table.filter(pl.col("drop_reason") > 0)
        if len(drops) == 0:
            return pl.DataFrame()

        return drops.group_by("drop_reason_name").count().sort("count", descending=True)

    def get_processing_paths(self) -> pl.DataFrame:
        """Analyze packet processing paths"""
        # Group common processing paths
        paths = self.table.select([
            pl.when(pl.col("branch_name") == "entry").then("received")
            .when(pl.col("branch_name").is_in(["do_rcv_direct", "established_proc"])).then("fast_path")
            .when(pl.col("branch_name").is_in(["socket_busy", "backlog_add"])).then("slow_path")
            .when(pl.col("branch_name").is_in(["new_syn_recv", "listen_state"])).then("connection_setup")
            .when(pl.col("branch_name") == "time_wait").then("connection_cleanup")
            .when(pl.col("drop_reason") > 0).then("dropped")
            .otherwise("other").alias("processing_path")
        ])

        return paths.group_by("processing_path").count().sort("count", descending=True)

    def get_performance_indicators(self) -> dict:
        """Calculate performance indicators"""
        total = len(self.table)
        if total == 0:
            return {}

        drops = self.table.filter(pl.col("drop_reason") > 0).height
        fast_path = self.table.filter(
            pl.col("branch_name").is_in(["do_rcv_direct", "established_proc"])
        ).height
        slow_path = self.table.filter(
            pl.col("branch_name").is_in(["socket_busy", "backlog_add"])
        ).height

        return {
            "drop_rate": (drops / total) * 100,
            "fast_path_rate": (fast_path / total) * 100,
            "slow_path_rate": (slow_path / total) * 100,
            "backlog_pressure": (self.table.filter(pl.col("branch_name") == "socket_busy").height / total) * 100
        }


class TcpBranchDistributionGraph(CollectionGraph):
    """Graph showing TCP branch distribution"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpV4RcvTable)
        if tcp_table is not None and len(tcp_table.table) > 0:
            return TcpBranchDistributionGraph(
                graph_engine=graph_engine,
                tcp_table=tcp_table
            )
        return None

    @classmethod
    def base_name(cls) -> str:
        return "TCP v4 Receive Branch Distribution"

    def name(self) -> str:
        return f"{self.base_name()} - {self.graph_engine.collection_data.benchmark}"

    def __init__(self, graph_engine: GraphEngine, tcp_table: TcpV4RcvTable):
        self.graph_engine = graph_engine
        self.tcp_table = tcp_table

    def x_axis(self) -> str:
        return "Branch Type"

    def y_axis(self) -> str:
        return "Count"

    def plot(self) -> None:
        stats = self.tcp_table.get_statistics()
        if len(stats) == 0:
            return

        # Filter out entry branch and show top 15 branches
        stats = stats.filter(pl.col("branch_name") != "entry").head(15)

        self.graph_engine.bar(
            stats["branch_name"].to_list(),
            stats["count"].to_list()
        )

    def plot_trends(self) -> None:
        pass


class TcpDropReasonsGraph(CollectionGraph):
    """Graph showing TCP drop reasons"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpV4RcvTable)
        if tcp_table is not None:
            drops = tcp_table.get_drop_summary()
            if len(drops) > 0:
                return TcpDropReasonsGraph(
                    graph_engine=graph_engine,
                    tcp_table=tcp_table
                )
        return None

    @classmethod
    def base_name(cls) -> str:
        return "TCP Drop Reasons"

    def name(self) -> str:
        return f"{self.base_name()} - {self.graph_engine.collection_data.benchmark}"

    def __init__(self, graph_engine: GraphEngine, tcp_table: TcpV4RcvTable):
        self.graph_engine = graph_engine
        self.tcp_table = tcp_table

    def x_axis(self) -> str:
        return "Drop Reason"

    def y_axis(self) -> str:
        return "Count"

    def plot(self) -> None:
        drops = self.tcp_table.get_drop_summary()
        if len(drops) == 0:
            return

        self.graph_engine.bar(
            drops["drop_reason_name"].to_list(),
            drops["count"].to_list()
        )

    def plot_trends(self) -> None:
        pass


class TcpProcessingPathGraph(CollectionGraph):
    """Graph showing TCP processing paths (fast/slow/drop)"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpV4RcvTable)
        if tcp_table is not None and len(tcp_table.table) > 0:
            return TcpProcessingPathGraph(
                graph_engine=graph_engine,
                tcp_table=tcp_table
            )
        return None

    @classmethod
    def base_name(cls) -> str:
        return "TCP Processing Paths"

    def name(self) -> str:
        return f"{self.base_name()} - {self.graph_engine.collection_data.benchmark}"

    def __init__(self, graph_engine: GraphEngine, tcp_table: TcpV4RcvTable):
        self.graph_engine = graph_engine
        self.tcp_table = tcp_table

    def x_axis(self) -> str:
        return "Processing Path"

    def y_axis(self) -> str:
        return "Count"

    def plot(self) -> None:
        paths = self.tcp_table.get_processing_paths()
        if len(paths) == 0:
            return

        # Use pie chart for processing paths
        self.graph_engine.pie(
            paths["processing_path"].to_list(),
            paths["count"].to_list()
        )

    def plot_trends(self) -> None:
        pass
