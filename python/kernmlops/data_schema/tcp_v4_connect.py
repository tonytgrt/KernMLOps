"""Data schema for TCP v4 connect tracking"""

import polars as pl
from data_schema.schema import (
    UPTIME_TIMESTAMP,
    CollectionGraph,
    CollectionTable,
    GraphEngine,
)


class TcpV4ConnectTable(CollectionTable):
    """Table for TCP v4 connect events"""

    @classmethod
    def name(cls) -> str:
        return "tcp_v4_connect"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            UPTIME_TIMESTAMP: pl.Int64(),
            "pid": pl.Int32(),
            "tgid": pl.Int32(),
            "latency_ns": pl.Int64(),
            "branch_type": pl.Int8(),
            "branch_name": pl.Utf8(),
            "path_type": pl.Int8(),
            "path_name": pl.Utf8(),
            "error_code": pl.Int32(),
            "error_name": pl.Utf8(),
            "saddr": pl.Utf8(),
            "daddr": pl.Utf8(),
            "sport": pl.Int32(),
            "dport": pl.Int32(),
            "comm": pl.Utf8(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "TcpV4ConnectTable":
        return TcpV4ConnectTable(table=table)

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return [
            TcpConnectBranchGraph,
            TcpConnectPathGraph,
            TcpConnectLatencyGraph,
            TcpConnectErrorGraph,
        ]

    def get_branch_summary(self) -> pl.DataFrame:
        """Get summary of branch hits"""
        total = len(self.table)
        if total == 0:
            return pl.DataFrame()

        return self.table.group_by("branch_name").agg([
            pl.count().alias("count"),
            (pl.count() * 100.0 / total).alias("percentage"),
            pl.col("latency_ns").mean().alias("avg_latency_ns"),
            pl.col("latency_ns").max().alias("max_latency_ns"),
        ]).sort("count", descending=True)

    def get_path_analysis(self) -> pl.DataFrame:
        """Analyze connection paths"""
        return self.table.group_by("path_name").agg([
            pl.count().alias("count"),
            pl.col("latency_ns").mean().alias("avg_latency_ns"),
            pl.col("latency_ns").quantile(0.99).alias("p99_latency_ns"),
            pl.col("error_code").filter(pl.col("error_code") != 0).count().alias("errors"),
        ]).sort("count", descending=True)

    def get_error_summary(self) -> pl.DataFrame:
        """Get error distribution"""
        errors = self.table.filter(pl.col("error_code") != 0)
        if len(errors) == 0:
            return pl.DataFrame()

        return errors.group_by(["error_name", "branch_name"]).count().sort("count", descending=True)

    def get_destination_analysis(self) -> pl.DataFrame:
        """Analyze connections by destination"""
        return self.table.group_by(["daddr", "dport"]).agg([
            pl.count().alias("attempts"),
            pl.col("error_code").filter(pl.col("error_code") == 0).count().alias("successes"),
            pl.col("error_code").filter(pl.col("error_code") != 0).count().alias("failures"),
            pl.col("latency_ns").mean().alias("avg_latency_ns"),
        ]).sort("attempts", descending=True)


class TcpConnectStatsTable(CollectionTable):
    """Aggregated statistics for TCP connections"""

    @classmethod
    def name(cls) -> str:
        return "tcp_connect_stats"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            "total_connections": pl.Int64(),
            "successful_connections": pl.Int64(),
            "failed_connections": pl.Int64(),
            "fast_path_count": pl.Int64(),
            "slow_path_count": pl.Int64(),
            "error_path_count": pl.Int64(),
            "fastopen_count": pl.Int64(),
            "avg_latency_ns": pl.Float64(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "TcpConnectStatsTable":
        return TcpConnectStatsTable(table=table)

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return []


class TcpConnectBranchGraph(CollectionGraph):
    """Graph showing branch distribution in tcp_v4_connect"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpV4ConnectTable)
        if tcp_table is not None:
            branch_summary = tcp_table.get_branch_summary()
            if len(branch_summary) > 0:
                return TcpConnectBranchGraph(graph_engine, branch_summary)
        return None

    @classmethod
    def base_name(cls) -> str:
        return "tcp_connect_branches"

    def __init__(self, graph_engine: GraphEngine, branch_data: pl.DataFrame):
        self.graph_engine = graph_engine
        self.branch_data = branch_data

    def name(self) -> str:
        return f"{self.base_name()}_{self.graph_engine.collection_data.id}"

    def x_axis(self) -> str:
        return "Branch"

    def y_axis(self) -> str:
        return "Count"

    def plot(self) -> None:
        top_branches = self.branch_data.head(15)
        self.graph_engine.bar(
            x=top_branches["branch_name"].to_list(),
            y=top_branches["count"].to_list(),
            title="TCP Connect Branch Distribution",
            xlabel=self.x_axis(),
            ylabel=self.y_axis(),
        )

    def plot_trends(self) -> None:
        pass


class TcpConnectPathGraph(CollectionGraph):
    """Graph showing connection path distribution"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpV4ConnectTable)
        if tcp_table is not None:
            path_data = tcp_table.get_path_analysis()
            if len(path_data) > 0:
                return TcpConnectPathGraph(graph_engine, path_data)
        return None

    @classmethod
    def base_name(cls) -> str:
        return "tcp_connect_paths"

    def __init__(self, graph_engine: GraphEngine, path_data: pl.DataFrame):
        self.graph_engine = graph_engine
        self.path_data = path_data

    def name(self) -> str:
        return f"{self.base_name()}_{self.graph_engine.collection_data.id}"

    def x_axis(self) -> str:
        return "Path Type"

    def y_axis(self) -> str:
        return "Count"

    def plot(self) -> None:
        self.graph_engine.bar(
            x=self.path_data["path_name"].to_list(),
            y=self.path_data["count"].to_list(),
            title="TCP Connect Path Distribution",
            xlabel=self.x_axis(),
            ylabel=self.y_axis(),
        )

    def plot_trends(self) -> None:
        pass


class TcpConnectLatencyGraph(CollectionGraph):
    """Graph showing connection latency distribution"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpV4ConnectTable)
        if tcp_table is not None and len(tcp_table.table) > 0:
            return TcpConnectLatencyGraph(graph_engine, tcp_table)
        return None

    @classmethod
    def base_name(cls) -> str:
        return "tcp_connect_latency"

    def __init__(self, graph_engine: GraphEngine, tcp_table: TcpV4ConnectTable):
        self.graph_engine = graph_engine
        self.tcp_table = tcp_table

    def name(self) -> str:
        return f"{self.base_name()}_{self.graph_engine.collection_data.id}"

    def x_axis(self) -> str:
        return "Time (s)"

    def y_axis(self) -> str:
        return "Latency (μs)"

    def plot(self) -> None:
        data = self.tcp_table.table.sort(UPTIME_TIMESTAMP)
        if len(data) > 0:
            timestamps = self.graph_engine.collection_data.normalize_uptime_sec(data)
            latencies = (data["latency_ns"] / 1000).to_list()  # Convert to microseconds

            self.graph_engine.scatter(
                x=timestamps,
                y=latencies,
                title="TCP Connect Latency Over Time",
                xlabel=self.x_axis(),
                ylabel=self.y_axis(),
            )

    def plot_trends(self) -> None:
        data = self.tcp_table.table.sort(UPTIME_TIMESTAMP)
        if len(data) > 10:
            timestamps = self.graph_engine.collection_data.normalize_uptime_sec(data)
            latencies = (data["latency_ns"] / 1000).to_list()
            self.graph_engine.plot_trend(x=timestamps, y=latencies)


class TcpConnectErrorGraph(CollectionGraph):
    """Graph showing connection errors"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        tcp_table = graph_engine.collection_data.get(TcpV4ConnectTable)
        if tcp_table is not None:
            error_summary = tcp_table.get_error_summary()
            if len(error_summary) > 0:
                return TcpConnectErrorGraph(graph_engine, error_summary)
        return None

    @classmethod
    def base_name(cls) -> str:
        return "tcp_connect_errors"

    def __init__(self, graph_engine: GraphEngine, error_data: pl.DataFrame):
        self.graph_engine = graph_engine
        self.error_data = error_data

    def name(self) -> str:
        return f"{self.base_name()}_{self.graph_engine.collection_data.id}"

    def x_axis(self) -> str:
        return "Error Type"

    def y_axis(self) -> str:
        return "Count"

    def plot(self) -> None:
        # Group by error type
        error_counts = self.error_data.group_by("error_name").agg(
            pl.col("count").sum()
        ).sort("count", descending=True).head(10)

        if len(error_counts) > 0:
            self.graph_engine.bar(
                x=error_counts["error_name"].to_list(),
                y=error_counts["count"].to_list(),
                title="TCP Connect Error Distribution",
                xlabel=self.x_axis(),
                ylabel=self.y_axis(),
            )

    def plot_trends(self) -> None:
        pass
