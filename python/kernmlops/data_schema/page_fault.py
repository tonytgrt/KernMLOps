import polars as pl
from data_schema.schema import (
    UPTIME_TIMESTAMP,
    CollectionGraph,
    CollectionTable,
    GraphEngine,
)


class PageFaultTable(CollectionTable):

    @classmethod
    def name(cls) -> str:
        return "page_fault"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            UPTIME_TIMESTAMP: pl.Int64(),
            "pid": pl.Int32(),
            "tgid": pl.Int32(),
            "address": pl.Int64(),
            "error_code": pl.Int32(),
            "is_major": pl.Boolean(),
            "is_write": pl.Boolean(),
            "is_exec": pl.Boolean(),
            "comm": pl.Utf8(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "PageFaultTable":
        return PageFaultTable(table=table)

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        # Filter out kernel threads (pid 0) and invalid addresses
        return self.table.filter(
            (pl.col("pid") > 0) &
            (pl.col("address") > 0)
        )

    def graphs(self) -> list[type[CollectionGraph]]:
        # Only return PageFaultRateGraph for now
        return [PageFaultRateGraph]

    def by_process(self, process_name: str) -> pl.DataFrame:
        """Filter faults by process name"""
        return self.filtered_table().filter(pl.col("comm") == process_name)

    def fault_summary(self) -> pl.DataFrame:
        """Summarize faults by type"""
        return self.filtered_table().group_by(["comm", "is_major", "is_write"]).agg([
            pl.count().alias("fault_count"),
            pl.col("address").n_unique().alias("unique_pages")
        ]).sort("fault_count", descending=True)


class PageFaultRateGraph(CollectionGraph):
    """Graph showing page fault rate over time"""

    @classmethod
    def with_graph_engine(cls, graph_engine: GraphEngine) -> CollectionGraph | None:
        page_fault_table = graph_engine.collection_data.get(PageFaultTable)
        if page_fault_table is not None:
            return PageFaultRateGraph(
                graph_engine=graph_engine,
                page_fault_table=page_fault_table
            )
        return None

    @classmethod
    def base_name(cls) -> str:
        return "Page Fault Rate"

    def name(self) -> str:
        return f"{self.base_name()} - {self.graph_engine.collection_data.benchmark}"

    def __init__(self, graph_engine: GraphEngine, page_fault_table: PageFaultTable):
        self.graph_engine = graph_engine
        self.page_fault_table = page_fault_table

    def x_axis(self) -> str:
        return "Time (seconds)"

    def y_axis(self) -> str:
        return "Faults per Second"

    def plot(self) -> None:
        # Calculate fault rate in 100ms windows
        df = self.page_fault_table.filtered_table()

        if len(df) == 0:
            print("No page fault data to plot")
            return

        # Group by 100ms windows
        windowed = df.with_columns(
            (pl.col(UPTIME_TIMESTAMP) // 100_000).alias("window")
        ).group_by("window").agg([
            pl.count().alias("fault_count"),
            pl.col("is_major").sum().alias("major_faults")
        ]).sort("window")

        if len(windowed) == 0:
            print("No windowed data to plot")
            return

        x_data = self.graph_engine.collection_data.normalize_uptime_sec(
            windowed.with_columns(
                (pl.col("window") * 100_000).alias(UPTIME_TIMESTAMP)
            )
        )

        # Plot total and major faults
        self.graph_engine.plot(
            x_data,
            (windowed["fault_count"] * 10).to_list(),  # Convert to per second
            label="Total Faults/sec"
        )
        self.graph_engine.plot(
            x_data,
            (windowed["major_faults"] * 10).to_list(),  # Convert to per second
            label="Major Faults/sec"
        )

    def plot_trends(self) -> None:
        # Add trend lines if needed
        pass
