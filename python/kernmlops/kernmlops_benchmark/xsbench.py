import subprocess
from dataclasses import dataclass
from typing import cast

from kernmlops_benchmark.benchmark import Benchmark, GenericBenchmarkConfig
from kernmlops_benchmark.errors import (
    BenchmarkNotRunningError,
    BenchmarkRunningError,
)
from kernmlops_config import ConfigBase


@dataclass(frozen=True)
class XSBenchConfig(ConfigBase):
    # Add configuration parameters specific to xsbench
    threads: int = 1
    grid_points: int = 11303
    lookups: int = 15000000
    # ... other parameters

class XSBenchBenchmark(Benchmark):
    @classmethod
    def name(cls) -> str:
        return "xsbench"

    @classmethod
    def default_config(cls) -> ConfigBase:
        return XSBenchConfig()

    @classmethod
    def from_config(cls, config: ConfigBase) -> "Benchmark":
        generic_config = cast(GenericBenchmarkConfig, getattr(config, "generic"))
        xsbench_config = cast(XSBenchConfig, getattr(config, cls.name()))
        return XSBenchBenchmark(generic_config=generic_config, config=xsbench_config)

    def __init__(self, *, generic_config: GenericBenchmarkConfig, config: XSBenchConfig):
        self.generic_config = generic_config
        self.config = config
        self.benchmark_dir = self.generic_config.get_benchmark_dir() / "xsbench"
        self.process: subprocess.Popen | None = None

    def is_configured(self) -> bool:
        return self.benchmark_dir.is_dir()

    def setup(self) -> None:
        if self.process is not None:
            raise BenchmarkRunningError()
        self.generic_config.generic_setup()

    def run(self) -> None:
        # Launch xsbench with appropriate parameters
        run_cmd = [
            f"{self.benchmark_dir}/XSBench",
            "-t", str(self.config.threads),
            "-g", str(self.config.grid_points),
            "-l", str(self.config.lookups)
        ]
        self.process = subprocess.Popen(run_cmd)

    def poll(self) -> int | None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        return self.process.poll()

    def wait(self) -> None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        self.process.wait()

    def kill(self) -> None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        self.process.kill()
