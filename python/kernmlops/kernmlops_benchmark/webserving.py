import subprocess
import time
from dataclasses import dataclass
from typing import cast

from kernmlops_benchmark.benchmark import Benchmark, GenericBenchmarkConfig
from kernmlops_benchmark.errors import (
    BenchmarkError,
    BenchmarkNotRunningError,
    BenchmarkRunningError,
)
from kernmlops_config import ConfigBase


@dataclass(frozen=True)
class WebServingConfig(ConfigBase):
    # Container configuration
    protocol: str = "http"
    web_server_ip: str = "localhost"
    database_server_ip: str = "localhost"
    memcached_server_ip: str = "localhost"

    # Performance parameters
    load_scale: int = 1
    max_pm_children: int = 80
    worker_process: int = 4

    # Docker network
    network_name: str = "webserving-net"

    # Container names
    database_container: str = "webserving-db"
    memcached_container: str = "webserving-memcached"
    web_server_container: str = "webserving-web"
    client_container: str = "webserving-client"


class WebServingBenchmark(Benchmark):
    @classmethod
    def name(cls) -> str:
        return "webserving"

    @classmethod
    def default_config(cls) -> ConfigBase:
        return WebServingConfig()

    @classmethod
    def from_config(cls, config: ConfigBase) -> "Benchmark":
        generic_config = cast(GenericBenchmarkConfig, getattr(config, "generic"))
        webserving_config = cast(WebServingConfig, getattr(config, cls.name()))
        return WebServingBenchmark(generic_config=generic_config, config=webserving_config)

    def __init__(self, *, generic_config: GenericBenchmarkConfig, config: WebServingConfig):
        self.generic_config = generic_config
        self.config = config
        self.benchmark_dir = self.generic_config.get_benchmark_dir() / "cloudsuite"
        self.client_process: subprocess.Popen | None = None
        self.containers_started = False

    def is_configured(self) -> bool:
        # Check if Docker is available and images are pulled
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", "cloudsuite/web-serving:db_server"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def setup(self) -> None:
        if self.client_process is not None:
            raise BenchmarkRunningError()

        # Create docker network if it doesn't exist
        subprocess.run(
            ["docker", "network", "create", self.config.network_name],
            capture_output=True
        )

        # Stop any existing containers
        self._cleanup_containers()

        # Start database server
        print("Starting database server...")
        subprocess.run([
            "docker", "run", "-dt",
            f"--name={self.config.database_container}",
            f"--network={self.config.network_name}",
            "cloudsuite/web-serving:db_server"
        ], check=True)

        # Wait for database to initialize
        time.sleep(10)

        # Start memcached server
        print("Starting memcached server...")
        subprocess.run([
            "docker", "run", "-dt",
            f"--name={self.config.memcached_container}",
            f"--network={self.config.network_name}",
            "cloudsuite/web-serving:memcached_server"
        ], check=True)

        # Get container IPs
        db_ip = self._get_container_ip(self.config.database_container)
        memcached_ip = self._get_container_ip(self.config.memcached_container)

        # Start web server
        print("Starting web server...")
        subprocess.run([
            "docker", "run", "-dt",
            f"--name={self.config.web_server_container}",
            f"--network={self.config.network_name}",
            "-p", "8080:8080",
            "cloudsuite/web-serving:web_server",
            "/etc/bootstrap.sh",
            self.config.protocol,
            "localhost",  # Web server IP
            db_ip,
            memcached_ip,
            str(self.config.max_pm_children),
            str(self.config.worker_process)
        ], check=True)

        # Wait for web server to start
        time.sleep(15)

        self.containers_started = True
        self.generic_config.generic_setup()

    def run(self) -> None:
        if self.client_process is not None:
            raise BenchmarkRunningError()

        if not self.containers_started:
            raise BenchmarkError("Containers not started. Run setup() first.")

        # Get web server IP
        web_ip = self._get_container_ip(self.config.web_server_container)

        # Run the client benchmark
        print(f"Starting benchmark client with load scale {self.config.load_scale}...")
        self.client_process = subprocess.Popen([
            "docker", "run",
            f"--name={self.config.client_container}",
            f"--network={self.config.network_name}",
            "cloudsuite/web-serving:faban_client",
            web_ip,
            str(self.config.load_scale)
        ])

    def poll(self) -> int | None:
        if self.client_process is None:
            raise BenchmarkNotRunningError()
        return self.client_process.poll()

    def wait(self) -> None:
        if self.client_process is None:
            raise BenchmarkNotRunningError()
        self.client_process.wait()

        # Collect results
        print("\nCollecting benchmark results...")
        subprocess.run([
            "docker", "logs", self.config.client_container
        ])

    def kill(self) -> None:
        if self.client_process is not None:
            self.client_process.kill()
        self._cleanup_containers()

    def _cleanup_containers(self) -> None:
        """Stop and remove all benchmark containers."""
        containers = [
            self.config.client_container,
            self.config.web_server_container,
            self.config.memcached_container,
            self.config.database_container
        ]

        for container in containers:
            subprocess.run(
                ["docker", "stop", container],
                capture_output=True
            )
            subprocess.run(
                ["docker", "rm", container],
                capture_output=True
            )

        self.containers_started = False

    def _get_container_ip(self, container_name: str) -> str:
        """Get the IP address of a container in the network."""
        result = subprocess.run(
            [
                "docker", "inspect", "-f",
                f"{{{{.NetworkSettings.Networks.{self.config.network_name}.IPAddress}}}}",
                container_name
            ],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
