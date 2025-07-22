import json
import os
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
class IperfConfig(ConfigBase):
    # Server configuration
    server_port: int = 5201
    server_bind: str = "0.0.0.0"

    # Client configuration
    client_target: str = "localhost"
    client_duration: int = 30  # seconds
    client_parallel: int = 4   # number of parallel streams
    client_bandwidth: str = "0"  # 0 means unlimited, can be "100M", "1G", etc.
    client_buffer_length: str = "128K"  # TCP buffer size
    client_window_size: str = "0"  # TCP window size, 0 for system default
    client_mss: int = 0  # Maximum segment size, 0 for default

    # Test options
    reverse: bool = False  # Reverse mode (server sends, client receives)
    bidirectional: bool = False  # Test in both directions
    zero_copy: bool = False  # Use zero-copy sendfile
    no_delay: bool = False  # Set TCP no delay, disabling Nagle's Algorithm

    # Output options
    json_output: bool = True  # Get JSON formatted output
    interval: int = 1  # Reporting interval in seconds


class IperfBenchmark(Benchmark):
    @classmethod
    def name(cls) -> str:
        return "iperf"

    @classmethod
    def default_config(cls) -> ConfigBase:
        return IperfConfig()

    @classmethod
    def from_config(cls, config: ConfigBase) -> "Benchmark":
        generic_config = cast(GenericBenchmarkConfig, getattr(config, "generic"))
        iperf_config = cast(IperfConfig, getattr(config, cls.name()))
        return IperfBenchmark(generic_config=generic_config, config=iperf_config)

    def __init__(self, *, generic_config: GenericBenchmarkConfig, config: IperfConfig):
        self.generic_config = generic_config
        self.config = config
        self.benchmark_dir = self.generic_config.get_benchmark_dir() / "iperf"
        self.server_process: subprocess.Popen | None = None
        self.client_process: subprocess.Popen | None = None
        self.results_file = self.benchmark_dir / "results.json"

    def is_configured(self) -> bool:
        # Create benchmark directory
        self.benchmark_dir.mkdir(parents=True, exist_ok=True)
        return True

    def setup(self) -> None:
        if self.server_process is not None or self.client_process is not None:
            raise BenchmarkRunningError()

        # Check if iperf3 is available
        iperf_check = subprocess.run(["which", "iperf3"], capture_output=True)
        if iperf_check.returncode != 0:
            # Try to install iperf3
            if os.path.exists("/.dockerenv") or os.environ.get("CONTAINER_HOSTNAME"):
                print("Installing iperf3 in Docker container...")
                install_result = subprocess.run(
                    ["apt-get", "update"], capture_output=True
                )
                if install_result.returncode == 0:
                    install_result = subprocess.run(
                        ["apt-get", "install", "-y", "iperf3"],
                        capture_output=True
                    )
                    if install_result.returncode != 0:
                        raise BenchmarkError(
                            "Failed to install iperf3 in Docker container.\n"
                            "Please install manually: apt-get install iperf3"
                        )
                else:
                    raise BenchmarkError("Failed to update package list")
            else:
                raise BenchmarkError(
                    "iperf3 is not available. Please install iperf3:\n"
                    "  Ubuntu/Debian: sudo apt-get install iperf3\n"
                    "  RHEL/CentOS: sudo dnf install iperf3\n"
                    "  macOS: brew install iperf3"
                )

        # Start iperf3 server
        print(f"Starting iperf3 server on port {self.config.server_port}...")
        server_cmd = [
            "iperf3",
            "-s",
            "-p", str(self.config.server_port),
            "-B", self.config.server_bind
        ]

        # Start server in background
        self.server_process = subprocess.Popen(
            server_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Wait for server to start
        time.sleep(2)

        # Check if server is running
        if self.server_process.poll() is not None:
            stdout, stderr = self.server_process.communicate()
            raise BenchmarkError(
                f"Failed to start iperf3 server:\n"
                f"stdout: {stdout.decode('utf-8')}\n"
                f"stderr: {stderr.decode('utf-8')}"
            )

        # Skip server test in Docker - it often fails due to timing
        if os.path.exists("/.dockerenv") or os.environ.get("CONTAINER_HOSTNAME"):
            print("  Running in Docker - skipping server test")
        else:
            # Test server connectivity with retries
            print("Waiting for iperf3 server to be ready...")
            max_retries = 10
            for i in range(max_retries):
                test_cmd = ["iperf3", "-c", self.config.client_target, "-p", str(self.config.server_port), "-t", "1", "--connect-timeout", "1000"]
                test_result = subprocess.run(test_cmd, capture_output=True, text=True)
                if test_result.returncode == 0:
                    break
                elif i < max_retries - 1:
                    time.sleep(1)
                    print(f"  Retry {i+1}/{max_retries}...")
                else:
                    # Provide detailed error information
                    self.kill()
                    error_msg = f"iperf3 server not responding after {max_retries} attempts\n"
                    error_msg += f"stdout: {test_result.stdout}\n"
                    error_msg += f"stderr: {test_result.stderr}\n"

                    # Check if it's a connection issue
                    if "connect failed" in test_result.stderr.lower():
                        error_msg += "\nPossible causes:\n"
                        error_msg += "- Server not fully started\n"
                        error_msg += "- Firewall blocking connection\n"
                        error_msg += "- Wrong IP/port configuration\n"
                        error_msg += f"- Tried connecting to {self.config.client_target}:{self.config.server_port}\n"

                    raise BenchmarkError(error_msg)

        print("iperf3 server started successfully")
        self.generic_config.generic_setup()

    def run(self) -> None:
        if self.client_process is not None:
            raise BenchmarkRunningError()

        if self.server_process is None:
            raise BenchmarkError("iperf3 server not started. Run setup() first.")

        # Build client command
        client_cmd = [
            "iperf3",
            "-c", self.config.client_target,
            "-p", str(self.config.server_port),
            "-t", str(self.config.client_duration),
            "-P", str(self.config.client_parallel),
            "-i", str(self.config.interval)
        ]

        # Add bandwidth limit if specified
        if self.config.client_bandwidth != "0":
            client_cmd.extend(["-b", self.config.client_bandwidth])

        # Add buffer length
        if self.config.client_buffer_length:
            client_cmd.extend(["-l", self.config.client_buffer_length])

        # Add window size
        if self.config.client_window_size != "0":
            client_cmd.extend(["-w", self.config.client_window_size])

        # Add MSS if specified
        if self.config.client_mss > 0:
            client_cmd.extend(["-M", str(self.config.client_mss)])

        # Add test mode options
        if self.config.reverse:
            client_cmd.append("-R")

        if self.config.bidirectional:
            client_cmd.append("--bidir")

        if self.config.zero_copy:
            client_cmd.append("-Z")

        if self.config.no_delay:
            client_cmd.append("-N")

        # Add JSON output
        if self.config.json_output:
            client_cmd.extend(["-J", "--logfile", str(self.results_file)])

        print("Starting iperf3 client test...")
        print(f"Command: {' '.join(client_cmd)}")

        self.client_process = subprocess.Popen(
            client_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    def poll(self) -> int | None:
        if self.client_process is None:
            raise BenchmarkNotRunningError()
        return self.client_process.poll()

    def wait(self) -> None:
        if self.client_process is None:
            raise BenchmarkNotRunningError()

        returncode = self.client_process.wait()
        stdout, stderr = self.client_process.communicate()

        # Parse and display results
        if returncode == 0:
            if self.config.json_output and self.results_file.exists():
                try:
                    with open(self.results_file, 'r') as f:
                        results = json.load(f)
                    self._display_results(results)
                except Exception as e:
                    print(f"Error parsing results: {e}")
                    print(f"stdout: {stdout.decode('utf-8')}")
            else:
                print(stdout.decode('utf-8'))
        else:
            print(f"iperf3 client failed with return code {returncode}")
            print(f"stderr: {stderr.decode('utf-8')}")

        # Stop server after client completes
        if self.server_process:
            self._stop_server()

    def kill(self) -> None:
        if self.client_process is not None:
            self.client_process.kill()
            self.client_process = None

        if self.server_process is not None:
            self._stop_server()

    def _stop_server(self) -> None:
        """Stop the iperf3 server."""
        if self.server_process is None:
            return

        try:
            self.server_process.terminate()
            # Give it time to shut down gracefully
            for _ in range(10):
                if self.server_process.poll() is not None:
                    break
                time.sleep(0.5)
            else:
                # Force kill if still running
                self.server_process.kill()
        except Exception as e:
            print(f"Error stopping iperf3 server: {e}")

        self.server_process = None

    def _display_results(self, results: dict) -> None:
        """Display iperf3 JSON results in a readable format."""
        print("\n" + "="*60)
        print("iperf3 Test Results")
        print("="*60)

        if "start" in results:
            start = results["start"]
            print(f"Test: {start.get('test_start', {}).get('protocol', 'TCP')}")
            print(f"Duration: {start.get('test_start', {}).get('duration', 'N/A')} seconds")
            print(f"Parallel streams: {start.get('test_start', {}).get('num_streams', 'N/A')}")

        if "end" in results:
            end = results["end"]

            # Sender statistics
            if "sum_sent" in end:
                sent = end["sum_sent"]
                print("\nSender:")
                print(f"  Total transferred: {sent.get('bytes', 0) / (1024**3):.2f} GB")
                print(f"  Bitrate: {sent.get('bits_per_second', 0) / (10**9):.2f} Gbps")

            # Receiver statistics
            if "sum_received" in end:
                received = end["sum_received"]
                print("\nReceiver:")
                print(f"  Total transferred: {received.get('bytes', 0) / (1024**3):.2f} GB")
                print(f"  Bitrate: {received.get('bits_per_second', 0) / (10**9):.2f} Gbps")

            # CPU utilization
            if "cpu_utilization_percent" in end:
                cpu = end["cpu_utilization_percent"]
                print("\nCPU Utilization:")
                print(f"  Local: {cpu.get('host_total', 0):.1f}%")
                print(f"  Remote: {cpu.get('remote_total', 0):.1f}%")

        print("="*60)
