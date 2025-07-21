import os
import signal
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
class NginxWrkConfig(ConfigBase):
    # Nginx configuration
    nginx_port: int = 8080
    nginx_workers: int = 4
    nginx_root: str = ""  # Will be set to benchmark_dir/nginx/html if empty

    # Wrk configuration
    wrk_threads: int = 4
    wrk_connections: int = 400
    wrk_duration: str = "30s"
    wrk_timeout: str = "30s"

    # Request configuration
    request_path: str = "/index.html"
    request_rate: int = 0  # 0 means no rate limit


class NginxWrkBenchmark(Benchmark):
    @classmethod
    def name(cls) -> str:
        return "nginxwrk"

    @classmethod
    def default_config(cls) -> ConfigBase:
        return NginxWrkConfig()

    @classmethod
    def from_config(cls, config: ConfigBase) -> "Benchmark":
        generic_config = cast(GenericBenchmarkConfig, getattr(config, "generic"))
        nginxwrk_config = cast(NginxWrkConfig, getattr(config, cls.name()))
        return NginxWrkBenchmark(generic_config=generic_config, config=nginxwrk_config)

    def __init__(self, *, generic_config: GenericBenchmarkConfig, config: NginxWrkConfig):
        self.generic_config = generic_config
        self.config = config
        self.benchmark_dir = self.generic_config.get_benchmark_dir() / "nginxwrk"
        self.nginx_dir = self.benchmark_dir / "nginx"
        self.wrk_dir = self.benchmark_dir / "wrk"
        self.nginx_process: subprocess.Popen | None = None
        self.wrk_process: subprocess.Popen | None = None

    def is_configured(self) -> bool:
        # Check if both nginx and wrk are available
        nginx_available = subprocess.run(
            ["which", "nginx"], capture_output=True
        ).returncode == 0

        wrk_available = (self.wrk_dir / "wrk").exists() or subprocess.run(
            ["which", "wrk"], capture_output=True
        ).returncode == 0

        return nginx_available and wrk_available

    def setup(self) -> None:
        if self.nginx_process is not None or self.wrk_process is not None:
            raise BenchmarkRunningError()

        # Create nginx directories
        self.nginx_dir.mkdir(parents=True, exist_ok=True)
        (self.nginx_dir / "html").mkdir(exist_ok=True)
        (self.nginx_dir / "logs").mkdir(exist_ok=True)
        (self.nginx_dir / "temp").mkdir(exist_ok=True)

        # Create a test HTML file
        html_content = """<!DOCTYPE html>
<html>
<head><title>Nginx Benchmark</title></head>
<body>
<h1>Nginx HTTP Benchmark</h1>
<p>This page is used for benchmarking TCP performance with wrk.</p>
<!-- Adding some content to make the page more realistic -->
""" + "<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 100 + """
</body>
</html>"""

        with open(self.nginx_dir / "html" / "index.html", "w") as f:
            f.write(html_content)

        # Create nginx configuration
        nginx_conf = f"""
worker_processes {self.config.nginx_workers};
error_log {self.nginx_dir}/logs/error.log;
pid {self.nginx_dir}/nginx.pid;

events {{
    worker_connections 1024;
    use epoll;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log {self.nginx_dir}/logs/access.log;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;

    server {{
        listen {self.config.nginx_port};
        server_name localhost;

        root {self.nginx_dir}/html;
        index index.html;

        location / {{
            try_files $uri $uri/ =404;
        }}
    }}
}}
"""

        with open(self.nginx_dir / "nginx.conf", "w") as f:
            f.write(nginx_conf)

        # Start nginx
        print(f"Starting nginx on port {self.config.nginx_port}...")
        self.nginx_process = subprocess.Popen([
            "nginx",
            "-c", str(self.nginx_dir / "nginx.conf"),
            "-p", str(self.nginx_dir)
        ])

        # Wait for nginx to start
        time.sleep(2)

        # Verify nginx is running
        if self.nginx_process.poll() is not None:
            raise BenchmarkError("Failed to start nginx")

        # Test if nginx is responding
        test_result = subprocess.run([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://localhost:{self.config.nginx_port}/"
        ], capture_output=True, text=True)

        if test_result.stdout != "200":
            self.kill()
            raise BenchmarkError(f"Nginx not responding correctly: {test_result.stdout}")

        print("Nginx started successfully")
        self.generic_config.generic_setup()

    def run(self) -> None:
        if self.wrk_process is not None:
            raise BenchmarkRunningError()

        if self.nginx_process is None:
            raise BenchmarkError("Nginx not started. Run setup() first.")

        # Determine wrk executable path
        wrk_exe = "wrk"
        if (self.wrk_dir / "wrk").exists():
            wrk_exe = str(self.wrk_dir / "wrk")

        # Build wrk command
        wrk_cmd = [
            wrk_exe,
            "-t", str(self.config.wrk_threads),
            "-c", str(self.config.wrk_connections),
            "-d", self.config.wrk_duration,
            "--timeout", self.config.wrk_timeout,
            "--latency",
            f"http://localhost:{self.config.nginx_port}{self.config.request_path}"
        ]

        # Add rate limiting if specified
        if self.config.request_rate > 0:
            # Use wrk2 style rate limiting if available
            wrk_cmd.extend(["-R", str(self.config.request_rate)])

        print("Starting wrk benchmark...")
        print(f"Command: {' '.join(wrk_cmd)}")

        self.wrk_process = subprocess.Popen(wrk_cmd)

    def poll(self) -> int | None:
        if self.wrk_process is None:
            raise BenchmarkNotRunningError()
        return self.wrk_process.poll()

    def wait(self) -> None:
        if self.wrk_process is None:
            raise BenchmarkNotRunningError()
        self.wrk_process.wait()

        # Clean up nginx after wrk completes
        if self.nginx_process:
            self._stop_nginx()

    def kill(self) -> None:
        if self.wrk_process is not None:
            self.wrk_process.kill()
            self.wrk_process = None

        if self.nginx_process is not None:
            self._stop_nginx()

    def _stop_nginx(self) -> None:
        """Gracefully stop nginx."""
        if self.nginx_process is None:
            return

        try:
            # Read nginx PID from file
            pid_file = self.nginx_dir / "nginx.pid"
            if pid_file.exists():
                with open(pid_file, "r") as f:
                    nginx_pid = int(f.read().strip())

                # Send SIGTERM for graceful shutdown
                os.kill(nginx_pid, signal.SIGTERM)

                # Wait for nginx to shut down
                for _ in range(10):
                    try:
                        os.kill(nginx_pid, 0)  # Check if process exists
                        time.sleep(0.5)
                    except ProcessLookupError:
                        break
                else:
                    # Force kill if still running
                    os.kill(nginx_pid, signal.SIGKILL)
        except Exception as e:
            print(f"Error stopping nginx: {e}")
            if self.nginx_process:
                self.nginx_process.kill()

        self.nginx_process = None
