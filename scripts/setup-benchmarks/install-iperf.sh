#!/bin/bash
BENCHMARK_DIR_NAME="kernmlops-benchmark"
BENCHMARK_DIR="${BENCHMARK_DIR:-$HOME/$BENCHMARK_DIR_NAME}"
IPERF_DIR="$BENCHMARK_DIR/iperf"

echo "Installing iperf3 benchmark..."

# Create benchmark directory
mkdir -p "$IPERF_DIR"

# Install iperf3
if ! command -v iperf3 &>/dev/null; then
    echo "Installing iperf3..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            sudo apt-get update
            sudo apt-get install -y iperf3
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install -y iperf3
        else
            echo "Unsupported Linux distribution"
            echo "Please install iperf3 manually"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &>/dev/null; then
            brew install iperf3
        else
            echo "Please install Homebrew first"
            exit 1
        fi
    else
        echo "Unsupported operating system: $OSTYPE"
        exit 1
    fi
else
    echo "iperf3 is already installed"
fi

# Verify installation
echo ""
echo "Verification:"
echo "============="
iperf3 --version

echo ""
echo "iperf3 installation complete!"
echo "Note: The benchmark will start its own iperf3 server on port 5201"
