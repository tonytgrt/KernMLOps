#!/bin/bash
BENCHMARK_DIR_NAME="kernmlops-benchmark"
BENCHMARK_DIR="${BENCHMARK_DIR:-$HOME/$BENCHMARK_DIR_NAME}"
NGINXWRK_DIR="$BENCHMARK_DIR/nginxwrk"
WRK_DIR="$NGINXWRK_DIR/wrk"

echo "Installing Nginx+Wrk benchmark..."

# Install nginx if not already installed
if ! command -v nginx &>/dev/null; then
    echo "Installing nginx..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            sudo apt-get update
            sudo apt-get install -y nginx
        elif [ -f /etc/redhat-release ]; then
            sudo dnf install -y nginx
        else
            echo "Unsupported Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &>/dev/null; then
            brew install nginx
        else
            echo "Please install Homebrew first"
            exit 1
        fi
    else
        echo "Unsupported operating system: $OSTYPE"
        exit 1
    fi
fi

# Create benchmark directory
mkdir -p "$WRK_DIR"

# Install wrk
if [ ! -f "$WRK_DIR/wrk" ] && ! command -v wrk &>/dev/null; then
    echo "Building wrk from source..."

    # Install dependencies
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            sudo apt-get install -y build-essential libssl-dev git
        elif [ -f /etc/redhat-release ]; then
            sudo dnf groupinstall -y "Development Tools"
            sudo dnf install -y openssl-devel git
        fi
    fi

    # Clone and build wrk
    cd "$NGINXWRK_DIR"
    git clone --depth=1 https://github.com/wg/wrk.git wrk-source
    cd wrk-source
    make
    cp wrk "$WRK_DIR/"
    cd ..
    rm -rf wrk-source

    echo "wrk installed to $WRK_DIR/wrk"
else
    echo "wrk is already installed"
fi

# Verify installations
echo ""
echo "Verification:"
echo "============="
nginx -v 2>&1
if [ -f "$WRK_DIR/wrk" ]; then
    "$WRK_DIR/wrk" --version
elif command -v wrk &>/dev/null; then
    wrk --version
fi

echo ""
echo "Nginx+Wrk installation complete!"
echo "Note: The benchmark will start its own nginx instance on port 8080"
