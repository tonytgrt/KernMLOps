#!/bin/bash
BENCHMARK_DIR_NAME="kernmlops-benchmark"
BENCHMARK_DIR="${BENCHMARK_DIR:-$HOME/$BENCHMARK_DIR_NAME}"
XSBENCH_DIR="$BENCHMARK_DIR/xsbench"

if [ -d $XSBENCH_DIR ]; then
    echo "XSBench already installed at: $XSBENCH_DIR"
    exit 0
fi

# Clone XSBench
git clone https://github.com/ANL-CESAR/XSBench.git $XSBENCH_DIR

# Build the openmp-threading version (default CPU version)
cd $XSBENCH_DIR/openmp-threading
make

echo "XSBench installation complete"
