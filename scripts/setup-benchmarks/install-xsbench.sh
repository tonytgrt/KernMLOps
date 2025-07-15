#!/bin/bash
BENCHMARK_DIR_NAME="kernmlops-benchmark"
BENCHMARK_DIR="${BENCHMARK_DIR:-$HOME/$BENCHMARK_DIR_NAME}"
XSBENCH_DIR="$BENCHMARK_DIR/xsbench"

if [ -d $XSBENCH_DIR ]; then
    echo "XSBench already installed at: $XSBENCH_DIR"
    exit 0
fi

# Clone and build XSBench
git clone https://github.com/ANL-CESAR/XSBench.git $XSBENCH_DIR
cd $XSBENCH_DIR
make
