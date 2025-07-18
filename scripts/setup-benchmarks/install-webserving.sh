#!/bin/bash
BENCHMARK_DIR_NAME="kernmlops-benchmark"
BENCHMARK_DIR="${BENCHMARK_DIR:-$HOME/$BENCHMARK_DIR_NAME}"
CLOUDSUITE_DIR="$BENCHMARK_DIR/cloudsuite"

echo "Installing CloudSuite WebServing benchmark..."

# Check if Docker is installed
if ! command -v docker &>/dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Create benchmark directory
mkdir -p "$CLOUDSUITE_DIR"

# Pull all required Docker images
echo "Pulling CloudSuite WebServing Docker images..."
docker pull cloudsuite/web-serving:db_server
docker pull cloudsuite/web-serving:memcached_server
docker pull cloudsuite/web-serving:web_server
docker pull cloudsuite/web-serving:faban_client

# Verify images were pulled successfully
IMAGES=("cloudsuite/web-serving:db_server" "cloudsuite/web-serving:memcached_server" "cloudsuite/web-serving:web_server" "cloudsuite/web-serving:faban_client")
for image in "${IMAGES[@]}"; do
    if ! docker image inspect "$image" &>/dev/null; then
        echo "Failed to pull $image"
        exit 1
    fi
done

echo "CloudSuite WebServing installation complete"
