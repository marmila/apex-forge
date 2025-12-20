#!/bin/bash
# Multi-platform build script for Shodan Security Monitor

set -e

IMAGE_NAME="your-registry/shodan-sec-monitor"
VERSION="1.0.0"

# Platforms to build for
PLATFORMS="linux/amd64,linux/arm64,linux/arm/v7"

echo "Building Shodan Security Monitor for platforms: $PLATFORMS"

# Build using Docker Buildx
docker buildx build \
    --platform ${PLATFORMS} \
    --tag ${IMAGE_NAME}:${VERSION} \
    --tag ${IMAGE_NAME}:latest \
    --push .  # Remove --push if you don't want to push immediately

echo "Build completed successfully!"
