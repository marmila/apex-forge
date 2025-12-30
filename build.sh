#!/bin/bash
# Multi-platform build script for Shodan Intelligence Sentinel

# Stop execution if any command fails
set -e

# Configuration - Update with your actual registry
IMAGE_NAME="ghcr.io/marmila/apex-forge"
VERSION="3.0.0"

# Platforms to build for (Optimized for modern 64-bit clusters like k3s)
PLATFORMS="linux/amd64,linux/arm64"

echo "--------------------------------------------------------"
echo "Building Shodan Intelligence Sentinel v${VERSION}"
echo "Platforms: ${PLATFORMS}"
echo "--------------------------------------------------------"

# Ensure buildx is ready
docker buildx create --use --name sentinel-builder || true

# Build and push using Docker Buildx
docker buildx build \
    --platform ${PLATFORMS} \
    --tag ${IMAGE_NAME}:${VERSION} \
    --tag ${IMAGE_NAME}:latest \
    --push .

echo "--------------------------------------------------------"
echo "Build and Push completed successfully!"
echo "Image: ${IMAGE_NAME}:${VERSION}"
echo "--------------------------------------------------------"