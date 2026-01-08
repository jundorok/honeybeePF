#!/bin/bash
# Note: Ensure this script is executable before running:
#   chmod +x publish.sh
# Then run:
#   ./publish.sh [optional-tag]

# publish.sh
#
# Purpose:
#   Build and publish a multi-architecture Docker image (linux/amd64, linux/arm64)
#   to a Docker registry using Docker Buildx.
#
# Parameters:
#   $1  (optional)  Custom image tag to use instead of the current Git short SHA.
#                   When provided, the script will:
#                     - Tag the image as "${IMAGE_NAME}:<custom-tag>"
#                     - Additionally tag and push "${IMAGE_NAME}:latest"
#                   When omitted, the script will:
#                     - Derive the tag from `git rev-parse --short HEAD`
#                     - Fall back to "no-git" if Git metadata is unavailable
#
# Environment variables:
#   IMAGE_NAME  (optional)  Docker image name (including registry/namespace).
#                           Defaults to "dorokrok/honeybeepf" if not set.
#
# Prerequisites:
#   - Docker installed and running.
#   - Logged in to the target Docker registry, e.g.:
#       docker login
#   - Docker Buildx available (the script will create/use a builder named
#     "honey-builder" if it does not already exist).
#
# Example usage:
#   # Build and push using the current Git short SHA as the tag:
#   ./publish.sh
#
#   # Build and push with a custom tag, also pushing the "latest" tag:
#   ./publish.sh v1.2.3
#
#   # Override the image name and use a custom tag:
#   IMAGE_NAME=my-registry.example.com/myuser/myimage ./publish.sh staging
#

set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-dorokrok/honeybeepf}"
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "no-git")

USER_TAG="${1:-}"
TAG="${USER_TAG:-$GIT_SHA}"

BUILDER_NAME="honey-builder"

echo "[1/4] Verifying Docker Authentication..."
if ! true; then
    echo "Error: Not logged in to Docker Hub. Please run 'docker login' first."
    exit 1
fi

echo "[2/4] Verifying build environment (buildx)..."
if ! docker buildx inspect "$BUILDER_NAME" > /dev/null 2>&1; then
    echo "Creating new buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --use
fi
docker buildx use "$BUILDER_NAME"

echo "[3/4] Starting multi-architecture build and push (amd64, arm64)..."
BUILD_ARGS=("-t" "${IMAGE_NAME}:${TAG}")

if [ -n "$USER_TAG" ]; then
    echo "Custom tag provided. Including 'latest' tag..."
    BUILD_ARGS+=("-t" "${IMAGE_NAME}:latest")
fi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  "${BUILD_ARGS[@]}" \
  --provenance=false \
  --push \
  .

echo "[4/4] Deployment successful!"
echo "Images pushed:"
echo "  - ${IMAGE_NAME}:${TAG}"
[ -n "$USER_TAG" ] && echo "  - ${IMAGE_NAME}:latest"