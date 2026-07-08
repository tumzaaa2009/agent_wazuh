#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: ./update_version.sh <new_version>"
  echo "Example: ./update_version.sh 1.0.1"
  exit 1
fi

NEW_VERSION=$1

echo "Updating version to $NEW_VERSION..."

# Update version.txt
echo "$NEW_VERSION" > version.txt

# Update index.ts
sed -i "s/const EDGE_VERSION = \".*\";/const EDGE_VERSION = \"$NEW_VERSION\";/" index.ts

echo "Building and restarting Docker container..."
docker compose build
docker compose up -d

echo "✅ Version updated to $NEW_VERSION and container restarted."
echo "Master API is now serving the new version."
