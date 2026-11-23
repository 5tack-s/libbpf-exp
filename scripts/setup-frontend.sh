#!/bin/bash
set -e

cd ~/libbpf-exp/frontend
export PATH="$HOME/bin:$PATH"

echo "Installing frontend dependencies..."
npm install

echo "Building frontend for production..."
npm run build

echo "Frontend built successfully!"
ls -la dist/
