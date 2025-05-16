#!/bin/bash
set -e

echo "======================================================"
echo "  ZK Project Server/Client Demo"
echo "======================================================"

echo "Building project..."
cargo build -p server -p client

echo -e "\n\nStep 1: Starting the server..."
# Start the server in the background
cargo run -p server &
SERVER_PID=$!

# Give the server time to start
sleep 2

echo -e "\n\nStep 2: Registering a new user..."
cargo run -p client -- register

echo -e "\n\nStep 3: Verifying stored credentials..."
cargo run -p client -- verify --user-id 12345

echo -e "\n\nStep 4: Stopping the server..."
kill $SERVER_PID

echo -e "\n\nStep 5: Verifying credentials while server is offline..."
echo "(This demonstrates that verification works without the server)"
cargo run -p client -- verify --user-id 12345

echo -e "\n\nDemo completed successfully!" 