#!/bin/bash

# Exit on any error
set -e

# Compile the application
echo "Compiling session-mimic..."
go build -ldflags="-s -w" -o session-mimic main.go

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install jq to run this script."
    echo "However, the request will still be made. Falling back to grep (less reliable)."
    ./session-mimic -debug -url=https://tls.peet.ws/api/all 2> debug.log > response.json
    cat debug.log
    echo "ja3_hash:" $(grep -o '"ja3_hash": *"[^"]*"' response.json | cut -d'"' -f4)
    echo "user_agent:" $(grep -o '"user_agent": *"[^"]*"' response.json | cut -d'"' -f4)
    echo "http2:" $(grep -o '"akamai_fingerprint": *"[^"]*"' response.json | cut -d'"' -f4)
    rm debug.log response.json
    exit 0
fi

# Run the command, save stdout to response.json, and let stderr pass through to console
echo "Running session-mimic against https://tls.peet.ws/api/all..."
./session-mimic -debug -url=https://tls.peet.ws/api/all > response.json

# Parse the JSON and display the relevant information
echo ""
echo "--- Fingerprint Results ---"
echo "JA3 Hash:   $(cat response.json | jq -r '.tls.ja3_hash')"
echo "HTTP2:      $(cat response.json | jq -r '.http2.akamai_fingerprint')"
echo "User-Agent: $(cat response.json | jq -r '.user_agent')"
echo "---------------------------"

# Clean up
rm response.json
