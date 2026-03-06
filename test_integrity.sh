#!/bin/bash

# Test script for catscanner (integrity.go)
# Before running: ensure config.json exists and points to valid target_dir, integrity_file, and log_file.
# Override TARGET_DIR and CONFIG via env if needed; TARGET_DIR must match config.json target_dir.

TARGET_DIR="${TARGET_DIR:-/path/to/your/web/files}"
CONFIG="${CONFIG:-config.json}"

# Ensure target_dir exists for the test file
mkdir -p "$TARGET_DIR"

echo "Building catscanner binary..."
go build -o catscanner integrity.go
chmod +x catscanner

echo "Regenerating integrity file..."
./catscanner -r -ext ".php,.html,.js" -config "$CONFIG"

sleep 1

echo -e "\nScanning for changes (should find none)..."
./catscanner -s -ext ".php,.html,.js" -config "$CONFIG"

echo -e "\nCreating a test file to simulate a change..."
echo "<?php echo 'Test file'; ?>" > "$TARGET_DIR/test_integrity.php"

echo -e "\nScanning again (should detect the new file)..."
./catscanner -s -ext ".php,.html,.js" -config "$CONFIG"

echo -e "\nCleaning up test file..."
rm "$TARGET_DIR/test_integrity.php"

echo -e "\nScanning again (should detect the removed file)..."
./catscanner -s -ext ".php,.html,.js" -config "$CONFIG"

echo -e "\nCleaning up..."
rm catscanner

echo -e "\nTest completed. Check the log file configured in $CONFIG" 