#!/bin/bash

# Test script for integrity.go

# Make sure logs directory exists
mkdir -p /home/sammyboy/logs

# Build the binary first
echo "Building integrity binary..."
go build -o integrity integrity.go
chmod +x integrity

# First, regenerate the integrity file
echo "Regenerating integrity file..."
./integrity -r -ext ".php,.html,.js"

# Wait a moment
sleep 1

# Then scan for changes (should find none since we just regenerated)
echo -e "\nScanning for changes (should find none)..."
./integrity -s -ext ".php,.html,.js"

# Create a test file to simulate a change
echo -e "\nCreating a test file to simulate a change..."
echo "<?php echo 'Test file'; ?>" > /home/sammyboy/public_html/test_integrity.php

# Scan again to detect the new file
echo -e "\nScanning again (should detect the new file)..."
./integrity -s -ext ".php,.html,.js"

# Clean up the test file
echo -e "\nCleaning up test file..."
rm /home/sammyboy/public_html/test_integrity.php

# Scan one more time to detect the removed file
echo -e "\nScanning again (should detect the removed file)..."
./integrity -s -ext ".php,.html,.js"

# Clean up the binary
echo -e "\nCleaning up..."
rm integrity

echo -e "\nTest completed. Check the log file at /home/sammyboy/logs/integrity.log" 