#!/bin/bash

# Test script for catscanner.
# Creates a self-contained temporary environment so no manual path editing
# is required. Cleans up after itself on exit.

set -e

# --- Setup ---
TMPDIR=$(mktemp -d)
LOGDIR="$TMPDIR/logs"
WEBROOT="$TMPDIR/public_html"
mkdir -p "$LOGDIR" "$WEBROOT"

# Write a minimal config pointing at the temp dirs
CONFIGFILE="$TMPDIR/config.json"
cat > "$CONFIGFILE" <<EOF
{
    "target_dir": "$WEBROOT",
    "integrity_file": "$LOGDIR/integrity.txt",
    "log_file": "$LOGDIR/integrity.log",
    "email": "",
    "email_method": ""
}
EOF

# Seed the web root with a sample PHP file
echo "<?php echo 'Hello'; ?>" > "$WEBROOT/index.php"

cleanup() {
    echo -e "\nCleaning up temporary directory: $TMPDIR"
    rm -rf "$TMPDIR"
    rm -f ./catscanner
}
trap cleanup EXIT

# --- Build ---
echo "Building catscanner binary..."
go build -o catscanner .

# --- Tests ---

echo -e "\n[1] Regenerating integrity file..."
./catscanner -r -ext ".php" -config "$CONFIGFILE"

echo -e "\n[2] Scanning for changes (should find none)..."
./catscanner -s -ext ".php" -config "$CONFIGFILE"

echo -e "\n[3] Creating a new file to simulate an intrusion..."
echo "<?php system(\$_GET['cmd']); ?>" > "$WEBROOT/shell.php"

echo -e "\n[4] Scanning again (should detect new file)..."
./catscanner -s -ext ".php" -config "$CONFIGFILE" || true   # exit 1 is expected

echo -e "\n[5] Removing the test file..."
rm "$WEBROOT/shell.php"

echo -e "\n[6] Scanning again (should detect removed file)..."
./catscanner -s -ext ".php" -config "$CONFIGFILE" || true   # exit 1 is expected

echo -e "\nTest log:"
cat "$LOGDIR/integrity.log"

echo -e "\nAll tests completed successfully."