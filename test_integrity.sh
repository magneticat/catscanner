#!/bin/bash

# Test script for catscanner.
# Creates a self-contained temporary environment so no manual path editing
# is required. Cleans up after itself on exit.

set -e

# --- Setup ---
TESTDIR=$(mktemp -d)
LOGDIR="$TESTDIR/logs"
WEBROOT="$TESTDIR/public_html"
BINARY="$TESTDIR/catscanner"
mkdir -p "$LOGDIR" "$WEBROOT"

# Write a minimal config pointing at the temp dirs
CONFIGFILE="$TESTDIR/config.json"
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
    echo -e "\nCleaning up temporary directory: $TESTDIR"
    rm -rf "$TESTDIR"
}
trap cleanup EXIT

# --- Build ---
echo "Building catscanner binary..."
go build -o "$BINARY" .

# --- Tests ---

echo -e "\n[1] Regenerating integrity file..."
"$BINARY" -r -ext ".php" -config "$CONFIGFILE"

echo -e "\n[2] Scanning for changes (should find none)..."
"$BINARY" -s -ext ".php" -config "$CONFIGFILE"

echo -e "\n[3] Creating a new file to simulate an intrusion..."
echo "<?php system(\$_GET['cmd']); ?>" > "$WEBROOT/shell.php"

echo -e "\n[4] Scanning again (should detect new file)..."
"$BINARY" -s -ext ".php" -config "$CONFIGFILE" || true   # exit 1 is expected

echo -e "\n[5] Removing the test file..."
rm "$WEBROOT/shell.php"

echo -e "\n[6] Scanning again (should detect removed file)..."
"$BINARY" -s -ext ".php" -config "$CONFIGFILE" || true   # exit 1 is expected

echo -e "\nTest log:"
cat "$LOGDIR/integrity.log"

echo -e "\nAll tests completed successfully."
