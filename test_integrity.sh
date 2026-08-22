#!/bin/bash

# Integration test for catscanner.
# Creates a self-contained temporary environment, asserts exit codes and
# output, and cleans up after itself on exit.

set -euo pipefail

TESTDIR=$(mktemp -d)
LOGDIR="$TESTDIR/logs"
WEBROOT="$TESTDIR/public_html"
BINARY="$TESTDIR/catscanner"
CONFIGFILE="$TESTDIR/config.json"
mkdir -p "$LOGDIR" "$WEBROOT"

write_config() {
    cat > "$CONFIGFILE" <<EOF
{
    "target_dir": "$WEBROOT",
    "integrity_file": "$LOGDIR/integrity.txt",
    "log_file": "$LOGDIR/integrity.log",
    "email": "",
    "email_method": "",
    "exclude_dirs": $1,
    "whitelist": $2
}
EOF
}

run_expect() {
    local expected=$1
    local label=$2
    shift 2
    local output
    local actual=0
    set +e
    output=$("$@" 2>&1)
    actual=$?
    set -e
    echo "$output"
    if [ "$actual" -ne "$expected" ]; then
        echo "FAIL [$label]: expected exit $expected, got $actual"
        return 1
    fi
    echo "OK [$label]: exit $expected"
    LAST_OUT=$output
}

contains() {
    local label=$1
    local needle=$2
    if ! printf '%s' "$LAST_OUT" | grep -Fq "$needle"; then
        echo "FAIL [$label]: output did not contain: $needle"
        echo "$LAST_OUT"
        return 1
    fi
    echo "OK [$label]: found '$needle'"
}

file_lacks() {
    local label=$1
    local needle=$2
    local file=$3
    if grep -Fq "$needle" "$file"; then
        echo "FAIL [$label]: $file unexpectedly contained: $needle"
        return 1
    fi
    echo "OK [$label]: $file does not contain '$needle'"
}

cleanup() {
    echo
    echo "Cleaning up temporary directory: $TESTDIR"
    rm -rf "$TESTDIR"
}
trap cleanup EXIT

LAST_OUT=""
write_config '[]' '[]'
echo "<?php echo 'Hello'; ?>" > "$WEBROOT/index.php"

echo "Building catscanner binary..."
go build -o "$BINARY" .

echo
echo "[1] Regenerating integrity file (clean baseline)..."
run_expect 0 "regen" "$BINARY" -r -ext ".php" -config "$CONFIGFILE"
contains "regen message" "Integrity file regenerated"
test -f "$LOGDIR/integrity.txt"

echo
echo "[2] Scanning for changes (should find none)..."
run_expect 0 "clean scan" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
contains "clean scan message" "No changes detected."

echo
echo "[3] Creating a new file to simulate an intrusion..."
echo "<?php echo 'new'; ?>" > "$WEBROOT/new-file.php"

echo
echo "[4] Scanning again (should detect new file)..."
run_expect 1 "new file" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
contains "new file summary" "1 new"

echo
echo "[5] Modifying an existing file..."
rm "$WEBROOT/new-file.php"
echo "<?php echo 'Hello'; ?>" > "$WEBROOT/index.php"
run_expect 0 "restore after new" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
echo "<?php echo 'changed'; ?>" > "$WEBROOT/index.php"
run_expect 1 "modified" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
contains "modified summary" "1 modified"

echo
echo "[6] Removing a baselined file..."
echo "<?php echo 'Hello'; ?>" > "$WEBROOT/index.php"
echo "<?php echo 'old'; ?>" > "$WEBROOT/old.php"
run_expect 0 "regen with old.php" "$BINARY" -r -ext ".php" -config "$CONFIGFILE"
rm "$WEBROOT/old.php"
run_expect 1 "deleted" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
contains "deleted summary" "1 missing"

echo
echo "[7] Mixed-case extensions..."
echo "<?php echo 'upper'; ?>" > "$WEBROOT/Page.PHP"
run_expect 0 "mixed-case regen" "$BINARY" -r -ext ".php" -config "$CONFIGFILE"
if ! grep -Fq "Page.PHP" "$LOGDIR/integrity.txt"; then
    echo "FAIL [mixed-case]: Page.PHP missing from baseline"
    exit 1
fi
echo "OK [mixed-case]: Page.PHP included in baseline"
run_expect 0 "mixed-case scan" "$BINARY" -s -ext ".PHP" -config "$CONFIGFILE"

echo
echo "[8] Excluded directories..."
mkdir -p "$WEBROOT/internal_data/attachments/nested" \
         "$WEBROOT/internal_data/code_cache" \
         "$WEBROOT/internal_data/temp"
echo "<?php // attach ?>" > "$WEBROOT/internal_data/attachments/file.php"
echo "<?php // nested ?>" > "$WEBROOT/internal_data/attachments/nested/deep.php"
echo "<?php // cache ?>" > "$WEBROOT/internal_data/code_cache/cache.php"
echo "<?php // temp ?>" > "$WEBROOT/internal_data/temp/tmp.php"
write_config '["internal_data/attachments","internal_data/code_cache","internal_data/temp"]' '[]'
run_expect 0 "exclude regen" "$BINARY" -r -ext ".php" -config "$CONFIGFILE"
file_lacks "exclude baseline attachments" "attachments" "$LOGDIR/integrity.txt"
file_lacks "exclude baseline cache" "code_cache" "$LOGDIR/integrity.txt"
file_lacks "exclude baseline temp" "internal_data/temp" "$LOGDIR/integrity.txt"
if ! grep -Fq "index.php" "$LOGDIR/integrity.txt"; then
    echo "FAIL [exclude baseline]: index.php missing"
    exit 1
fi
echo "OK [exclude baseline]: index.php present"

echo "<?php // changed attach ?>" > "$WEBROOT/internal_data/attachments/file.php"
run_expect 0 "exclude changes" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
contains "exclude changes message" "No changes detected."

echo
echo "[9] Removing an exclusion..."
write_config '[]' '[]'
run_expect 1 "remove exclusion" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
contains "remove exclusion new" "new"

echo
echo "[10] Adding an exclusion to an existing baseline..."
run_expect 0 "pre-add regen" "$BINARY" -r -ext ".php" -config "$CONFIGFILE"
if ! grep -Fq "file.php" "$LOGDIR/integrity.txt"; then
    echo "FAIL [pre-add exclusion]: expected attachments file in baseline"
    exit 1
fi
write_config '["internal_data/attachments","internal_data/code_cache","internal_data/temp"]' '[]'
run_expect 0 "add exclusion" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
contains "add exclusion clean" "No changes detected."

echo
echo "[11] Whitelist still scans but does not notify..."
mkdir -p "$WEBROOT/cache"
echo "<?php echo 'cache'; ?>" > "$WEBROOT/cache/foo.php"
write_config '[]' '["cache/*"]'
run_expect 0 "whitelist regen" "$BINARY" -r -ext ".php" -config "$CONFIGFILE"
if ! grep -Fq "foo.php" "$LOGDIR/integrity.txt"; then
    echo "FAIL [whitelist baseline]: cache/foo.php should still be scanned"
    exit 1
fi
echo "OK [whitelist baseline]: cache/foo.php present"
echo "<?php echo 'cache2'; ?>" > "$WEBROOT/cache/foo.php"
run_expect 0 "whitelist scan" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"
contains "whitelist summary" "whitelisted"

echo
echo "[12] Invalid exclusion path..."
write_config '["../outside"]' '[]'
run_expect 2 "invalid exclude" "$BINARY" -s -ext ".php" -config "$CONFIGFILE"

echo
echo "[13] Invalid extension and mode flags..."
write_config '[]' '[]'
run_expect 2 "invalid ext" "$BINARY" -r -ext ",, ," -config "$CONFIGFILE"
run_expect 2 "both modes" "$BINARY" -s -r -config "$CONFIGFILE"
run_expect 2 "no mode" "$BINARY" -config "$CONFIGFILE"

echo
echo "[14] Configuration load error..."
run_expect 2 "missing config" "$BINARY" -s -config "$TESTDIR/missing.json"

echo
echo "Test log:"
if [ -f "$LOGDIR/integrity.log" ]; then
    cat "$LOGDIR/integrity.log"
fi

echo
echo "All tests completed successfully."
