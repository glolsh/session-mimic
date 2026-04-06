#!/bin/bash

# Exit on any error
set -e

MIMIC_BIN="./session-mimic"

if [ ! -f "$MIMIC_BIN" ]; then
    echo "Error: Binary '$MIMIC_BIN' not found."
    echo "Please download the artifact from GitHub Actions first."
    exit 1
fi

chmod +x "$MIMIC_BIN"

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. jq is required for this robust validation script."
    exit 1
fi

echo "Running session-mimic against https://tls.peet.ws/api/all..."

# We need to capture both stdout (JSON response) and stderr (debug logs) separately.
# Create temporary files
STDOUT_FILE=$(mktemp)
STDERR_FILE=$(mktemp)

./session-mimic -debug -url=https://tls.peet.ws/api/all > "$STDOUT_FILE" 2> "$STDERR_FILE"

# Parse Selected Profile from stderr
SELECTED_PROFILE=$(grep -oP "\[DEBUG\] Selected Profile: \K(.*)" "$STDERR_FILE" || true)

# Output captured logs for context
cat "$STDERR_FILE"
echo ""

if [ -z "$SELECTED_PROFILE" ]; then
    echo "Error: Could not extract Selected Profile from stderr."
    cat "$STDERR_FILE"
    rm "$STDOUT_FILE" "$STDERR_FILE"
    exit 1
fi

echo "--- Fingerprint Integrity Check ---"
echo "Target Profile: $SELECTED_PROFILE"

# Extract fields from JSON
DETECTED_UA=$(jq -r '.user_agent' "$STDOUT_FILE")
JA4=$(jq -r '.tls.ja4' "$STDOUT_FILE")
JA3_HASH=$(jq -r '.tls.ja3_hash' "$STDOUT_FILE")
HTTP2_SETTINGS=$(jq -r '.http2.akamai_fingerprint' "$STDOUT_FILE")

echo "Detected UA:    $DETECTED_UA"
echo "JA4:            $JA4"
echo "JA3 Hash:       $JA3_HASH"
echo "HTTP/2:         $HTTP2_SETTINGS"
echo "-----------------------------------"

# 1. Cross-Check Logic (User-Agent Match)
UA_MATCH=false
if [[ "$SELECTED_PROFILE" == *"Chrome_144"* && "$DETECTED_UA" == *"Chrome/144"* ]]; then
    UA_MATCH=true
elif [[ "$SELECTED_PROFILE" == *"Chrome_146"* && "$DETECTED_UA" == *"Chrome/146"* ]]; then
    UA_MATCH=true
elif [[ "$SELECTED_PROFILE" == *"Firefox_147"* && "$DETECTED_UA" == *"Firefox/147"* ]]; then
    UA_MATCH=true
elif [[ "$SELECTED_PROFILE" == *"Firefox_148"* && "$DETECTED_UA" == *"Firefox/148"* ]]; then
    UA_MATCH=true
fi

if [ "$UA_MATCH" = false ]; then
    echo "[CRITICAL] FINGERPRINT MISMATCH DETECTED: Profile $SELECTED_PROFILE does not match User-Agent $DETECTED_UA"
    rm "$STDOUT_FILE" "$STDERR_FILE"
    exit 1
fi

# 2. Verify JA4 is a real browser signature (typically t13 for TLS 1.3)
if [[ ! "$JA4" == t13* ]]; then
    echo "[CRITICAL] FINGERPRINT MISMATCH DETECTED: JA4 signature '$JA4' does not indicate a modern TLS 1.3 browser."
    rm "$STDOUT_FILE" "$STDERR_FILE"
    exit 1
fi

# 3. HTTP/2 Settings Audit
# Check if initial window size looks like a default library instead of browser
# e.g., default Go client might not have settings like 6291456 (Chrome)
if [[ "$HTTP2_SETTINGS" == "" || "$HTTP2_SETTINGS" == "null" ]]; then
    echo "[CRITICAL] FINGERPRINT MISMATCH DETECTED: Missing HTTP/2 settings (Possible HTTP/1.1 downgrade or detection)."
    rm "$STDOUT_FILE" "$STDERR_FILE"
    exit 1
fi

# Print warnings if it looks suspiciously simple (Go default HTTP2 fingerprint is usually very short)
if [[ "$HTTP2_SETTINGS" == "3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s" ]]; then
    echo "[WARNING] HTTP/2 settings match older Go library defaults. May not pass strict DPI."
fi

# Final Check: PSK validation (if applicable based on profile)
if [[ "$SELECTED_PROFILE" == *"PSK"* ]]; then
    if ! grep -q "\[DEBUG\] PSK Extension Enabled" "$STDERR_FILE"; then
         echo "[CRITICAL] FINGERPRINT MISMATCH DETECTED: PSK extension expected but not logged as enabled."
         rm "$STDOUT_FILE" "$STDERR_FILE"
         exit 1
    fi
fi

echo "[OK] Node is invisible. Mimicry integrity 100%."

# Clean up
rm "$STDOUT_FILE" "$STDERR_FILE"
exit 0
