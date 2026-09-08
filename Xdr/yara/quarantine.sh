#!/usr/bin/env bash
# ==============================================================================
# SOC & Wazuh Active Response: quarantine.sh (Linux)
# Quarantines suspicious files to /var/ossec/quarantine/ with 0000 permissions
# ==============================================================================

LOG_FILE="/var/ossec/logs/active-responses.log"
QUARANTINE_DIR="/var/ossec/quarantine"

mkdir -p "$QUARANTINE_DIR"
chmod 700 "$QUARANTINE_DIR"

read -r INPUT_JSON

FILEPATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path // .parameters.extra_args[0] // empty')

if [ -z "$FILEPATH" ] || [ "$FILEPATH" == "null" ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine.sh: [ERROR] No valid file path provided" >> "$LOG_FILE"
    exit 0
fi

if [ ! -f "$FILEPATH" ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine.sh: [WARN] File not found: $FILEPATH" >> "$LOG_FILE"
    exit 0
fi

FILENAME=$(basename "$FILEPATH")
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
DEST="$QUARANTINE_DIR/${TIMESTAMP}_${FILENAME}"

SHA256=$(sha256sum "$FILEPATH" | awk '{print $1}')
mv -f "$FILEPATH" "$DEST" 2>/dev/null
chmod 0000 "$DEST" 2>/dev/null

echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine.sh: [QUARANTINED] file=$FILEPATH dest=$DEST sha256=$SHA256" >> "$LOG_FILE"
exit 0
