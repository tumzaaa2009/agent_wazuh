#!/bin/bash
# =============================================================
# YARA Active Response สำหรับ Linux Agent (Docker-based)
# ติดตั้งที่: /var/ossec/active-response/bin/yara.sh
# =============================================================

LOGFILE="/var/ossec/logs/active-responses.log"

echo "$(date -Is) yara.sh: [DEBUG] Script triggered." >> "$LOGFILE"

read INPUT_JSON
echo "$(date -Is) yara.sh: [DEBUG] Raw Input: $INPUT_JSON" >> "$LOGFILE"

# ดึง path ของไฟล์จาก FIM event
FILEPATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path')
if [ "$FILEPATH" == "null" ] || [ -z "$FILEPATH" ]; then
    echo "$(date -Is) yara.sh: [DEBUG] No path in syscheck, checking extra_args." >> "$LOGFILE"
    FILEPATH=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[0]')
fi

# Validate
if [ -z "$FILEPATH" ] || [ "$FILEPATH" == "null" ]; then
    echo "$(date -Is) yara.sh: [ERROR] No valid file path parsed from input." >> "$LOGFILE"

    logger -p local6.err -t wazuh_yara -- \
    "{\"event\":\"yara\",\"action\":\"error\",\"level\":\"ERROR\",\"reason\":\"no_file_path\"}"

    exit 0
fi

if [ ! -f "$FILEPATH" ]; then
    echo "$(date -Is) yara.sh: [ERROR] File not found on disk path=$FILEPATH" >> "$LOGFILE"

    logger -p local6.err -t wazuh_yara -- \
    "{\"event\":\"yara\",\"action\":\"error\",\"level\":\"ERROR\",\"reason\":\"file_not_found\",\"file\":\"$FILEPATH\"}"

    exit 0
fi

FILENAME=$(basename "$FILEPATH")
ABS_FILE=$(realpath "$FILEPATH")

echo "$(date -Is) yara.sh: [INFO] SCAN_START file=$ABS_FILE" >> "$LOGFILE"

YARA_RULES="/var/ossec/etc/shared/yara_rules.yar"
if [ ! -f "$YARA_RULES" ]; then
    YARA_RULES="/var/ossec/etc/shared/default/yara_rules.yar"

    if [ ! -f "$YARA_RULES" ]; then
        echo "$(date -Is) yara.sh: [ERROR] YARA rules not found." >> "$LOGFILE"

        logger -p local6.err -t wazuh_yara -- \
        "{\"event\":\"yara\",\"action\":\"error\",\"level\":\"ERROR\",\"reason\":\"rules_not_found\"}"

        exit 1
    fi
fi

echo "$(date -Is) yara.sh: [INFO] SCAN_START file=$ABS_FILE. Waiting 2s for IO sync..." >> "$LOGFILE"

sleep 2

echo "$(date -Is) yara.sh: [DEBUG] Executing Docker YARA container..." >> "$LOGFILE"

YARA_RESULT=$(docker run --rm \
    -u root \
    -v "$ABS_FILE":/scan/target_file:ro \
    -v "$YARA_RULES":/opt/yara/rules/yara_rules.yar:ro \
    --entrypoint yara \
    cincan/yara:latest \
    -r /opt/yara/rules/yara_rules.yar /scan/target_file 2>&1)

DOCKER_EXIT_CODE=$?

echo "$(date -Is) yara.sh: [DEBUG] Docker execution finished. Exit Code: $DOCKER_EXIT_CODE" >> "$LOGFILE"

CLEAN_YARA_RESULT=$(echo "$YARA_RESULT" | grep -vi warning)

if [ -n "$CLEAN_YARA_RESULT" ] && [ "$DOCKER_EXIT_CODE" -eq 0 ]; then

    echo "$(date -Is) yara.sh: [WARN] MALWARE_DETECTED file=$FILENAME result=$CLEAN_YARA_RESULT" >> "$LOGFILE"

    SHA256=$(sha256sum "$ABS_FILE" | awk '{print $1}')
    MD5=$(md5sum "$ABS_FILE" | awk '{print $1}')

    echo "$(date -Is) yara.sh: [DEBUG] Hashes computed. SHA256=$SHA256" >> "$LOGFILE"

    YARA_CLEAN_FORMAT=$(echo "$CLEAN_YARA_RESULT" | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')

    logger -p local6.notice -t wazuh_yara -- \
    "{\"event\":\"yara\",\"action\":\"detect\",\"level\":\"INFO\",\"rule\":\"$YARA_CLEAN_FORMAT\",\"file\":\"$ABS_FILE\",\"sha256\":\"$SHA256\",\"md5\":\"$MD5\"}"

    rm -f "$ABS_FILE"

    if [ ! -f "$ABS_FILE" ]; then

        echo "$(date -Is) yara.sh: [DEBUG] File successfully deleted." >> "$LOGFILE"

        echo "$(date -Is) wazuh-yara: src=$ABS_FILE dest=DELETED sha256=$SHA256 md5=$MD5 yara_match=$YARA_CLEAN_FORMAT cdb_format=$SHA256:$YARA_CLEAN_FORMAT" >> "$LOGFILE"
    else

        echo "$(date -Is) yara.sh: [ERROR] Failed to delete file." >> "$LOGFILE"

        logger -p local6.err -t wazuh_yara -- \
        "{\"event\":\"yara\",\"action\":\"delete_failed\",\"level\":\"ERROR\",\"rule\":\"$YARA_CLEAN_FORMAT\",\"file\":\"$ABS_FILE\",\"sha256\":\"$SHA256\",\"md5\":\"$MD5\"}"

    fi

else

    if [ "$DOCKER_EXIT_CODE" -ne 0 ]; then

        YARA_ERR_CLEAN=$(echo "$YARA_RESULT" | tr '\n' ' ' | sed 's/  */ /g')

        echo "$(date -Is) yara.sh: [ERROR] YARA scan failed. Result: $YARA_RESULT" >> "$LOGFILE"

        logger -p local6.err -t wazuh_yara -- \
        "{\"event\":\"yara\",\"action\":\"scan_error\",\"level\":\"ERROR\",\"reason\":\"$YARA_ERR_CLEAN\",\"file\":\"$ABS_FILE\"}"

    else

        echo "$(date -Is) yara.sh: [INFO] CLEAN file=$FILENAME" >> "$LOGFILE"

        logger -p local6.info -t wazuh_yara -- \
        "{\"event\":\"yara\",\"action\":\"clean\",\"level\":\"INFO\",\"file\":\"$ABS_FILE\"}"

    fi

fi

echo "$(date -Is) yara.sh: [DEBUG] Script completed." >> "$LOGFILE"
exit 0