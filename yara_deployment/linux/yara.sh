#!/bin/bash
# =============================================================
# YARA Active Response สำหรับ Linux Agent (Docker-based)
# ติดตั้งที่: /var/ossec/active-response/bin/yara.sh
# =============================================================

LOGFILE="/var/ossec/logs/active-responses.log"
YARA_RULES="/var/ossec/etc/shared/default/yara_rules.yar"

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
    exit 0
fi

if [ ! -f "$FILEPATH" ]; then
    echo "$(date -Is) yara.sh: [ERROR] File not found on disk path=$FILEPATH" >> "$LOGFILE"
    exit 0
fi

FILENAME=$(basename "$FILEPATH")
ABS_FILE=$(realpath "$FILEPATH")

echo "$(date -Is) yara.sh: [INFO] SCAN_START file=$ABS_FILE" >> "$LOGFILE"

# ตรวจสอบว่ามีไฟล์ Rule อยู่หรือไม่
if [ ! -f "$YARA_RULES" ]; then
    echo "$(date -Is) yara.sh: [ERROR] YARA rules not found at $YARA_RULES" >> "$LOGFILE"
    exit 0
fi

echo "$(date -Is) yara.sh: [DEBUG] Executing Docker YARA container..." >> "$LOGFILE"

# ============ Docker YARA Scan ============
YARA_RESULT=$(docker run --rm \
    -v "$ABS_FILE":/scan/target_file:ro \
    -v "$YARA_RULES":/opt/yara/rules/yara_rules.yar:ro \
    --entrypoint yara \
    cincan/yara:latest \
    -r /opt/yara/rules/yara_rules.yar /scan/target_file 2>&1)

DOCKER_EXIT_CODE=$?
echo "$(date -Is) yara.sh: [DEBUG] Docker execution finished. Exit Code: $DOCKER_EXIT_CODE" >> "$LOGFILE"

# ตรวจสอบว่าเจอไวรัสหรือไม่ (ถ้าไม่มี output หรือมีแต่ warning มักจะ clean, แต่ถ้าเจอจะ print ชื่อ rule)
# เราจะกรอง warning ออกไปก่อน (บางที YARA ปริ้นท์ warning)
CLEAN_YARA_RESULT=$(echo "$YARA_RESULT" | grep -v "warning")

if [ -n "$CLEAN_YARA_RESULT" ] && [ $DOCKER_EXIT_CODE -eq 0 ]; then
    echo "$(date -Is) yara.sh: [WARN] MALWARE_DETECTED file=$FILENAME result=$CLEAN_YARA_RESULT" >> "$LOGFILE"

    # คำนวณ Hash ก่อนลบ
    SHA256=$(sha256sum "$ABS_FILE" | awk '{print $1}')
    MD5=$(md5sum "$ABS_FILE" | awk '{print $1}')

    echo "$(date -Is) yara.sh: [DEBUG] Hashes computed. SHA256=$SHA256" >> "$LOGFILE"
    
    # ลบไฟล์ต้นฉบับ (Quarantine by deletion)
    rm -f "$ABS_FILE"
    if [ ! -f "$ABS_FILE" ]; then
        echo "$(date -Is) yara.sh: [DEBUG] File successfully deleted." >> "$LOGFILE"
    else
        echo "$(date -Is) yara.sh: [ERROR] Failed to delete file." >> "$LOGFILE"
    fi

    # เขียน Log แบบ parseable สำหรับ Wazuh Decoder (ส่งกลับ SOC กลาง)
    YARA_CLEAN_FORMAT=$(echo "$CLEAN_YARA_RESULT" | tr '\n' '|' | sed 's/|$//')
    echo "QUARANTINED src=$ABS_FILE dest=DELETED sha256=$SHA256 md5=$MD5 yara_match=$YARA_CLEAN_FORMAT" >> "$LOGFILE"
else
    if [ $DOCKER_EXIT_CODE -ne 0 ]; then
        echo "$(date -Is) yara.sh: [ERROR] YARA scan failed or container error. Result: $YARA_RESULT" >> "$LOGFILE"
    else
        echo "$(date -Is) yara.sh: [INFO] CLEAN file=$FILENAME" >> "$LOGFILE"
    fi
fi

echo "$(date -Is) yara.sh: [DEBUG] Script completed." >> "$LOGFILE"
exit 0
