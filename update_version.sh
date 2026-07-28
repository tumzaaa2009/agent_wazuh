#!/bin/bash
LOG_FILE="/var/hos-edge-connector/logs/boots.log"
TIMESTAMP=$(date +"%Y-%m-%dT%H:%M:%S%z")

echo "==================== UPDATE START: $TIMESTAMP ====================" >> "$LOG_FILE"
echo "🚀 Building and updating Docker containers safely..." | tee -a "$LOG_FILE"

docker compose up -d 2>&1 | tee -a "$LOG_FILE"

echo "✅ Container updated successfully." | tee -a "$LOG_FILE"

echo "🔄 Restarting Wazuh Manager..." | tee -a "$LOG_FILE"
if systemctl restart wazuh-manager >> "$LOG_FILE" 2>&1; then
    echo "✅ Wazuh Manager restarted successfully." | tee -a "$LOG_FILE"
else
    echo "❌ Failed to restart Wazuh Manager." | tee -a "$LOG_FILE"
fi

echo "==================== UPDATE END: $TIMESTAMP ====================" >> "$LOG_FILE"
