#!/bin/bash
# SOC oxAlph - Active Response: isolate-host.sh (Linux server)
# Triggered by confirmed-ransomware rules (130002 / 136031 / 136035).
# Network-isolates THIS host: drops all outbound except SOC management subnet.
# Logs in Wazuh standard convention (Starting / JSON / Ended).

AR_NAME="isolate-host.sh"
LOG_FILE="/var/ossec/logs/active-responses.log"

log_line() { echo "$(date '+%Y/%m/%d %H:%M:%S') active-response/bin/${AR_NAME}: $1" >> "$LOG_FILE" 2>/dev/null || echo "$1"; }
log_start() { log_line "Starting"; }
log_end()   { log_line "Ended"; }
log_json() {
  # $1=action $2=status
  local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
  log_line "{\"version\":1,\"origin\":{\"name\":\"$(hostname)\",\"module\":\"${AR_NAME}\"},\"command\":\"${1}\",\"parameters\":{\"program\":\"isolate-host\",\"status\":\"${2}\",\"timestamp\":\"${ts}\"}}"
}

# ─── SOC management subnets that must stay reachable ───
SOC_SUBNETS="192.168.36.0/24"   # ← ปรับตาม SOC subnet จริง

log_start

if ! command -v iptables >/dev/null 2>&1; then
    log_json "$ACTION" "ERROR"
    log_line "ERROR: iptables not available"
    exit 1
fi

ACTION="${1:-add}"

iptables -N SOC_ISOLATE 2>/dev/null

if [ "$ACTION" = "add" ]; then
    # allow established/related
    iptables -I SOC_ISOLATE 1 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    # allow SOC subnets
    for net in $SOC_SUBNETS; do
        iptables -I SOC_ISOLATE 1 -d "$net" -j ACCEPT 2>/dev/null
    done
    # drop everything else outbound + forward
    iptables -I OUTPUT  -j SOC_ISOLATE 2>/dev/null || true
    iptables -A SOC_ISOLATE -j DROP
    log_json "$ACTION" "ISOLATED"
    log_line "ISOLATED: outbound restricted to SOC subnets ($SOC_SUBNETS)"
elif [ "$ACTION" = "delete" ]; then
    # un-isolate: flush chain and detach
    iptables -D OUTPUT -j SOC_ISOLATE 2>/dev/null
    iptables -F SOC_ISOLATE 2>/dev/null
    log_json "$ACTION" "RESTORED"
    log_line "RESTORED: isolation removed"
fi

log_end
exit 0
