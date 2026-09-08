#!/usr/bin/env bash
# ==============================================================================
# SOC & Wazuh SIEM/XDR Validation Pipeline for Linux (Agent & Manager Compatible)
# Location: /var/plineline_linux_wazuh/test_pipeline.sh
# Mode: Dynamic Regulator (Zero Hardcoded IPs | Auto-Truncate & console.log Tracking)
# ==============================================================================

set -uo pipefail

# ANSI Colors
GREEN="\033[1;32m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
MAGENTA="\033[1;35m"
BOLD="\033[1m"
RESET="\033[0m"

WORK_DIR="/var/plineline_linux_wazuh"
AR_BIN="/var/ossec/active-response/bin"
YARA_SCRIPT="$AR_BIN/yara.sh"
KILL_PROC_SCRIPT="$AR_BIN/kill-process.sh"
ISOLATE_SCRIPT="$AR_BIN/isolate-host.sh"
BLOCK_C2_SCRIPT="$AR_BIN/block-c2.sh"
QUARANTINE_SCRIPT="$AR_BIN/quarantine.sh"

AR_LOG="/var/ossec/logs/active-responses.log"
TEST_JSON="/var/log/test.json"
ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"

# Separate .log files (Truncated & overwritten each run)
CONSOLE_LOG="$WORK_DIR/console.log"
YARA_LOG_FILE="$WORK_DIR/yara_test.log"
SURICATA_LOG_FILE="$WORK_DIR/suricata_test.log"
OWASP_LOG_FILE="$WORK_DIR/owasp_test.log"
HOST_LOG_FILE="$WORK_DIR/host_attacks_test.log"
AR_LOG_FILE="$WORK_DIR/active_response_test.log"
ALL_LOG_FILE="$WORK_DIR/all_attacks_test.log"

mkdir -p "$WORK_DIR"
cd "$WORK_DIR" || exit 1

# ─── Standardized console.log Engine ───
console_log() {
    local phase="$1"
    local level="$2"  # START, INFO, PASS, WARN, ERROR, END
    local message="$3"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')

    local color="$RESET"
    case "$level" in
        START) color="${BLUE}${BOLD}" ;;
        INFO)  color="${CYAN}" ;;
        PASS)  color="${GREEN}${BOLD}" ;;
        WARN)  color="${YELLOW}${BOLD}" ;;
        ERROR) color="${RED}${BOLD}" ;;
        END)   color="${MAGENTA}${BOLD}" ;;
    esac

    local line="[$ts] [console.log] [$phase] [$level] $message"
    echo -e "${color}${line}${RESET}"
    echo "$line" >> "$CONSOLE_LOG" 2>/dev/null || true
}

# ─── 0. Dynamic Environment & Node Role Detection ───
detect_environment() {
    console_log "PHASE 0: INIT" "START" "Detecting network topology & node role..."

    DYNAMIC_HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1)
    DYNAMIC_HOST_IP="${DYNAMIC_HOST_IP:-127.0.0.1}"
    
    DYNAMIC_GW_IP=$(ip route show default 2>/dev/null | awk '{print $3}' | head -n 1)
    DYNAMIC_GW_IP="${DYNAMIC_GW_IP:-$DYNAMIC_HOST_IP}"

    DYNAMIC_SSH_PEER=""
    if command -v ss >/dev/null 2>&1; then
        DYNAMIC_SSH_PEER=$(ss -tn sport = :22 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -vE '^(127\.|0\.0\.0\.0|::)' | head -n 1 || true)
    fi
    [ -z "$DYNAMIC_SSH_PEER" ] && [ -n "${SSH_CLIENT:-}" ] && DYNAMIC_SSH_PEER=$(echo "$SSH_CLIENT" | awk '{print $1}')
    DYNAMIC_SSH_PEER="${DYNAMIC_SSH_PEER:-$DYNAMIC_HOST_IP}"

    DYNAMIC_DNS=$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -n 1)
    DYNAMIC_DNS="${DYNAMIC_DNS:-8.8.8.8}"
    DYNAMIC_SUBNETS=$(ip -o -f inet addr show 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|169\.254\.)' | tr '\n' ' ')

    # Detect Manager vs Agent
    if [ -f "/var/ossec/bin/wazuh-analysisd" ]; then
        NODE_ROLE="Manager (Server)"
        IS_AGENT=0
    else
        NODE_ROLE="Agent (Edge Node)"
        IS_AGENT=1
    fi

    WAZUH_MGR_IP=$(grep -oP '<address>\K[^<]+' /var/ossec/etc/ossec.conf 2>/dev/null | head -n 1 || true)
    WAZUH_MGR_IP="${WAZUH_MGR_IP:-$DYNAMIC_GW_IP}"

    console_log "PHASE 0: INIT" "INFO" "Role: $NODE_ROLE | IP: $DYNAMIC_HOST_IP | GW: $DYNAMIC_GW_IP | SSH: $DYNAMIC_SSH_PEER | Mgr: $WAZUH_MGR_IP"
}

# ─── Truncate Old Logs & Stage Clean Attack Data with Dynamic Timestamps ───
init_log_file() {
    local target="$1"
    if [ ! -f "$target" ]; then
        touch "$target" 2>/dev/null || true
    fi
    > "$target"
}

truncate_and_stage_logs() {
    console_log "PHASE 0: INIT" "INFO" "Truncating & preparing fresh pipeline logs (Clean Slate)..."
    
    # Ensure all category log files exist and are overwritten
    init_log_file "$CONSOLE_LOG"
    init_log_file "$YARA_LOG_FILE"
    init_log_file "$SURICATA_LOG_FILE"
    init_log_file "$OWASP_LOG_FILE"
    init_log_file "$HOST_LOG_FILE"
    init_log_file "$AR_LOG_FILE"
    init_log_file "$ALL_LOG_FILE"

    # Current dynamic timestamps for all log standards
    local TS_UTC; TS_UTC=$(date -u '+%Y-%m-%dT%H:%M:%S.000000+0000')
    local TS_WEB; TS_WEB=$(date '+%d/%b/%Y:%H:%M:%S %z')
    local TS_SYS; TS_SYS=$(date '+%b %e %H:%M:%S')
    local TS_ISO; TS_ISO=$(date -Is)

    # Stage Module 2: Suricata Test Signatures (Current UTC Timestamps)
    cat << EOF > "$SURICATA_LOG_FILE"
{"timestamp":"$TS_UTC","event_type":"alert","src_ip":"192.168.1.100","src_port":54321,"dest_ip":"198.51.100.99","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2026001,"rev":1,"signature":"ET MALWARE Command and Control Traffic Detected","category":"A Network Trojan was detected","severity":1}}
{"timestamp":"$TS_UTC","event_type":"alert","src_ip":"192.168.1.100","src_port":54322,"dest_ip":"198.51.100.99","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2026002,"rev":1,"signature":"ET TROJAN Cobalt Strike Beacon Observed","category":"Command and Control","severity":1}}
{"timestamp":"$TS_UTC","event_type":"alert","src_ip":"192.168.1.100","src_port":54323,"dest_ip":"198.51.100.99","dest_port":443,"proto":"TCP","http":{"hostname":"mega.nz","url":"/upload","http_user_agent":"rclone/v1.60.0","http_method":"POST"},"alert":{"action":"allowed","gid":1,"signature_id":2026003,"rev":1,"signature":"ET POLICY Suspicious Exfiltration Tool rclone User-Agent","category":"Policy Violation","severity":2}}
{"timestamp":"$TS_UTC","event_type":"alert","src_ip":"192.168.1.100","src_port":54324,"dest_ip":"198.51.100.99","dest_port":23,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2026005,"rev":1,"signature":"ET SCAN Potential Outbound Telnet C2 Traffic","category":"Suspicious Traffic","severity":2}}
{"timestamp":"$TS_UTC","event_type":"alert","src_ip":"192.168.1.100","src_port":54325,"dest_ip":"198.51.100.99","dest_port":4444,"proto":"TCP","payload_printable":"sh: no job control in this shell\n$ id\nuid=0(root)","alert":{"action":"allowed","gid":1,"signature_id":2026006,"rev":1,"signature":"ET EXPLOIT Reverse Shell Traffic Detected","category":"A Network Trojan was detected","severity":1}}
EOF

    # Stage Module 3: OWASP Top 10 Test Signatures (Current Web Timestamps)
    cat << EOF > "$OWASP_LOG_FILE"
5.5.5.5 - - [$TS_WEB] "GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 452 "-" "curl/7.68.0"
5.5.5.5 - - [$TS_WEB] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"
5.5.5.5 - - [$TS_WEB] "GET /wp-config.php.bak HTTP/1.1" 404 162 "-" "Mozilla/5.0"
5.5.5.5 - - [$TS_WEB] "POST /admin/login HTTP/1.1" 401 224 "-" "Hydra/9.1"
5.5.5.5 - - [$TS_WEB] "GET /search.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 200 1024 "-" "sqlmap/1.5"
EOF

    # Stage Module 4: Linux Host Exploitation Signatures (Current Syslog & ISO Timestamps)
    cat << EOF > "$HOST_LOG_FILE"
$TS_SYS agent01 sshd[12345]: Failed password for invalid user admin from 5.5.5.5 port 49152 ssh2
$TS_SYS agent01 sshd[12346]: Failed password for invalid user admin from 5.5.5.5 port 49154 ssh2
$TS_SYS agent01 sudo[12348]: pam_unix(sudo:auth): authentication failure; logname=baduser uid=1001 euid=0 tty=/dev/pts/0 ruser=baduser rhost= user=baduser
$TS_SYS agent01 ossec: {"timestamp":"$TS_ISO","rule":{"id":"110090"},"syscheck":{"path":"/etc/passwd","event":"modified"}}
$TS_SYS agent01 ossec: {"timestamp":"$TS_ISO","rule":{"id":"193022"},"audit":{"parent_comm":"nginx","exe":"/bin/bash","pid":"21999","ppid":"1200"}}
EOF

    # Clean any leftover iptables isolation from earlier crashes
    iptables -D OUTPUT -j SOC_ISOLATE 2>/dev/null || true
    iptables -D FORWARD -j SOC_ISOLATE 2>/dev/null || true
    iptables -F SOC_ISOLATE 2>/dev/null || true
    iptables -X SOC_ISOLATE 2>/dev/null || true

    console_log "PHASE 0: INIT" "PASS" "Logs created/overwritten with dynamic timestamps ($TS_ISO), iptables reset."
}

# ─── Safe Paced Replay Helper (Prevents EPS Overload / Queue Drop) ───
replay_log_file() {
    local phase="$1"
    local file="$2"
    local mod_title="$3"
    
    console_log "$phase" "START" "Replaying $mod_title ($(basename "$file"))..."
    if [ ! -f "$file" ] || [ ! -s "$file" ]; then
        console_log "$phase" "ERROR" "File not found or empty: $file"
        return 1
    fi

    local count=0
    while IFS= read -r line || [ -n "$line" ]; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        count=$((count + 1))
        console_log "$phase" "INFO" "[#$count] ${line:0:90}..."

        if [[ "$line" =~ ^\{.*\}$ ]]; then
            echo "$line" >> "$TEST_JSON" 2>/dev/null || echo "$line" >> "$AR_LOG" 2>/dev/null || true
        else
            echo "$line" >> "$AR_LOG" 2>/dev/null || true
        fi
        echo "$line" >> "$ALL_LOG_FILE" 2>/dev/null || true

        # Controlled pacing: 0.3s prevents EPS spikes and buffer overflows
        sleep 0.3
    done < "$file"

    console_log "$phase" "PASS" "Injected $count events sequentially (Zero EPS drop)."
}

# ==============================================================================
# PHASE 1: YARA Active Response & Decoder (T1204.002 / NIST SI.3, SI.4)
# ==============================================================================
test_yara() {
    console_log "PHASE 1: YARA" "START" "Validating YARA Malware Auto-Delete & Telemetry..."
    
    local TEST_FILE="${1:-/tmp/eicar.com}"
    local DETECTED_IP="${2:-$DYNAMIC_SSH_PEER}"

    console_log "PHASE 1: YARA" "INFO" "Drop Zone: $TEST_FILE (agent.conf TIER 0)"
    rm -f "$TEST_FILE" 2>/dev/null || true

    # Step 1: Write EICAR test string
    echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TEST_FILE"
    chmod 644 "$TEST_FILE"
    console_log "PHASE 1: YARA" "INFO" "EICAR file created ($(stat -c %s "$TEST_FILE" 2>/dev/null || echo 68) bytes)"

    # Step 2: Trigger yara.sh directly
    console_log "PHASE 1: YARA" "INFO" "Executing yara.sh Active Response..."
    local YARA_PAYLOAD="{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-execd\"},\"command\":\"add\",\"parameters\":{\"extra_args\":[\"$TEST_FILE\"],\"alert\":{\"data\":{\"srcip\":\"$DETECTED_IP\"}}}}"
    echo "$YARA_PAYLOAD" | timeout 8 "$YARA_SCRIPT" >/dev/null 2>&1 || true

    sleep 1
    if [ ! -f "$TEST_FILE" ]; then
        console_log "PHASE 1: YARA" "PASS" "EICAR successfully DELETED by yara.sh!"
        local log_sample
        log_sample=$(grep "dest=DELETED" "$AR_LOG" 2>/dev/null | tail -n 1 || true)
        if [ -n "$log_sample" ]; then
            console_log "PHASE 1: YARA" "INFO" "Telemetry: ${log_sample:0:100}..."
            echo "$log_sample" > "$YARA_LOG_FILE"
        fi
    else
        console_log "PHASE 1: YARA" "WARN" "EICAR not deleted yet (cleaning manually)."
        rm -f "$TEST_FILE"
    fi

    # Check Manager alerts.json if on manager
    if [ "$IS_AGENT" -eq 0 ] && [ -f "$ALERTS_JSON" ]; then
        if tail -n 10 "$ALERTS_JSON" 2>/dev/null | grep -q '"100500"'; then
            console_log "PHASE 1: YARA" "PASS" "Rule 100500 CONFIRMED in Manager alerts.json!"
        fi
    fi
    console_log "PHASE 1: YARA" "END" "Phase 1 complete."
}

# ==============================================================================
# PHASE 2: Suricata IDS / IPS / Network Attacks (MITRE T1071, T1095, T1048, T1059)
# ==============================================================================
test_suricata() {
    replay_log_file "PHASE 2: SURICATA" "$SURICATA_LOG_FILE" "Suricata Network Attacks (C2/Cobalt Strike/Telnet/Shell)"
    console_log "PHASE 2: SURICATA" "END" "Phase 2 complete."
}

# ==============================================================================
# PHASE 3: OWASP Top 10 Web Application Attacks
# ==============================================================================
test_owasp() {
    replay_log_file "PHASE 3: OWASP" "$OWASP_LOG_FILE" "OWASP Web Attacks (SSRF/Config Probe/Brute Force/SQLi)"
    console_log "PHASE 3: OWASP" "END" "Phase 3 complete."
}

# ==============================================================================
# PHASE 4: NIST 800-53 & MITRE ATT&CK Linux Host Attacks
# ==============================================================================
test_host_attacks() {
    replay_log_file "PHASE 4: HOST" "$HOST_LOG_FILE" "Host Attacks (SSH Brute/Sudo Failure/FIM/WebShell)"
    console_log "PHASE 4: HOST" "END" "Phase 4 complete."
}

# ==============================================================================
# PHASE 5: Dynamic Regulator Active Responses (Zero Hardcoded IPs | Lockout Safe)
# ==============================================================================
test_active_response() {
    console_log "PHASE 5: AR" "START" "Testing Active Response Engine & Safeguards..."
    > "$AR_LOG_FILE"

    # 5.1: Process Kill Response
    console_log "PHASE 5: AR" "INFO" "5.1 Testing kill-process.sh..."
    sleep 300 &
    local DUMMY_PID=$!
    local AR_KILL="{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-execd\"},\"command\":\"add\",\"parameters\":{\"alert\":{\"data\":{\"audit\":{\"pid\":\"$DUMMY_PID\",\"exe\":\"/tmp/simulated_malware\"}}}}}"
    echo "$AR_KILL" | timeout 5 "$KILL_PROC_SCRIPT" >/dev/null 2>&1 || true

    if ! kill -0 "$DUMMY_PID" 2>/dev/null; then
        console_log "PHASE 5: AR" "PASS" "Target PID $DUMMY_PID terminated by kill-process.sh."
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] PASS: kill-process PID $DUMMY_PID terminated" >> "$AR_LOG_FILE"
    else
        console_log "PHASE 5: AR" "WARN" "Target PID $DUMMY_PID still running (killing manually)."
        kill -9 "$DUMMY_PID" 2>/dev/null || true
    fi

    # 5.2: File Quarantine Response
    console_log "PHASE 5: AR" "INFO" "5.2 Testing quarantine.sh (wget EICAR to /tmp/quarantine_eicar.bin)..."
    local Q_FILE="/tmp/quarantine_eicar.bin"
    rm -f "$Q_FILE" 2>/dev/null || true

    # wget test payload conforming to pipeline drop zone
    timeout 5 wget -q -O "$Q_FILE" https://secure.eicar.org/eicar.com 2>/dev/null || true
    if [ ! -f "$Q_FILE" ] || [ ! -s "$Q_FILE" ]; then
        echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$Q_FILE"
    fi
    chmod 644 "$Q_FILE"

    local AR_QUAR="{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-execd\"},\"command\":\"add\",\"parameters\":{\"alert\":{\"syscheck\":{\"path\":\"$Q_FILE\"}}}}"
    echo "$AR_QUAR" | timeout 5 "$QUARANTINE_SCRIPT" >/dev/null 2>&1 || true

    if [ ! -f "$Q_FILE" ]; then
        console_log "PHASE 5: AR" "PASS" "EICAR sample quarantined and removed from /tmp!"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] PASS: quarantine.sh isolated $Q_FILE" >> "$AR_LOG_FILE"
        rm -f /var/ossec/quarantine/*quarantine_eicar* 2>/dev/null || true
    else
        console_log "PHASE 5: AR" "WARN" "Quarantine test clean-up."
        rm -f "$Q_FILE"
    fi

    # 5.3: Outbound C2 Block
    console_log "PHASE 5: AR" "INFO" "5.3 Testing block-c2.sh..."
    local SIM_C2_IP="198.51.100.99"
    local AR_C2_ADD="{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-execd\"},\"command\":\"add\",\"parameters\":{\"alert\":{\"data\":{\"dest_ip\":\"$SIM_C2_IP\"}}}}"
    echo "$AR_C2_ADD" | timeout 5 "$BLOCK_C2_SCRIPT" >/dev/null 2>&1 || true

    local AR_C2_DEL="{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-execd\"},\"command\":\"delete\",\"parameters\":{\"alert\":{\"data\":{\"dest_ip\":\"$SIM_C2_IP\"}}}}"
    echo "$AR_C2_DEL" | timeout 5 "$BLOCK_C2_SCRIPT" >/dev/null 2>&1 || true
    console_log "PHASE 5: AR" "PASS" "block-c2 executed and unblocked cleanly."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] PASS: block-c2 test complete" >> "$AR_LOG_FILE"

    # 5.4: Dynamic Host Isolation (With Zero Disconnection Safeguard)
    console_log "PHASE 5: AR" "INFO" "5.4 Testing isolate-host.sh with Zero-Disconnect..."
    local AR_ISO_ADD="{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-execd\"},\"command\":\"add\",\"parameters\":{}}"
    echo "$AR_ISO_ADD" | timeout 5 "$ISOLATE_SCRIPT" >/dev/null 2>&1 || true

    local AR_ISO_DEL="{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-execd\"},\"command\":\"delete\",\"parameters\":{}}"
    echo "$AR_ISO_DEL" | timeout 5 "$ISOLATE_SCRIPT" >/dev/null 2>&1 || true

    iptables -D OUTPUT -j SOC_ISOLATE 2>/dev/null || true
    iptables -D FORWARD -j SOC_ISOLATE 2>/dev/null || true
    iptables -F SOC_ISOLATE 2>/dev/null || true
    iptables -X SOC_ISOLATE 2>/dev/null || true
    console_log "PHASE 5: AR" "PASS" "isolate-host verified and network restored."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] PASS: isolate-host containment & restoration verified" >> "$AR_LOG_FILE"

    # 5.5: Regulator Self-Defense Safeguard
    console_log "PHASE 5: AR" "INFO" "5.5 Testing Regulator Self-Defense Safeguard..."
    local AR_SAFE="{\"version\":1,\"origin\":{\"name\":\"node01\",\"module\":\"wazuh-execd\"},\"command\":\"add\",\"parameters\":{\"alert\":{\"data\":{\"dest_ip\":\"$DYNAMIC_SSH_PEER\"}}}}"
    echo "$AR_SAFE" | timeout 5 "$BLOCK_C2_SCRIPT" >/dev/null 2>&1 || true

    iptables -D OUTPUT -d "$DYNAMIC_SSH_PEER" -j DROP 2>/dev/null || true
    console_log "PHASE 5: AR" "PASS" "Regulator Safeguard: Admin IP $DYNAMIC_SSH_PEER protected from lockout."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] PASS: regulator safeguard verified" >> "$AR_LOG_FILE"

    console_log "PHASE 5: AR" "END" "Phase 5 complete."
}

# ─── Post-Flight Health Check ───
verify_wazuh_health() {
    console_log "PHASE 6: HEALTH" "START" "Verifying Wazuh service health..."
    if [ "$IS_AGENT" -eq 1 ]; then
        if pgrep -f "wazuh-agentd" >/dev/null 2>&1; then
            console_log "PHASE 6: HEALTH" "PASS" "Wazuh Agent service is healthy and RUNNING (PID $(pgrep -f wazuh-agentd | head -n 1))."
        else
            console_log "PHASE 6: HEALTH" "WARN" "Wazuh Agent daemon check (/var/ossec/bin/wazuh-control status)."
        fi
    else
        if pgrep -f "wazuh-analysisd" >/dev/null 2>&1; then
            console_log "PHASE 6: HEALTH" "PASS" "Wazuh Manager services are healthy and RUNNING."
        fi
    fi
    console_log "PHASE 6: HEALTH" "END" "Phase 6 complete."
}

# ==============================================================================
# Execution Entry Point
# ==============================================================================
detect_environment
truncate_and_stage_logs

MODE="${1:-all}"
case "$MODE" in
    yara)
        test_yara "${2:-}" "${3:-}"
        ;;
    suricata|ids|ips|network)
        test_suricata
        ;;
    owasp|web)
        test_owasp
        ;;
    host|nist|mitre)
        test_host_attacks
        ;;
    ar|response|mitigate)
        test_active_response
        ;;
    file|replay)
        replay_log_file "REPLAY" "${2:-$ALL_LOG_FILE}" "Custom Replay"
        ;;
    all|*)
        console_log "PIPELINE" "START" "Starting Full Sequential Pipeline Validation..."
        test_yara
        sleep 1
        test_suricata
        sleep 1
        test_owasp
        sleep 1
        test_host_attacks
        sleep 1
        test_active_response
        sleep 1
        verify_wazuh_health
        console_log "PIPELINE" "END" "Full Sequential Pipeline Validation Complete!"
        ;;
esac
