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

# ─── Dynamic Regulator Discovery: Zero Hardcoded IPs ───
# Discovers: Local subnets, Default Gateway, Active SSH peer IPs, and Wazuh Cluster
DYNAMIC_ALLOW_IPS=()

# 1. Discover Active SSH Management Connections (Prevents Lockout)
if command -v ss >/dev/null 2>&1; then
    while IFS= read -r peer_ip; do
        [ -n "$peer_ip" ] && DYNAMIC_ALLOW_IPS+=("$peer_ip")
    done < <(ss -tn sport = :22 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -vE '^(127\.|0\.0\.0\.0|::)' | sort -u)
fi
if [ -n "${SSH_CLIENT:-}" ]; then
    DYNAMIC_ALLOW_IPS+=("$(echo "$SSH_CLIENT" | awk '{print $1}')")
fi

# 2. Discover Default Gateway
GW_IP=$(ip route show default 2>/dev/null | awk '{print $3}' | head -n 1)
[ -n "$GW_IP" ] && DYNAMIC_ALLOW_IPS+=("$GW_IP")

# 3. Discover Local Interface Subnets (CIDR)
LOCAL_SUBNETS=()
while IFS= read -r cidr; do
    [ -n "$cidr" ] && LOCAL_SUBNETS+=("$cidr")
done < <(ip -o -f inet addr show 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|169\.254\.)' | sort -u)

# 4. Discover Wazuh Manager / Cluster Addresses from config
while IFS= read -r mgr; do
    [[ -n "$mgr" && "$mgr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && DYNAMIC_ALLOW_IPS+=("$mgr")
done < <(grep -oP '<address>\K[^<]+' /var/ossec/etc/ossec.conf 2>/dev/null || true)

# 5. Discover DNS Nameservers
while IFS= read -r ns; do
    [[ -n "$ns" && "$ns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && DYNAMIC_ALLOW_IPS+=("$ns")
done < <(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | sort -u)

# 6. Optional Environmental Subnets (if defined)
for extra in ${SOC_SUBNETS:-}; do
    LOCAL_SUBNETS+=("$extra")
done

log_start

if ! command -v iptables >/dev/null 2>&1; then
    log_json "$ACTION" "ERROR"
    log_line "ERROR: iptables not available"
    exit 1
fi

ACTION="$1"
if [ -z "$ACTION" ]; then
    INPUT=$(cat)
    if [ -n "$INPUT" ]; then
        ACTION=$(echo "$INPUT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('command', 'add'))" 2>/dev/null || echo "add")
    else
        ACTION="add"
    fi
fi

if [ "$ACTION" = "add" ]; then
    # 1. Create or reset SOC_ISOLATE chain
    iptables -F SOC_ISOLATE 2>/dev/null || iptables -N SOC_ISOLATE 2>/dev/null

    # 2. Allow loopback for local OS services
    iptables -A SOC_ISOLATE -o lo -j ACCEPT 2>/dev/null

    # 3. Allow established connections for ongoing management sessions
    iptables -A SOC_ISOLATE -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

    # 4. Dynamically allow all discovered SSH peers, Gateways & Managers
    for ip in "${DYNAMIC_ALLOW_IPS[@]}"; do
        iptables -A SOC_ISOLATE -d "$ip" -j ACCEPT 2>/dev/null
        iptables -A SOC_ISOLATE -s "$ip" -j ACCEPT 2>/dev/null
    done

    # 5. Allow Local Subnets
    for net in "${LOCAL_SUBNETS[@]}"; do
        iptables -A SOC_ISOLATE -d "$net" -j ACCEPT 2>/dev/null
    done

    # 6. Strict Anti-Exfiltration: DROP all remaining outbound & forwarded packets
    iptables -A SOC_ISOLATE -j DROP

    # Attach to OUTPUT and FORWARD chains
    iptables -D OUTPUT -j SOC_ISOLATE 2>/dev/null || true
    iptables -I OUTPUT 1 -j SOC_ISOLATE 2>/dev/null
    iptables -D FORWARD -j SOC_ISOLATE 2>/dev/null || true
    iptables -I FORWARD 1 -j SOC_ISOLATE 2>/dev/null

    # 7. Forcibly close external sockets not belonging to management IPs or local networks
    if command -v ss >/dev/null 2>&1; then
        SS_FILTER="not dst 127.0.0.1/8"
        for net in "${LOCAL_SUBNETS[@]}"; do
            SS_FILTER="$SS_FILTER and not dst $net"
        done
        for ip in "${DYNAMIC_ALLOW_IPS[@]}"; do
            SS_FILTER="$SS_FILTER and not dst $ip"
        done
        ss -K -t "$SS_FILTER" 2>/dev/null || true
    fi

    log_json "$ACTION" "ISOLATED"
    log_line "ISOLATED: Dynamic Regulator containment activated. Allowed Management IPs: [${DYNAMIC_ALLOW_IPS[*]}], Subnets: [${LOCAL_SUBNETS[*]}]. All unauthorized exfiltration severed."
elif [ "$ACTION" = "delete" ]; then
    # un-isolate: flush chain and detach
    iptables -D OUTPUT -j SOC_ISOLATE 2>/dev/null || true
    iptables -D FORWARD -j SOC_ISOLATE 2>/dev/null || true
    iptables -F SOC_ISOLATE 2>/dev/null || true
    iptables -X SOC_ISOLATE 2>/dev/null || true
    log_json "$ACTION" "RESTORED"
    log_line "RESTORED: isolation removed, full network connectivity restored."
fi

log_end
exit 0
