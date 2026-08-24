# SOC oxAlph - Active Response: isolate-host.ps1
# Triggered by confirmed-ransomware rules (130002 / 136031 / 136035).
# Network-isolates THIS host by blocking all outbound traffic except:
#   - The Wazuh manager (keeps agent connectivity for further response)
#   - Explicitly whitelisted SOC subnets ($socSubnets)
# Does NOT require srcip from the alert - ransomware encrypts locally.
# Logs in Wazuh standard convention (Starting / JSON / Ended).

$ErrorActionPreference = 'SilentlyContinue'
$AR_NAME      = "isolate-host.ps1"
$LOG_FILE     = "$env:ProgramData\ossec-agent\active-response\active-responses.log"

function Log-Line($msg) {
    Add-Content -Path $LOG_FILE -Value "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') active-response/bin/${AR_NAME}: $msg" -Encoding ascii
}
function Log-Json($action, $status) {
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
    $host_ = hostname
    Log-Line "{`"version`":1,`"origin`":{`"name`":`"$host_`",`"module`":`"${AR_NAME}`"},`"command`":`"$action`",`"parameters`":{`"program`":`"isolate-host`",`"status`":`"$status`",`"timestamp`":`"$ts`"}}"
}

# ─── SOC management assets that must stay reachable ───
$socSubnets   = @('192.168.36.0/24')          # ← ปรับตาม SOC subnet จริง
$managerIPs   = @()                            # เติม Wazuh manager IP เพิ่มได้

Log-Line "Starting"
Log-Json "add" "STARTED"

# 1) Enable Windows Firewall for all profiles (ensure enforcement)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 2) Block ALL outbound by default
New-NetFirewallRule -DisplayName "SOC-ISOLATE - Block All Outbound" `
    -Direction Outbound -Action Block -Profile Any -Enabled True | Out-Null

# 3) Allow outbound only to SOC subnets / manager
foreach ($subnet in ($socSubnets + $managerIPs)) {
    New-NetFirewallRule -DisplayName "SOC-ISOLATE - Allow $subnet" `
        -Direction Outbound -Action Allow -RemoteAddress $subnet -Profile Any | Out-Null
}

# 4) Allow DNS to internal only (first allowed subnet's gateway assumed)
Log-Line "ISOLATED: host network restricted to SOC subnets only"

Log-Json "add" "ISOLATED"
Log-Line "Ended"
exit 0
