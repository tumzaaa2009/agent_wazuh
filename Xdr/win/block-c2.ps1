# SOC oxAlph - Active Response: block-c2.ps1 (Windows client)
# Triggered by Wazuh rules 136001-136101. Blocks the C2 destination IP
# immediately via Windows Firewall OUTBOUND rule => stops the connection
# BEFORE the implant starts working. Safe for endpoints without Wazuh agent
# (deployed via GPO/Intune alongside the Wazuh agent).
param()

$ErrorActionPreference = 'SilentlyContinue'
function Write-SocLog([string]$msg) {
    $line = "{0} soc-block-c2: {1}" -f (Get-Date -Format 'ddd MMM dd HH:mm:ss yyyy'), $msg
    $arLog = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
    if (-not (Test-Path $arLog)) { $arLog = "C:\Program Files (x86)\ossec-agent\active-response.log" }
    Add-Content -Path $arLog -Value $line -Encoding ASCII
}

# --- Read alert JSON from stdin (Wazuh AR contract) ---
try { $alert = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { $alert = $null }

$action = "add"; if ($args.Count -ge 1) { $action = $args[0] }

$srcIp = $null; $dstIp = $null; $ruleId = $null
if ($alert -and $alert.parameters -and $alert.parameters.alert) {
    $a = $alert.parameters.alert
    $srcIp = $a.srcip; $dstIp = $a.dstip; $ruleId = $a.rule
}

# Prefer the EXTERNAL C2 destination; fallback to source (compromised host)
function Test-Public([string]$ip) {
    if (-not $ip) { return $false }
    return ($ip -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1|fc|fd)')
}

$blockIp = $null
if ((Test-Public $dstIp)) { $blockIp = $dstIp }
elseif ($srcIp -and $srcIp -ne '127.0.0.1') { $blockIp = $srcIp }

if (-not $blockIp) {
    Write-SocLog "skip: no blockable IP (src=$srcIp dst=$dstIp rule=$ruleId)"
    exit 0
}

$ruleName = "SOC-C2-Block $blockIp"

if ($action -eq 'add') {
    # Outbound block = kill the C2 channel; Inbound block = kill reverse shell
    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress $blockIp -Action Block -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "$ruleName (In)" -Direction Inbound -RemoteAddress $blockIp -Action Block -Profile Any -Enabled True | Out-Null
    Write-SocLog "BLOCKED ip=$blockIp rule=$ruleId (out+in)"
} else {
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "$ruleName (In)" -ErrorAction SilentlyContinue
    Write-SocLog "UNBLOCKED ip=$blockIp rule=$ruleId"
}

Write-Output "soc-block-c2: action=$action ip=$blockIp rule=$ruleId"
exit 0
