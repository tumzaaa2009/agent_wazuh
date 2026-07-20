################################
## Script to remove malicious for detection IOC in MISP
## Fixed: reads from data.misp.* path for MISP integration alerts
################################

$INPUT_JSON = Read-Host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json
$INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json
$ErrorActionPreference = "SilentlyContinue"

$logFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$command = $INPUT_ARRAY."command"
$hostip  = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
            Where-Object { $_.DHCPEnabled -ne $null -and $_.DefaultIPGateway -ne $null }
           ).IPAddress | Select-Object -First 1

# ─── ดึงข้อมูลจาก MISP integration path ────────────────────────────────────
$mispType        = $INPUT_ARRAY."parameters"."alert"."data"."misp"."type"
$mispValue       = $INPUT_ARRAY."parameters"."alert"."data"."misp"."value"
$mispDescription = $INPUT_ARRAY."parameters"."alert"."data"."misp"."source"."description"

# ─── fallback: Sysmon raw event path (กรณี alert มาจาก Sysmon โดยตรง) ─────
$sysmonEventID   = $INPUT_ARRAY."parameters"."alert"."data"."win"."system"."eventID"
$sysmonDestIP    = $INPUT_ARRAY."parameters"."alert"."data"."win"."eventdata"."destinationIp"
$sysmonQueryName = $INPUT_ARRAY."parameters"."alert"."data"."win"."eventdata"."queryName"

# ─── ตัดสินใจว่าจะใช้ path ไหน ─────────────────────────────────────────────
# ถ้ามี MISP data ให้ใช้ MISP path ก่อนเสมอ
if ($mispType -and $mispValue) {

    # แปลง description → event type เพื่อ route ไป block method ที่ถูกต้อง
    # รองรับทั้ง "Sysmon - Event 22: DNS Query event" และ "Sysmon - Event 3: ..."
    if ($mispDescription -match 'Event\s+(\d+)') {
        $detectedEventID = $matches[1]
    } else {
        # fallback: เดาจาก type ของ IOC เอง
        $detectedEventID = if ($mispType -eq 'domain') { '22' } else { '3' }
    }

    $IOCtype       = $mispType     # "domain", "ip-dst", "md5", etc.
    $IOCvalue      = $mispValue    # ค่า IOC จริง เช่น "ccwaterfall.com"
    $IOCeventid    = $detectedEventID

} elseif ($sysmonEventID) {
    # ใช้ Sysmon raw path แทน
    $IOCeventid    = $sysmonEventID
    $IOCvalue      = $sysmonDestIP
    $IOCtype       = if ($sysmonEventID -eq '3') { 'ip-dst' } else { 'domain' }
    if ($sysmonEventID -eq '22') { $IOCvalue = $sysmonQueryName }

} else {
    # ไม่พบข้อมูล IOC เลย → log แล้วออก
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: No IOC data found in alert" |
        Out-File -FilePath $logFile -Append -Encoding ascii
    exit 1
}

# ─── Block logic: ใช้ misp.type เป็นตัวตัดสินหลัก ──────────────────────

# ip-dst, ip-src, ip → block via Firewall
if ($IOCtype -in @('ip-dst','ip-src','ip')) {
    foreach ($ip in $IOCvalue) {

        if ($ip -in $ipWhitelist -or (IsPrivateIP $ip)) {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED (whitelist): $ip" |
                Out-File -FilePath $logFile -Append -Encoding ascii
            continue
        }

        $existingRule = Get-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -ErrorAction SilentlyContinue

        if ($command -eq 'add' -and -not $existingRule) {
            New-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" `
                -Direction Outbound -LocalPort Any -Protocol Any `
                -Action Block -RemoteAddress $ip
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - BLOCKED IP: $ip via Windows Firewall" |
                Out-File -FilePath $logFile -Append -Encoding ascii

        } elseif ($command -eq 'delete' -and $existingRule) {
            Remove-NetFirewallRule -DisplayName "Wazuh Active Response - $ip"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - UNBLOCKED IP: $ip from Windows Firewall" |
                Out-File -FilePath $logFile -Append -Encoding ascii
        }
    }

# domain, hostname, url → block via hosts file
} elseif ($IOCtype -in @('domain','hostname','url')) {

    $hostsPath  = "C:\Windows\System32\drivers\etc\hosts"
    $escapedVal = [regex]::Escape($IOCvalue)

    if (IsDomainWhitelisted $IOCvalue) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED (domain whitelist): $IOCvalue" |
            Out-File -FilePath $logFile -Append -Encoding ascii
        exit 0
    }

    if ($command -eq 'add') {
        if (-not (Select-String -Path $hostsPath -Pattern "^127\.0\.0\.1`t$escapedVal$" -Quiet)) {
            Add-Content -Path $hostsPath -Value "127.0.0.1`t$IOCvalue"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - BLOCKED DOMAIN: $IOCvalue → 127.0.0.1" |
                Out-File -FilePath $logFile -Append -Encoding ascii
        } else {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIP: $IOCvalue already blocked" |
                Out-File -FilePath $logFile -Append -Encoding ascii
        }

    } elseif ($command -eq 'delete') {
        $content  = Get-Content -Path $hostsPath
        $filtered = $content | Where-Object { $_ -notmatch "^127\.0\.0\.1`t$escapedVal$" }
        $filtered | Set-Content -Path $hostsPath
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - UNBLOCKED DOMAIN: $IOCvalue" |
            Out-File -FilePath $logFile -Append -Encoding ascii
    }

} else {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - UNHANDLED IOC type: $IOCtype value: $IOCvalue" |
        Out-File -FilePath $logFile -Append -Encoding ascii
}