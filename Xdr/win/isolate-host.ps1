################################
## Wazuh Active Response - Total Host Network Kill (Zero Exception)
## 1. Disables all Network Adapters (Ethernet, Wi-Fi, Virtual)
## 2. Sets IP to 1.1.1.1 / 255.255.255.255 (No Gateway)
## 3. Total Firewall Block (All Inbound / Outbound)
## 4. Releases IP, flushes DNS, ARP, and deletes default routes
## Result: 100% offline, zero lateral spread, disconnected from Manager & LAN
################################

$ErrorActionPreference = "SilentlyContinue"
$logFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$backupFile = "C:\Program Files (x86)\ossec-agent\active-response\network-backup.json"

$inputJson = [Console]::In.ReadLine()
if ([string]::IsNullOrWhiteSpace($inputJson)) {
    $inputJson = Read-Host
}
if ([string]::IsNullOrWhiteSpace($inputJson)) { exit 0 }

try {
    $data = $inputJson | ConvertFrom-Json
    if ($data -is [string]) { $data = $data | ConvertFrom-Json }
} catch { exit 0 }

$command = $data.command
$rulePrefix = "Wazuh Total Isolation"

if ($command -eq "add") {
    # ─── 1. Backup รายชื่อ Adapter ก่อนสั่งปิด ───────────────────────────
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

    $backupList = @()
    foreach ($adapter in $adapters) {
        $backupList += @{
            Name = $adapter.Name
            InterfaceDescription = $adapter.InterfaceDescription
        }
    }
    $backupList | ConvertTo-Json | Out-File -FilePath $backupFile -Encoding ascii -Force

    # ─── 2. Windows Firewall Block ทั้งหมด 100% (ไม่มีข้อยกเว้น แม้กระทั่ง Manager) ──
    Get-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    New-NetFirewallRule -DisplayName "$rulePrefix - Block All Inbound" `
        -Direction Inbound -Action Block -LocalPort Any -Protocol Any -RemoteAddress Any

    New-NetFirewallRule -DisplayName "$rulePrefix - Block All Outbound" `
        -Direction Outbound -Action Block -LocalPort Any -Protocol Any -RemoteAddress Any

    # ─── 3. เปลี่ยน IP เป็น 1.1.1.1 ตัด Gateway & DNS ───────────────────
    foreach ($item in $backupList) {
        $adapterName = $item.Name
        & netsh interface ip set address name="$adapterName" source=static addr=1.1.1.1 mask=255.255.255.255
        & netsh interface ip set dns name="$adapterName" source=static addr=127.0.0.1
    }

    # ─── 4. ล้าง Routing, ARP, DNS และ Release IP ───────────────────────
    & ipconfig /release
    & route delete 0.0.0.0
    & arp -d *
    & ipconfig /flushdns

    # ─── 5. สั่ง Disable การ์ดจอ/การ์ดแลน/Wi-Fi ทุกตัวทันที (ตัดสายเน็ตระดับฮาร์ดแวร์) ─
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false

    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - TOTAL NETWORK KILL: Disabled all NICs, Reset IP 1.1.1.1, Firewall Block All (ZERO EXCEPTION)" |
    Out-File -FilePath $logFile -Append -Encoding ascii

}
elseif ($command -eq "delete") {
    # ─── คืนค่า Network ทั้งหมดเมื่อสั่งปลดบล็อก ────────────────────────
    # 1. Enable การ์ดแลน/Wi-Fi กลับคืนมา
    Get-NetAdapter | Enable-NetAdapter -Confirm:$false
    Start-Sleep -Seconds 2

    # 2. ลบ Firewall Isolation Rules
    Get-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    # 3. คืนค่า DHCP
    if (Test-Path $backupFile) {
        $backupList = Get-Content -Path $backupFile | ConvertFrom-Json
        foreach ($item in $backupList) {
            $adapterName = $item.Name
            & netsh interface ip set address name="$adapterName" source=dhcp
            & netsh interface ip set dns name="$adapterName" source=dhcp
        }
        Remove-Item -Path $backupFile -Force
    }
    else {
        $allAdapters = Get-NetAdapter
        foreach ($ad in $allAdapters) {
            & netsh interface ip set address name="$($ad.Name)" source=dhcp
            & netsh interface ip set dns name="$($ad.Name)" source=dhcp
        }
    }

    & ipconfig /renew

    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - RESTORED NETWORK: Enabled all NICs and restored DHCP" |
    Out-File -FilePath $logFile -Append -Encoding ascii
}
