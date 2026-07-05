# 🦠 YARA Deployment Guide - SOC Zone (Docker + Native)

> **Logic ใหม่**: Edge Connector ไม่ต้อง drop YARA binary ไปที่ Agent  
> แต่ละ OS ใช้วิธีการติดตั้งที่เหมาะสมกับตัวเอง

---

## 📁 โครงสร้างไฟล์ทั้งหมด

```
yara_deployment/
├── agent.conf                    # Shared config (FIM directories) → ส่งให้ Agent ทุกตัว
├── ossec_manager_block.xml       # Block ที่ต้องวางใน ossec.conf ของ Manager
├── linux/
│   └── yara.sh                   # Active Response Script (ใช้ Docker Container สแกน)
├── yara/
│   ├── docker-compose.yml        # YARA Docker Container (สำหรับ Ubuntu Agent)
│   ├── yarawazuh.env             # Environment variables
│   ├── rules/                    # YARA Rules (ซิงก์จาก SOC กลาง)
│   ├── logs/                     # YARA scan logs
│   └── win/
│       ├── yara64.exe            # YARA Binary สำหรับ Windows (User ติดตั้งเอง)
│       ├── yarac64.exe           # YARA Compiler สำหรับ Windows
│       └── yara.bat              # Active Response Script for Windows
└── ossec_agent/                  # ตัวอย่าง ossec.conf เดิม (อ้างอิง)
```

---

## 🐧 Linux/Ubuntu Agent - ติดตั้งด้วย Docker

### ขั้นที่ 1: ติดตั้ง YARA Docker Container บนเครื่อง Agent

```bash
# สร้างโฟลเดอร์สำหรับ YARA Rules
mkdir -p /var/yara/rules /var/yara/logs

# Copy docker-compose.yml ไปวางที่เครื่อง Agent
# (หรือ Edge Connector จะทำให้อัตโนมัติ)
cd /var/yara
docker compose up -d
```

### ขั้นที่ 2: วาง Active Response Script

```bash
# Copy yara.sh ไปที่ active-response/bin ของ Wazuh Agent
cp yara.sh /var/ossec/active-response/bin/yara.sh
chmod 750 /var/ossec/active-response/bin/yara.sh
chown root:wazuh /var/ossec/active-response/bin/yara.sh
```

### ขั้นที่ 3: ตรวจสอบ YARA Rules

YARA Rules จะถูกซิงก์ผ่าน 2 ช่องทาง:
1. **Manager shared folder**: `/var/ossec/etc/shared/default/yara_rules.yar` → Agent ดึงลงไปเอง
2. **Docker volume**: `/var/yara/rules/` → ใช้กับ `docker exec yara yara ...`

### หลักการทำงาน

```
FIM ตรวจเจอไฟล์ใหม่ (Rule 554/550)
  └─→ Wazuh สั่ง Active Response: yara.sh (รันที่เครื่อง Agent)
        └─→ yara.sh เรียก Docker Container สแกนไฟล์
              ├─ CLEAN → เขียน Log (ไม่ทำอะไร)
              └─ MALWARE → ลบไฟล์ + เขียน Hash ลง Log
                    └─→ Wazuh Decoder อ่าน Log → ส่ง Alert กลับ Manager
                          └─→ Edge Connector POST Hash ไป SOC กลาง
```

---

## 🪟 Windows Agent - ติดตั้ง yara64.exe เอง

### ขั้นที่ 1: ติดตั้ง YARA Binary

```powershell
# สร้างโฟลเดอร์
New-Item -ItemType Directory -Path "C:\Program Files\yara" -Force
New-Item -ItemType Directory -Path "C:\Program Files\yara\rules" -Force

# Copy ไฟล์ YARA
Copy-Item yara64.exe "C:\Program Files\yara\yara64.exe"
Copy-Item yarac64.exe "C:\Program Files\yara\yarac64.exe"
เพิ่ม PATH 
เปิด
WIN+X
 Settings > System > About >Advaced System seting >Environment Variables>System Variable>Path>C:\Program Files\YARA






↓

เพิ่ม



```



### ขั้นที่ 2: วาง Active Response Script

```powershell
# Copy yara.bat ไปที่ active-response\bin ของ Wazuh Agent
Copy-Item yara.bat "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat"
```

### ขั้นที่ 3: ตรวจสอบ YARA Rules

Wazuh Manager (Edge) จะซิงก์ YARA rules จาก API ส่วนกลาง แล้วแจกจ่ายลง Windows Agent อัตโนมัติไปที่:
`C:\Program Files (x86)\ossec-agent\shared\yara_rules.yar`
ดังนั้นคุณไม่ต้อง copy ไฟล์ Rule เอง (สคริปต์ `yara.bat` ชี้เป้าไปที่โฟลเดอร์นี้เรียบร้อยแล้ว)

### หลักการทำงาน

```
FIM ตรวจเจอไฟล์ใหม่ (Rule 554/550) ทุกไดรฟ์ A:-Z:
  └─→ Wazuh สั่ง Active Response: yara.bat (รันที่เครื่อง Windows)
        └─→ yara.bat เรียก yara64.exe สแกนไฟล์
              ├─ CLEAN → เขียน Log
              └─ MALWARE → ลบไฟล์ + certutil คำนวณ Hash → เขียน Log
                    └─→ Wazuh Decoder อ่าน Log → ส่ง Alert กลับ Manager
```

---

## ⚙️ การตั้งค่า Manager (ossec.conf)

### 1. วาง agent.conf (Shared Config)

```bash
# Copy ไปที่ Manager shared folder
cp agent.conf /var/ossec/etc/shared/default/agent.conf
chown wazuh:wazuh /var/ossec/etc/shared/default/agent.conf
chmod 660 /var/ossec/etc/shared/default/agent.conf
```

Wazuh จะซิงก์ไฟล์นี้ลง Agent ทุกตัวอัตโนมัติ ประกอบด้วย:

| OS | FIM Directories | Filter |
|---|---|---|
| **Windows** | A: ถึง Z: (ทุกไดรฟ์) realtime | `.exe, .dll, .bat, .ps1, .vbs, .php, .msi, .scr, .lnk, .docm, .xlsm, .pptm` |
| **Linux** | `/opt, /var/www, /var/opt, /tmp, /home, /root, /srv` realtime | `.exe, .sh, .php, .py, .elf, .bin, .so, .war, .jar` |
| **Linux** | `/etc, /usr/bin, /usr/sbin, /bin, /sbin, /boot` periodic | All files |

### 2. วาง YARA Command Block ใน ossec.conf

เปิด `/var/ossec/etc/ossec.conf` แล้วนำเนื้อหาจาก `ossec_manager_block.xml` ไปวางก่อนปิด `</ossec_config>`

> ⚠️ **สำคัญ:** ตรวจสอบว่ามี Block นี้เพียงชุดเดียว (ลบที่ซ้ำออก)

### 3. Restart Wazuh Manager

```bash
systemctl restart wazuh-manager
```

---

## 🔍 ทดสอบ End-to-End

### Linux Agent

```bash
# สร้างไฟล์ทดสอบที่โฟลเดอร์ที่ FIM เฝ้าอยู่
echo '<?php eval($_POST["cmd"]); ?>' > /tmp/test_webshell.php

# รอ FIM ตรวจเจอ → ดู Log
tail -f /var/ossec/logs/active-responses.log
```

### Windows Agent

```powershell
# สร้างไฟล์ทดสอบ
Set-Content -Path "C:\temp\test_webshell.php" -Value '<?php eval($_POST["cmd"]); ?>'

# ดู Log
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Wait
```

---

**อัปเดตล่าสุด:** 2026-07-02
