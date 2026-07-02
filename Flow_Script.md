# 🚀 Hospital Edge Connector - Workflow, API Reference & Installation Guide

เอกสารนี้อธิบายรูปแบบข้อมูล การทำงาน และขั้นตอนการติดตั้ง **Hospital Edge Connector (Agent)** สำหรับเชื่อมต่อกับ **Central SOC (ส่วนกลาง)** เพื่อรับคำสั่งทำ **Active Response** (Global Block IP) และการทำ **Native YARA Scanning** แบบ Zero-Config

---

## 🛠️ ส่วนที่ 1: ขั้นตอนการติดตั้งสำหรับหน่วยบริการใหม่ (Installation Guide)

### 1. ดาวน์โหลดและแตกไฟล์ Hospital Edge Connector
โหลดไฟล์แพ็กเกจจากศูนย์กลาง ซึ่งจะมี Source Code และเครื่องมือทุกอย่างครบถ้วน:
```bash
wget https://rh4cloudcenter.moph.go.th/api/v1/yara-rules/hospital_edge_connector.zip
unzip hospital_edge_connector.zip
cd agent_wazuh
```

### 2. ตั้งค่าการเชื่อมต่อ (Edit `.env`)
เปิดไฟล์ `.env` ขึ้นมา แล้วแก้ไขค่าให้ตรงกับข้อมูลของโรงพยาบาล:
```env
HOSPITAL_CODE=รหัสโรงพยาบาล (เช่น 141)
HOSPITAL_NAME=ชื่อโรงพยาบาล
API_KEY=API_KEYสำหรับเชื่อมต่อส่วนกลาง
```

### 3. ตั้งค่าระบบ Wazuh (แค่ครั้งเดียว)
เปิดไฟล์ `/var/ossec/etc/ossec.conf` ของเครื่อง SIEM โรงพยาบาล แล้วนำโค้ดในไฟล์ **`agent_mockup.xml`** ไปแปะไว้ก่อนปิด Tag `</ossec_config>` ในไฟล์

*(หมายเหตุ: โรงพยาบาลไม่ต้องสร้าง Rule หรือ Decoder ใดๆ ด้วยตัวเอง เพราะระบบ Edge Connector จะเป็นคนดึง Rule จากศูนย์กลางมาลงให้ในขั้นตอนถัดไป)*

### 4. ติดตั้งสคริปต์ YARA Quarantine (ทางเลือก)
หากต้องการให้ระบบ "กักกัน/ลบมัลแวร์" โดยอัตโนมัติ ให้ก๊อปปี้ไฟล์สคริปต์ไปไว้ในโฟลเดอร์ Active Response:
```bash
cp deploy_yara_windows.ps1 deploy_yara_linux.sh /var/ossec/active-response/bin/
chmod 750 /var/ossec/active-response/bin/deploy_yara_linux.sh
```

### 5. สั่งรัน Edge Connector
เริ่มการทำงานของ Edge Connector ซึ่งจะไปดึง Rule แรกเริ่มมาทับลง Wazuh ให้ทันที:
```bash
docker compose up -d --build
```

**(เสร็จสิ้นการติดตั้ง! ระบบพร้อมทำงาน ดึง Rule อัตโนมัติ และเชื่อมต่อ WebSocket ทันที)**

---

## 📡 ส่วนที่ 2: รูปแบบการทำงานและ API Reference

### 2.1 การเชื่อมต่อผ่าน WebSocket (Realtime Push)
Edge Connector ทำการเชื่อมต่อ WebSocket ไปยังส่วนกลางแบบเปิดค้างไว้ เมื่อมีเหตุการณ์โจมตี SOC จะ Push ข้อมูลสั่งการลงมา
**URL:** `wss://rh4cloudcenter.moph.go.th/ws/active-response`

**Payload ขาเข้า (จาก SOC -> Edge Connector):**
```json
{
  "action": "execute_active_response",
  "payload": {
    "log_id": 9999,
    "command": "soc-firewall-drop",
    "arguments": ["8.8.8.8", "3600"],
    "agent_id": "001",
    "agent_name": "MophRh4"
  }
}
```

**Payload ขาเข้า (คำสั่งสแกน YARA):**
```json
{
  "action": "execute_active_response",
  "payload": {
    "log_id": 10000,
    "command": "yara-scan",
    "arguments": ["/var/www/html/upload/shell.php"],
    "agent_id": "000"
  }
}
```

**Payload ขาตอบกลับ (จาก Edge Connector -> SOC) แบบ WebSocket เพื่อ Ack สถานะ:**
```json
{
  "type": "ack",
  "hospital_code": "141",
  "status": "success",
  "log_id": 9999
}
```

### 2.2 การตอบกลับสถานะผ่าน HTTP REST API (Status Callback)
นอกจากการส่งผ่าน WebSocket แล้ว Edge Connector ยังสามารถยิง API แจ้งสถานะกลับไปยัง SOC แบบละเอียดได้:

**1. แจ้งว่าได้รับคำสั่ง (Received):**
`POST https://rh4cloudcenter.moph.go.th/api/v1/active-response/receive`
```json
{
  "log_id": 9999,
  "hospital_code": "141"
}
```

**2. แจ้งว่าบล็อกสำเร็จ (Success/Executed):**
`POST https://rh4cloudcenter.moph.go.th/api/v1/active-response/success`
```json
{
  "log_id": 9999,
  "hospital_code": "141"
}
```

### 2.3 การดึงข้อมูลคิวผ่าน REST API (Polling) - ทางเลือก
หากไม่ใช้ WebSocket สามารถใช้ API ดึงคิวงาน (Queue) มาประมวลผลแทนได้ โดยใช้ `GET` ไปที่ Endpoint:
`https://rh4cloudcenter.moph.go.th/api/v1/active-response/queues?hospital_code={HOSPITAL_CODE}`
และเคลียร์ Queue โดยใช้ `DELETE` เมื่อดำเนินการสำเร็จ

---

## ⚙️ ส่วนที่ 3: กระบวนการประมวลผลฝั่ง Edge Connector สู่ Wazuh

ระบบ Edge Connector ถูกออกแบบการทำงานเป็นแบบ **Hybrid** เพื่อรองรับการสั่งการทั้งลูกข่าย (Remote Agents) และเครื่องหลัก (Manager) ได้อย่างสมบูรณ์แบบ โดยมีกลไกดังนี้:

**กรณีที่ 1: สั่งบล็อกเครื่องลูกข่าย (Agent ID: 001, 002, ...)**
1. **รับข้อมูลจาก SOC:** Edge Connector ได้รับคำสั่งบล็อก IP พร้อมระบุ `agent_id`
2. **ส่งคำสั่งผ่านเครือข่าย Wazuh:** ระบบจะรันคำสั่ง `/var/ossec/bin/agent_control -b {IP} -f firewall-drop -u {agent_id}`
3. **Agent ลูกข่ายทำงาน:** เครื่องลูกข่ายได้รับคำสั่ง บล็อก IP และเริ่มนับเวลาถอยหลังปลดบล็อก

**กรณีที่ 2: สั่งบล็อกเครื่องหลัก (Agent ID: 000 / Manager)**
เพื่อเลี่ยงข้อจำกัดการเชื่อมต่อภายในของ Manager เอง ระบบจะเปลี่ยนไปใช้วิธี **รันสคริปต์บล็อกโดยตรง (Direct Script Execution)** แทน:
1. **รับข้อมูลจาก SOC:** Edge Connector ได้รับคำสั่งบล็อก IP โดยระบุ `agent_id: "000"`
2. **รันสคริปต์แบบ Bypass:** โค้ดจะสร้าง Payload แล้วส่งเข้าสคริปต์ของ Wazuh โดยตรง (`/var/ossec/active-response/bin/firewall-drop`) ผ่านคำสั่ง `add` ตามด้วย `continue`
3. **ผลลัพธ์:** สคริปต์จะทำการอัปเดต `iptables` ให้ทันทีโดยไม่ต้องรอระบบ wazuh-execd
*(หมายเหตุ: การรันตรงแบบนี้จะทำให้ไม่มีการปลดบล็อก IP อัตโนมัติตาม Timeout ของระบบ Wazuh)*

---

## 🦠 ส่วนที่ 4: กระบวนการทำงานของ YARA Native Scan และ Auto Quarantine (Full-Loop)

ระบบมีความสามารถในการตรวจจับมัลแวร์ในตัวเอง และจัดการไฟล์อันตรายได้แบบ End-to-End พร้อมระบบรายงาน Hash:
1. **Auto-Update YARA Rules (Sync):** ระบบ Edge Connector จะดึงไฟล์ YARA Rules ล่าสุดจาก `https://rh4cloudcenter.moph.go.th/api/v1/yara-rules` มาเก็บไว้ที่ `/var/ossec/etc/shared/default/yara_rules.yar` บน Host เพื่อให้ Wazuh ซิงก์ลงไปยัง Agent อัตโนมัติ
2. **Global Drive Scanning:** ที่เครื่องลูกข่าย (Windows/Linux) ระบบ FIM จะเฝ้าระวังไฟล์รันเนเบิล (exe, dll ฯลฯ) ทันทีที่ไฟล์ตกถึงพื้น จะเรียกสคริปต์ YARA สแกนแบบออฟไลน์ด้วย Rule ล่าสุด
3. **Auto Quarantine (ลบอัตโนมัติ):** เมื่อพบว่าเป็นมัลแวร์ สคริปต์ Active Response (เช่น `yara.sh`) จะสั่งลบไฟล์ต้นทางหรือกักกันทันที
4. **Malware Hash Reporting (Threat Intel):** หลังจากลบสำเร็จ Edge Connector จะทำการ POST ข้อมูล Hash ของมัลแวร์นั้นๆ กลับไปที่ `https://rh4cloudcenter.moph.go.th/api/v1/malware-events` เพื่อนำไปอัปเดตเป็นฐานข้อมูล CDB ส่วนกลางของเขตสุขภาพต่อไป

---

## 🔄 ส่วนที่ 5: ระบบแจกจ่าย Rule และ Decoder อัตโนมัติ (Zero-Touch SOC Sync)

Edge Connector จะทำหน้าที่ดึง Rule และ Decoder ใหม่ๆ จาก SOC มาติดตั้งที่โรงพยาบาลโดยอัตโนมัติ:
1. แอดมินส่วนกลางเพิ่มไฟล์ที่ขึ้นต้นด้วย `soc_` (เช่น `soc_yara.xml`) เข้าโฟลเดอร์ส่วนกลาง
2. Edge Connector จะดึงไฟล์ `soc_configs.zip` จาก `https://rh4cloudcenter.moph.go.th/api/v1/wazuh-configs` ทุกๆ 24 ชั่วโมง
3. ระบบจะแตกไฟล์ลง `/var/ossec/etc/rules/` และ `/var/ossec/etc/decoders/`
4. ทำการ Restart Wazuh Manager อัตโนมัติ เพื่อให้ Rule ชุดใหม่ทำงาน (โดยไม่กระทบ Rule เดิมของโรงพยาบาล)

---

## 🔍 ส่วนที่ 6: วิธีการทดสอบแบบ End-to-End (Checklist)

### 🔑 ข้อมูลการเข้าถึง UAT (Hospital Edge SIEM)
หากต้องการทดสอบหรือแก้บั๊กบนเครื่องจำลองของโรงพยาบาล (Hospital SIEM) สามารถเข้าผ่าน SSH ได้ดังนี้:
- **IP / Port:** `209.15.115.141` พอร์ต `456`
- **Username / Password:** `root` / `Su13540038`

### ขั้นที่ 1: ตรวจสอบการทำงานของ Edge Connector
```bash
cd /var/hospital-edge-connector
docker logs --tail 20 hospital-edge-connector
```
> **สิ่งที่ต้องเห็น:** `✅ Connected to Central SOC WebSocket!` และมี Log แจ้งว่า "Successfully wrote log for IP" เมื่อมีคิวเข้ามา

### ขั้นที่ 2: ตรวจสอบว่า Rule ทำงานและเกิด Alert หรือไม่
```bash
tail -f /var/ossec/logs/alerts/alerts.json | grep 110100
```
> **สิ่งที่ต้องเห็น:** แจ้งเตือนรูปแบบ JSON ที่มี `rule.id: "110100"` และ IP ที่ถูกสั่งบล็อก

### ขั้นที่ 3: ตรวจสอบ Active Response และ Iptables
เมื่อ Alert ทำงาน Wazuh จะรันสคริปต์ Block ทันที
```bash
# เช็คประวัติการรันสคริปต์
tail -f /var/ossec/logs/active-responses.log
# เช็คตาราง iptables ว่าโดนบล็อกจริงหรือไม่
iptables -L INPUT -v -n | grep DROP
```
