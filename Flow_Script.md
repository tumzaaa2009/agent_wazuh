# 🚀 Hospital Edge Connector - Workflow, API Reference & Installation Guide

เอกสารนี้อธิบายรูปแบบข้อมูล การทำงาน และขั้นตอนการติดตั้ง **Hospital Edge Connector (Agent)** สำหรับเชื่อมต่อกับ **Central SOC (ส่วนกลาง)** เพื่อรับคำสั่งทำ **Active Response** (Global Block IP)

---

## 🛠️ ส่วนที่ 1: ขั้นตอนการติดตั้งสำหรับหน่วยบริการใหม่ (Installation Guide)

### 1. ตั้งค่าการอ่าน Log และ Active Response ใน Wazuh (`ossec.conf`)
เปิดไฟล์ `/var/ossec/etc/ossec.conf` แล้วตรวจสอบและนำโค้ดนี้ไปวางไว้ก่อนปิด Tag `</ossec_config>` สุดท้ายของไฟล์:

```xml
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100100</rules_id>
    <timeout>604800</timeout> <!-- บล็อกเป็นเวลา 7 วัน -->
  </active-response>
```

### 2. สร้าง Rule สำหรับดักจับคำสั่งบล็อกจาก SOC
เปิดไฟล์ `/var/ossec/etc/rules/local_rules.xml` แล้วเพิ่ม Rule รหัส `100100` ลงไป:
```xml
<group name="local,syslog,">
  <rule id="100100" level="10">
    <decoded_as>json</decoded_as>
    <field name="source">central_soc</field>
    <field name="command">firewall-drop</field>
    <description>Central SOC requested a firewall drop for IP: $(srcip)</description>
    <mitre>
      <id>T1036</id>
    </mitre>
  </rule>
</group>
```

### 3. Restart Wazuh Manager
เพื่อให้การตั้งค่าทั้งหมดมีผล ให้รันคำสั่ง:
```bash
systemctl restart wazuh-manager
```

### 4. ติดตั้งและตั้งค่า Edge Connector
นำ Source Code ของ Edge Connector ไปวางที่หน่วยบริการ (เช่น `/var/hospital-edge-connector`)
1. แก้ไขไฟล์ `.env` ให้ตรงกับข้อมูลของโรงพยาบาล:
   ```env
   HOSPITAL_CODE=รหัสโรงพยาบาล
   API_KEY=API_KEYของโรงพยาบาลนั้น
   ```
2. สั่งรัน Docker Container:
   ```bash
   cd /var/hospital-edge-connector
   docker compose up -d --build
   ```

**(เสร็จสิ้นการติดตั้ง! ระบบพร้อมทำงานและดึง Queue มาบล็อกทันที)**

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

## 🔍 ส่วนที่ 4: วิธีการทดสอบแบบ End-to-End (Checklist)

### ขั้นที่ 1: ตรวจสอบการทำงานของ Edge Connector
```bash
cd /var/hospital-edge-connector
docker logs --tail 20 hospital-edge-connector
```
> **สิ่งที่ต้องเห็น:** `✅ Connected to Central SOC WebSocket!` และมี Log แจ้งว่า "Successfully wrote log for IP" เมื่อมีคิวเข้ามา

### ขั้นที่ 2: ตรวจสอบว่า Rule ทำงานและเกิด Alert หรือไม่
```bash
tail -f /var/ossec/logs/alerts/alerts.json | grep 100100
```
> **สิ่งที่ต้องเห็น:** แจ้งเตือนรูปแบบ JSON ที่มี `rule.id: "100100"` และ IP ที่ถูกสั่งบล็อก

### ขั้นที่ 3: ตรวจสอบ Active Response และ Iptables
เมื่อ Alert ทำงาน Wazuh จะรันสคริปต์ Block ทันที
```bash
# เช็คประวัติการรันสคริปต์
tail -f /var/ossec/logs/active-responses.log
# เช็คตาราง iptables ว่าโดนบล็อกจริงหรือไม่
iptables -L INPUT -v -n | grep DROP
```
