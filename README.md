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

**Payload ขาตอบกลับ (จาก Edge Connector -> SOC) เพื่อ Ack ว่ารับคำสั่งแล้ว:**
```json
{
  "type": "ack",
  "hospital_code": "141",
  "status": "success",
  "log_id": 9999
}
```

### 2.2 การดึงข้อมูลผ่าน REST API (Polling) - ทางเลือก
หากไม่ใช้ WebSocket สามารถใช้ API ดึงคิวงาน (Queue) มาประมวลผลแทนได้ โดยใช้ `GET` ไปที่ Endpoint:
`https://rh4cloudcenter.moph.go.th/api/v1/active-response/queues?hospital_code={HOSPITAL_CODE}`
และเคลียร์ Queue โดยใช้ `DELETE` เมื่อดำเนินการสำเร็จ

---

## ⚙️ ส่วนที่ 3: กระบวนการประมวลผลฝั่ง Edge Connector สู่ Wazuh

เพื่อลดปัญหาความเข้ากันได้ของระบบคำสั่ง Edge Connector จะไม่สั่งรัน Script โดยตรง แต่จะใช้การ**เขียน Log** เข้าสู่ Wazuh เพื่อให้ Manager ตรวจจับและสั่ง Block ผ่าน Flow มาตรฐาน:

1. **รับข้อมูลจาก SOC:** Edge Connector ได้รับคำสั่งบล็อก IP
2. **เขียน Log ทันที:** โค้ดจะนำ IP และ Timestamp มาจัดรูปแบบ JSON แล้วเขียนบันทึกลงใน `/var/ossec/logs/active-responses.log` (ผ่าน Volume Mount)
   *ตัวอย่างข้อมูลที่ถูกเขียน:*
   `{"timestamp":"2026-06-19T10:00:00.000Z","source":"central_soc","command":"firewall-drop","srcip":"8.8.8.8","timeout":604800,"log_id":9999}`
3. **Wazuh ตรวจจับ:** Wazuh Manager (ผ่าน localfile syslog) จะอ่าน Log นั้น, ถอดรหัสผ่าน JSON Decoder, และ Trigger เข้า Rule รหัส `100100`
4. **ทำ Active Response:** Wazuh ยิงคำสั่ง `firewall-drop` เพื่อบล็อก IP นั้นด้วย iptables เป็นระยะเวลา 7 วัน (`604800`) ตามที่คอนฟิกไว้

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
