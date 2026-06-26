# 📦 Hospital Edge Connector - Version History (Changelog)

เอกสารนี้ใช้สำหรับติดตามประวัติการอัปเดตและฟีเจอร์ที่ถูกปรับปรุงในแต่ละเวอร์ชันของ Edge Connector ครับ

---
## 📡 v1.2.1 (Latest) - HTTP REST API Success ACK
**Date:** 2026-06-20
- 🌐 **Bug Fix agent ไม่ดึง Rule ของส่วนกลาง

---
## 📡 v1.2.0  - HTTP REST API Success ACK
**Date:** 2026-06-20
- 🌐 **Add HTTP Success Callback:** เพิ่มการยิง API แจ้งเตือนสถานะความสำเร็จ (`active-response/success`) กลับไปยังฝั่ง Core/Central SOC ทันทีหลังจากที่ Edge Connector บล็อก IP เรียบร้อยแล้ว เพื่อให้ Dashboard ฝั่งส่วนกลางอัปเดตสถานะแบบ Real-time

---

## 🚀 v1.1.1 - Cleanup & Documentation Update
**Date:** 2026-06-20
- 🧹 ลบโฟลเดอร์ `out/` ที่เกิดจากการรัน Pipeline Test ทิ้งเพื่อประหยัดพื้นที่
- 🙈 เพิ่มโฟลเดอร์ `out/` ลงใน `.gitignore` เพื่อไม่ให้เผลอเอาขึ้น Git
- 📝 อัปเดตคู่มือ `Flow_Script.md` ให้สะท้อนการทำงานแบบ "รันสคริปต์ตรง" (Direct Script Execution) สำหรับ Agent 000 ตามโค้ดล่าสุด

---

## 🛠️ v1.1.0 - Hybrid Architecture & Agent 000 Fix
**Date:** 2026-06-20
- 🐛 **Fix Wazuh Manager Bug:** แก้ปัญหา `agent_control` ค้นหา Agent ID 000 ไม่เจอในระบบ Wazuh 4.x
- ⚡ **Hybrid Execution Flow:**
  - **สำหรับเครื่องลูกข่าย (Agent 001+):** ใช้งานคำสั่งผ่านเครือข่ายด้วย `agent_control` ตามมาตรฐาน
  - **สำหรับเครื่องแม่ข่าย (Agent 000):** ใช้การยิง Payload (`add`, `continue`) ตรงเข้าสคริปต์ `/var/ossec/active-response/bin/firewall-drop` เพื่อให้บล็อกผ่าน iptables ได้ทันที (Bypass wazuh-execd)
- 🧹 เขียนสคริปต์ล้างข้อมูลที่ซ้ำซ้อนใน iptables (Deduplication) เพื่อให้มี IP ละ 1 กฎเท่านั้น

---

## 🔌 v1.0.1 - Array Payload & Polling Fallback
**Date:** 2026-06-19
- 🔄 เพิ่มระบบรองรับการรับ Queue ข้อมูลแบบ Array Payload จาก Central SOC
- 📥 เพิ่มทางเลือกในการดึงข้อมูลแบบ HTTP API Pulling (Polling) เผื่อกรณี WebSocket มีปัญหา 

---

## 🎉 v1.0.0 - Initial Release
**Date:** 2026-06-19
- 🏗️ สร้างโครงสร้างแอปพลิเคชันด้วย Bun & TypeScript
- 🔗 เชื่อมต่อ WebSocket กับ Central SOC (`wss://rh4cloudcenter.moph.go.th/ws/active-response`)
- 🛡️ รองรับคำสั่ง `soc-firewall-drop` / `firewall-drop`
- 📨 ส่งสถานะการรับคำสั่งกลับ (ACK Payload) ไปยัง SOC
