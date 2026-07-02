# RH4 Centralized SOC - Master Architecture & Workflow

> [!IMPORTANT]
> เอกสารฉบับนี้เป็นการรวมเนื้อหาจากไฟล์ทั้งหมดที่คุณเคยมี (WorkFlow_OverAll, DiagramOnePage, Flow_Claude, how_to) เข้าไว้เป็น **ไฟล์เดียวที่อัปเดตล่าสุด** เพื่อป้องกันความสับสนในการทำงานต่อครับ

---

## 1. ข้อมูลระบบและสถาปัตยกรรม (System Infrastructure)
ศูนย์ปฏิบัติการเฝ้าระวังความมั่นคงปลอดภัยทางไซเบอร์ ระดับเขต (Centralized SOC RH4) ทำงานบนโครงสร้างแบบกระจายศูนย์ (Distributed) โดยมีระบบเครือข่ายดังนี้:

1. **Master Node:** `10.0.192.14` (Wazuh Master)
   - *UAT SSH Access:* `ssh root@10.0.192.14 -p 22` (Pass: `Su13540038`)
2. **Worker Node:** `10.0.192.15` (Wazuh Worker, Central API, Shuffle, TheHive, Cowrie) - IP จริง: `110.77.139.123`
   - *UAT SSH Access:* `ssh root@10.0.192.15 -p 22` (Pass: `Su13540038`)
3. **Cloud Gateway / Proxy:** `209.15.108.231` (โดเมน: `rh4cloudcenter.moph.go.th`) ทำหน้าที่เป็น Nginx Reverse Proxy
4. **Hospital Edge Node (SIEM หน่วยบริการ):** เครื่องที่หน่วยบริการ (เช่น `209.15.115.141`)
   - *UAT SSH Access:* `ssh root@209.15.115.141 -p 456` (Pass: `Su13540038`)

### การจัดการเส้นทาง (Routing & Reverse Proxy)
- **Nginx Proxy:** ถูกตั้งค่าแบบแยกย่อยตามแอปพลิเคชันใน `/var/WWW/ModDocker/conf/conf.d/`
- **SSH Tunnel:** มีการเชื่อมต่ออุโมงค์ผ่าน SSH เพื่อให้โดเมนหลักสามารถเรียกบริการภายใน `10.0.192.15` ได้อย่างปลอดภัย
- **WebApp AutoPentest:** เชื่อมต่อและแก้ปัญหา Timeout แล้ว ทำให้ระบบ Frontend และ API ภายในสื่อสารกันได้ปกติ

---

## 2. ลำดับการทำงานของระบบ (End-to-End Threat Response)

กระบวนการจัดการภัยคุกคามทำงานแบบ **Closed-Loop (ตรวจจับ -> สั่งการ -> รายงานผล)** โดยไม่ต้องอาศัยคนควบคุม:

1. **Detection (การตรวจจับ):**
   - ภัยคุกคามที่เกิดขึ้นที่หน่วยบริการ (Honeypot, OWASP, Suricata) รวมถึงการโจมตี 403 แบบ Brute-force หรือพบไฟล์มัลแวร์ในเครื่องลูกข่าย
   - Wazuh Manager (Master & Worker) จะประเมิน Level และ Groups หากพบความเสี่ยงสูง ระบบจะส่งข้อมูลไปให้ SOAR ทันที
2. **Analysis & Decision (n8n SOAR):**
   - n8n ทำการรับ Alert จาก Wazuh ผ่าน Webhook 
   - มีการยิง Trigger ผ่าน HTTP POST ไปยัง **Central SOC API** เพื่อสั่งการตอบโต้
3. **Queueing (SOC API & BullMQ):**
   - คำสั่งตอบโต้จะถูกบันทึกลง **PostgreSQL** ในสถานะ `queued` 
   - ข้อมูลผู้โจมตีอย่าง `attack_country` และ `attack_time` จะถูกบันทึกไว้ด้วย
4. **Execution (Edge Connector ที่ Hospital SIEM):**
   - สคริปต์ **Edge Connector** ที่เครื่องโรงพยาบาล จะดึงคำสั่งผ่าน WebSocket และทำงานร่วมกับ `agent_control` เพื่อบล็อก IP (Firewall-drop) ทันที
   - **YARA Full-Loop Integration:** Edge Connector จะทำการดาวน์โหลด YARA Rules กลางจาก SOC API ไปไว้ที่หน่วยบริการแบบอัตโนมัติ เพื่อให้ Agent ฝั่งโรงพยาบาลรันสแกนไฟล์ไวรัสได้ทันที
5. **Feedback Loop (Tracking & Intelligence Sync):**
   - Edge Connector ยิง API แจ้งเตือนสถานะการบล็อกกลับมาที่ศูนย์กลางว่า `received` และ `executed` (บล็อกสำเร็จ) 
   - หากเป็นการสแกนเจอไวรัส Edge Connector จะส่งข้อมูล Hash ของไฟล์ที่พบ กลับไปที่ `POST /api/v1/malware-events` เพื่อบันทึกเข้าฐานข้อมูลกลาง (PostgreSQL) และถูกนำไปสร้างเป็น CDB List (Threat Intelligence) ให้ระบบส่วนกลางรู้จักไวรัสตัวนั้นโดยอัตโนมัติ

---

## 3. โครงสร้างฐานข้อมูล (PostgreSQL Database Schema)
ระบบใช้ Prisma ในการจัดการ Database โดยมีการอัปเดต Schema ล่าสุดเพื่อรองรับการเก็บข้อมูลผู้โจมตีและการติดตามคิวที่แม่นยำขึ้น:

```prisma
model ActiveResponseLog {
  id              Int       @id @default(autoincrement())
  hospital_id     Int
  agent_id        String?
  rule_id         String?
  rule_description String?
  srcip           String
  command         String
  timeout         Int?
  status          String    @default("queued") // สถานะ: queued, received, executed, failed
  attack_country  String?   // ประเทศของผู้โจมตี
  attack_time     DateTime? // วันเวลาที่เกิดการโจมตีจริง
  location        String?   // เส้นทางไฟล์ Log ต้นทาง (เช่น /var/log/auth.log)
  full_log        String?   // ข้อความ Log ฉบับเต็มจากระบบ
  created_at      DateTime  @default(now())
  executed_at     DateTime?
}

model SystemLog {
  id          Int      @id @default(autoincrement())
  level       String   // info, warn, error
  module      String   // API, CronWorker, BullMQ, WebSocket
  event       String   // e.g. "ar_received", "fetch_success"
  message     String
  metadata    Json?    // ข้อมูลเพิ่มเติม
  created_at  DateTime @default(now())
}
```

---

## 4. API Reference (สำหรับ Edge Connector และ n8n)

### 4.1 ขาเข้า (Triggering from n8n)
`POST https://rh4cloudcenter.moph.go.th/api/v1/active-response/trigger`
```json
{
  "hospital_code": "141",
  "srcip": "1.2.3.4",
  "command": "firewall-drop",
  "attack_country": "Russia",
  "attack_time": "2026-06-20T10:00:00Z",
  "location": "/var/log/auth.log",
  "full_log": "sshd: Failed password for root from 1.2.3.4 port 22 ssh2"
}
```

### 4.2 ขาตอบกลับ (Status Callback from Edge Connector)
ระบบรองรับทั้ง **WebSocket** และ **HTTP REST API** เพื่อความเสถียรสูงสุด:

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

### 4.3 ระบบดึง Log สำหรับโรงพยาบาลลูกข่าย (Pull-Worker)
หากโรงพยาบาลใดใช้ระบบของตนเอง SOC ส่วนกลางจะมี **Cron Worker** วิ่งไปดูดข้อมูล Log (ผ่าน OpenSearch API) ทุกๆ 5 นาที และคัดกรอง Level >= 5 หรือ Groups ของเว็บ (OWASP/ModSec) เพื่อ Forward ส่งให้ n8n เองโดยอัตโนมัติ

---

## 5. คู่มือการเข้าใช้งานระบบ (Access Information)

คุณสามารถเข้าใช้งานระบบต่างๆ ได้ตามตารางด้านล่าง:

| ระบบ (Service) | URL | หมายเหตุ / รหัสผ่าน |
| --- | --- | --- |
| **Wazuh Dashboard** | `https://rh4cloudcenter.moph.go.th/` | ศูนย์กลางมอนิเตอร์ |
| **Shuffle (SOAR)** | `http://10.0.192.15:3001` | หน้าเว็บสำหรับสร้าง Automation (ต้องใช้ VPN หรือ Network ภายใน) |
| **The Hive** | `http://10.0.192.15:9000` | ระบบจัดการ Case (Default: `admin` / `secret`) |
| **Cortex** | `http://10.0.192.15:9001` | ระบบวิเคราะห์ข้อมูลเชิงลึก |
| **Cowrie (Honeypot)**| `ssh root@10.0.192.15 -p 2222` | เซิร์ฟเวอร์หลอกสำหรับรับการโจมตี (ไม่ใช่ Web) |
| **n8n Webhook** | `https://rh4cloudcenter.moph.go.th/n8n/` | โฟลว์หลักที่รับ Alert จาก Wazuh ทั่วเขต |

---
**อัปเดตล่าสุด:** 2026-06-20
**สถานะระบบ:** บูรณาการ ModSecurity, Suricata, OWASP (403) สำเร็จ และมีระบบแทร็กประวัติการ Block IP ครบวงจร
