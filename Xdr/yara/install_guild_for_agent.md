# คู่มือการติดตั้ง YARA Active Response บนเครื่อง Agent (Linux)

เอกสารนี้อธิบายขั้นตอนการติดตั้ง YARA สำหรับทำ Active Response และการตั้งค่า Auditd บนเครื่อง Wazuh Agent เพื่อตรวจจับและจัดการมัลแวร์แบบเรียลไทม์

---

## 📋 สิ่งที่ต้องเตรียม (Prerequisites)
ก่อนเริ่มติดตั้ง ให้นำไฟล์ต่อไปนี้ไปวางไว้ที่เครื่อง Agent โดย**ให้อยู่ในโฟลเดอร์เดียวกันทั้งหมด** (เช่น สร้างโฟลเดอร์ `/tmp/yara_install`):
1. ไฟล์ `install_native_yara.sh` 
2. ไฟล์สคริปต์ `yara.sh` 
3. ไฟล์ `c2-exec.rules`

---

## ⚙️ ขั้นตอนการติดตั้ง

เข้าไปที่โฟลเดอร์ที่เก็บไฟล์ไว้ และรันสคริปต์ติดตั้งด้วยสิทธิ์ `root`:
```bash
sudo bash install_native_yara.sh
```

**สิ่งที่สคริปต์ตัวนี้จะทำให้แบบอัตโนมัติ (Automated Phases):**
- **Phase 1:** ตรวจจับ OS ของเครื่องอัตโนมัติ (Ubuntu/CentOS ฯลฯ)
- **Phase 2:** ดาวน์โหลดและติดตั้ง Packages ที่จำเป็น
- **Phase 3:** Compile YARA 4.5.5
- **Phase 4:** คัดลอกและตั้งค่าสิทธิ์ไฟล์ `yara.sh`
- **Phase 5:** โหลด Auditd Rule (`c2-exec.rules`) และรีสตาร์ท Service 
- **Phase 6:** ทดสอบระบบ

💡 **การดูสถานะ:** 
คุณสามารถเช็คสถานะการรันสคริปต์ได้แบบเรียลไทม์ (หรือดูย้อนหลัง) ที่ไฟล์ log ซึ่งจะถูกสร้างในโฟลเดอร์เดียวกันกับสคริปต์:
```bash
tail -f status_install.log
```
**✅ การตรวจสอบความถูกต้องเบื้องต้น (Verification):**
1. เช็คว่าไฟล์ YARA ถูกสร้างและสิทธิ์ถูกต้อง:
```bash
ls -la /var/ossec/active-response/bin/yara.sh
```
2. เช็คว่าระบบได้โหลด Audit Rule เข้าไปแล้ว:
```bash
sudo auditctl -l | grep c2_exec_dropzone
```

---

## 📂 ขั้นตอนที่ 2: ตรวจสอบ YARA Rules (ฝั่ง Agent)

โดยปกติ Wazuh Manager จะทำการส่งไฟล์ Rules ผ่านโฟลเดอร์ `shared` มาให้ Agent อัตโนมัติ 
ให้ตรวจสอบว่าบนเครื่อง Agent มีไฟล์ Rules ของ YARA อยู่หรือไม่:
```bash
ls -la /var/ossec/etc/shared/yara_rules.yar
# หรือ
ls -la /var/ossec/etc/shared/default/yara_rules.yar
```
*(ถ้ายังไม่มี ให้ตรวจสอบการตั้งค่า Centralized Configuration บน Wazuh Manager เพื่อให้ Push ไฟล์ลงมา)*

---
🎉 **เสร็จสิ้นการติดตั้ง!** ตอนนี้เครื่อง Agent พร้อมทำการตอบสนองภัยคุกคาม (Active Response) อัตโนมัติด้วย YARA แล้วครับ