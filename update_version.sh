#!/bin/bash



echo "Building and restarting Docker container..."
# 1. หยุด Container ที่รันอยู่
docker compose down 

# 2. เคลียร์ขยะและลบ Image เก่าที่ไม่ได้ใช้งานทั้งหมด (บังคับลบด้วย -f)
echo "Cleaning up old docker images..."
docker system prune -a -f

# 3. สั่ง Build ใหม่โดยไม่ใช้ Cache เก่า
echo "Rebuilding completely fresh..."
docker compose build --no-cache

# 4. เริ่มต้น Container ใหม่
docker compose up -d

echo "✅ Container restarted successfully."
echo "Master API is now serving the updated code."

echo "Restarting Wazuh Manager..."
SYSTEMD_IGNORE_CHROOT=1 systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart
if [ $? -ne 0 ]; then
    echo "❌ [CRITICAL ERROR] Failed to restart Wazuh Manager!"
    exit 1
fi
echo "✅ Wazuh Manager restarted successfully."
