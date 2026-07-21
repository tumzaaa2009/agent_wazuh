#!/bin/bash
echo "Downloading Emerging Threats Suricata ruleset..."
cd /tmp/
curl -LO https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz
# Extract and move to rules directory
tar -xvzf emerging.rules.tar.gz
echo "Moving rules to /var/suricata/rules/"
# The user wants them mapped to /etc/suricata/ and specified as emerging-all.rules
# The tarball usually contains a rules/ folder with multiple files. 
# We can concatenate them into emerging-all.rules as requested.
# Support running on host or inside container
if [ -d "/etc/suricata/rules" ]; then
    DEST="/etc/suricata/rules"
else
    DEST="/var/opt/suricata/rules"
fi

cat rules/*.rules > $DEST/emerging-all.rules
chmod 640 $DEST/emerging-all.rules
echo "Rules downloaded and prepared in $DEST/emerging-all.rules"

# If running on host and suricata container exists, reload it
if command -v docker >/dev/null 2>&1 && docker ps | grep -q suricata; then
    echo "Reloading Suricata rules..."
    docker kill -s USR2 suricata
fi
