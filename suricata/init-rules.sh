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
cat rules/*.rules > /var/suricata/rules/emerging-all.rules
chmod 640 /var/suricata/rules/emerging-all.rules
echo "Rules downloaded and prepared in /var/suricata/rules/emerging-all.rules"
