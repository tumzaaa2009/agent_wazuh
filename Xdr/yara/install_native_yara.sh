#!/bin/bash
set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
LOG_FILE="${SCRIPT_DIR}/status_install.log"
# Redirect stdout and stderr to both terminal and log file
exec > >(tee -i "$LOG_FILE") 2>&1

# Function to display installation status phase
print_status() {
    echo -e "\n========================================================"
    echo " [*] PHASE: $1"
    echo "========================================================"
}

echo "========================================================"
echo "      Auto-Installer: Wazuh YARA Active Response        "
echo "      Logging to: $LOG_FILE                             "
echo "========================================================"

print_status "1. OS Detection"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo "[*] Detected OS: $OS"
else
    echo "[!] Cannot detect OS (/etc/os-release not found). Assuming generic Linux."
    OS="unknown"
fi

print_status "2. Install Dependencies"
case $OS in
    ubuntu|debian)
        echo "[*] Removing old yara..."
        apt-get remove --purge -y yara || true
        apt-get autoremove -y

        echo "[*] Installing dependencies via apt-get..."
        apt-get update
        if apt-get install -y make gcc autoconf libtool libssl-dev pkg-config jq curl; then
            echo "[*] Dependencies installed successfully."
        else
            echo "[!] Failed to install dependencies."
            exit 1
        fi
        ;;
    centos|rhel|fedora|rocky|almalinux)
        echo "[*] Removing old yara..."
        yum remove -y yara || true

        echo "[*] Installing dependencies via yum..."
        yum install -y epel-release || true
        yum groupinstall -y "Development Tools"
        if yum install -y autoconf libtool openssl-devel jq curl file-devel; then
            echo "[*] Dependencies installed successfully."
        else
            echo "[!] Failed to install dependencies."
            exit 1
        fi
        ;;
    *)
        echo "[!] Unknown or unsupported OS '$OS'. Attempting to continue assuming dependencies are met..."
        ;;
esac

print_status "3. Build & Install Yara 4.5.5 from source"
echo "[*] Downloading Yara source..."
cd /usr/local/src
curl -LO https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz
tar -xzf v4.5.5.tar.gz
cd yara-4.5.5

echo "[*] Compiling Yara..."
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make
make install
ldconfig
echo "[*] Yara compiled and installed successfully."

print_status "4. Configure Wazuh Active Response Script"

WAZUH_GID=$(getent group wazuh | cut -d: -f3)
[ -z "$WAZUH_GID" ] && WAZUH_GID="wazuh"

for SRC in "${SCRIPT_DIR}"/*.sh; do
    SCRIPT_NAME=$(basename "$SRC")
    if [ "$SCRIPT_NAME" = "install_native_yara.sh" ]; then
        continue
    fi
    
    DEST="/var/ossec/active-response/bin/${SCRIPT_NAME}"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$DEST"
        chown root:"$WAZUH_GID" "$DEST"
        chmod 750 "$DEST"
        echo "[*] Script copied to $DEST and permissions (-rwxr-x--- root:wazuh) applied."
    else
        echo "[!] Source script $SRC not found, skipping copy."
    fi
done

print_status "5. Configure Auditd Rules (C2/Exec Dropzone)"
RULE_SRC="${SCRIPT_DIR}/c2-exec.rules"
RULE_DEST="/etc/audit/rules.d/c2-exec.rules"
if [ -f "$RULE_SRC" ]; then
    cp "$RULE_SRC" "$RULE_DEST"
    echo "[*] Rule copied to $RULE_DEST"
    
    echo "[*] Reloading auditd rules..."
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load
    elif command -v auditctl >/dev/null 2>&1; then
        auditctl -R "$RULE_DEST"
    fi
    
    echo "[*] Restarting auditd service..."
    systemctl restart auditd || service auditd restart || true
    echo "[*] Auditd configured successfully."
else
    echo "[!] Rule file $RULE_SRC not found, skipping auditd setup."
fi

print_status "6. Test Yara Rule"
if yara /var/ossec/etc/shared/yara_rules.yar /dev/null 2>/dev/null; then
    echo "[*] Yara rule test passed."
else
    echo "[!] Yara rule test failed or no rules file found (ignoring error, assuming Wazuh Manager will push them)."
fi

print_status "COMPLETE!"
echo "[*] Installation Successfully Completed."
echo "[*] You can review this run's log at: $LOG_FILE"