#!/bin/bash
# active-response/bin/kill-process.sh
# Reads Wazuh AR JSON from stdin, kills the offending PID, logs result.

read INPUT_JSON
COMMAND=$(echo $INPUT_JSON | jq -r .command)
if [ "$COMMAND" = "add" ]; then
    PROCID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.audit.pid // .parameters.alert.data.audit.process.id // .parameters.alert.data.audit.process.pid // .parameters.alert.data.audit.execve.pid // .parameters.alert.data.process.id // .parameters.alert.data.process.pid // .parameters.alert.data.pid // .parameters.alert.data.win.eventdata.sourceProcessId // .parameters.alert.data.win.eventdata.processId // .parameters.extra_args[0] // empty')
    IMAGE=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.audit.exe // .parameters.alert.data.audit.command // .parameters.alert.data.win.eventdata.sourceImage // .parameters.alert.data.win.eventdata.image // empty')
    
    if [ -z "$PROCID" ] || [ "$PROCID" == "null" ]; then
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: No processID present in alert data — aborting." >> /var/ossec/logs/active-responses.log
        exit 0
    fi

    # Regulator & Hospital HIS Safeguard: Never kill critical OS, DB, HIS, Web, or Wazuh services
    PCOMM=$(ps -p "$PROCID" -o comm= 2>/dev/null || true)
    PROTECTED_HIS_REGEX="^(systemd|init|sshd|wazuh-.*|ossec-.*|auditd|mysqld|mariadb|postgres|postmaster|oracle|java|node|nginx|apache2|httpd|php-fpm|php|docker|containerd|dockerd|redis-server|mongod|hisservice|his-.*)$"
    if [[ "$PCOMM" =~ $PROTECTED_HIS_REGEX ]] || [ "$PROCID" -le 300 ]; then
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Safeguard: Skipped killing protected core/HIS process PID $PROCID ($PCOMM)." >> /var/ossec/logs/active-responses.log
        exit 0
    fi
    
    kill -9 "$PROCID" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Killed PID $PROCID ($IMAGE $PCOMM) in response to alert." >> /var/ossec/logs/active-responses.log
    else
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Failed to kill PID $PROCID (already exited or not found)" >> /var/ossec/logs/active-responses.log
    fi

    # Parent Process Inspection
    PPID_EXT=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.audit.ppid // .parameters.alert.data.audit.process.ppid // .parameters.alert.data.process.ppid // .parameters.alert.data.win.eventdata.parentProcessId // empty')
    if [ -n "$PPID_EXT" ] && [ "$PPID_EXT" != "null" ] && [ "$PPID_EXT" -gt 1 ]; then
        PNAME=$(ps -p "$PPID_EXT" -o comm= 2>/dev/null || true)
        if [[ "$PNAME" =~ $PROTECTED_HIS_REGEX ]] || [ "$PPID_EXT" -le 300 ]; then
            echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Safeguard: Skipped killing parent PID $PPID_EXT ($PNAME) because it is critical." >> /var/ossec/logs/active-responses.log
        else
            kill -9 "$PPID_EXT" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Killed parent PID $PPID_EXT ($PNAME) (Aggressive Response)." >> /var/ossec/logs/active-responses.log
            fi
        fi
    fi
fi
