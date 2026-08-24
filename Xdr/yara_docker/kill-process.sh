#!/bin/bash
# active-response/bin/kill-process.sh
# Reads Wazuh AR JSON from stdin, kills the offending PID, logs result.

read INPUT_JSON
COMMAND=$(echo $INPUT_JSON | jq -r .command)
if [ "$COMMAND" = "add" ]; then
    PROCID=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.win.eventdata.sourceProcessId // .parameters.alert.data.win.eventdata.processId // .parameters.alert.data.audit.process.pid // empty')
    IMAGE=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.win.eventdata.sourceImage // .parameters.alert.data.win.eventdata.image // empty')
    
    if [ -z "$PROCID" ]; then
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: No processID present in alert data — aborting." >> /var/ossec/logs/active-responses.log
        exit 1
    fi
    
    kill -9 $PROCID
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Killed PID $PROCID ($IMAGE) in response to alert." >> /var/ossec/logs/active-responses.log
    else
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Failed to kill PID $PROCID" >> /var/ossec/logs/active-responses.log
    fi

    # Aggressive Response: Kill parent process
    PPID_EXT=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.win.eventdata.parentProcessId // .parameters.alert.data.audit.process.ppid // empty')
    if [ -n "$PPID_EXT" ] && [ "$PPID_EXT" != "null" ]; then
        PNAME=$(ps -p $PPID_EXT -o comm= 2>/dev/null)
        if [[ "$PNAME" =~ ^(systemd|init|sshd|sudo|su|cron)$ ]]; then
            echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Safeguard: Skipped killing parent PID $PPID_EXT ($PNAME) because it is critical." >> /var/ossec/logs/active-responses.log
        else
            kill -9 $PPID_EXT
            if [ $? -eq 0 ]; then
                echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Killed parent PID $PPID_EXT ($PNAME) (Aggressive Response)." >> /var/ossec/logs/active-responses.log
            else
                echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Failed to kill parent PID $PPID_EXT" >> /var/ossec/logs/active-responses.log
            fi
        fi
    fi
fi
