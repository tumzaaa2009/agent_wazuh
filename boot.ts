import { $, serve } from "bun";
import * as os from "os";
import { exec } from "child_process";
import { existsSync } from "fs";

//patch update ข้อมูล cdb list แยก hash ip domain fixbug checkrule gggggg////

// --- 0. Set System Timezone (Asia/Bangkok) ---
function setSystemTimezone() {
    process.env.TZ = "Asia/Bangkok";
    const platform = os.platform();

    if (platform === 'win32') {
        exec('tzutil /s "SE Asia Standard Time"', (err) => {
            if (err) console.log("⚠️ Failed to set Windows timezone (Run as Admin required):", err.message);
            else console.log("✅ Successfully set Windows timezone to SE Asia Standard Time");
        });
    } else if (platform === 'linux') {
        // Try timedatectl first, fallback to symlink for Docker containers
        exec('timedatectl set-timezone Asia/Bangkok || ln -sf /usr/share/zoneinfo/Asia/Bangkok /etc/localtime', (err) => {
            if (err) console.log("⚠️ Failed to set Linux timezone:", err.message);
            else console.log("✅ Successfully set Linux timezone to Asia/Bangkok");
        });
    }
}
setSystemTimezone();

// --- 0.1 Fix Missing Legacy CDB Lists (Prevents API 500 Error) ---
function setupDummyLists() {
    const platform = os.platform();
    if (platform === 'linux') {
        // Wazuh dashboard API crashes with 500 if these files are missing
        // Files MUST have at least one valid key:value pair, otherwise wazuh-analysisd fails to load them
        exec('mkdir -p /var/ossec/etc/lists/malicious-ioc && echo "dummy:dummy" >> /var/ossec/etc/lists/malicious-ioc/malicious-ip && echo "dummy:dummy" >> /var/ossec/etc/lists/malicious-ioc/malicious-domains && echo "dummy:dummy" >> /var/ossec/etc/lists/malicious-ioc/malware-hashes && chown -R wazuh:wazuh /var/ossec/etc/lists/malicious-ioc', (err) => {
            if (err) console.log("⚠️ Failed to setup dummy lists:", err.message);
            else console.log("✅ Successfully verified legacy lists exist.");
        });
    }
}
setupDummyLists();

const HOSPITAL_CODE = process.env.HOSPITAL_CODE || "141";
const WS_URL = process.env.WS_URL || "wss://rh4cloudcenter.moph.go.th/ws/active-response";
const HOSPITAL_NAME = process.env.HOSPITAL_NAME || "";
const PROVINCE = process.env.PROVINCE || "";
const ZONE = process.env.ZONE || "";
const API_KEY = process.env.API_KEY || "";
const INDEXER_URL = process.env.INDEXER_URL || "";
const BASE_API_URL = WS_URL.replace("wss://", "https://").replace("/ws/active-response", "");
const INDEXER_USER = process.env.INDEXER_USER || "";
const INDEXER_PASSWORD = process.env.INDEXER_PASSWORD || "";
const YARA_API_URL = process.env.YARA_API_URL || "https://rh4cloudcenter.moph.go.th/api/v1/yara-rules";

// Master Version is maintained in agent_version.txt
import { appendFile } from "fs/promises";
import { existsSync } from "fs";

// Override console.log and console.error to write to separate log files
const originalConsoleLog = console.log;
const originalConsoleError = console.error;

const logDir = "/app/logs";
if (!existsSync(logDir)) {
    import("fs").then(fs => fs.mkdirSync(logDir, { recursive: true })).catch(() => { });
}

async function writeLog(level: "INFO" | "ERROR", ...args: any[]) {
    const msg = args.map(a => (typeof a === 'object' && a !== null) ? JSON.stringify(a) : String(a)).join(" ");
    const timestamp = new Date().toISOString();
    const logStr = `[${timestamp}] [${level}] ${msg}\n`;

    if (level === "ERROR") {
        originalConsoleError(...args);
    } else {
        originalConsoleLog(...args);
    }

    let system = "system";
    const lowerMsg = msg.toLowerCase();

    // Categorize log based on keywords
    if (lowerMsg.includes("yara") || lowerMsg.includes("malware") || lowerMsg.includes("quarantine")) {
        system = "yara";
    } else if (lowerMsg.includes("soc configs") || lowerMsg.includes("wazuh") || lowerMsg.includes("mockup") || lowerMsg.includes("ossec.conf") || lowerMsg.includes("agent.conf") || lowerMsg.includes("policy")) {
        system = "wazuh";
    } else if (lowerMsg.includes("firewall") || lowerMsg.includes("active response") || lowerMsg.includes("queue item") || lowerMsg.includes("ack") || lowerMsg.includes("srcip")) {
        system = "active-response";
    }

    await appendFile(`${logDir}/${system}.log`, logStr).catch(() => { });
}

console.log = (...args) => { writeLog("INFO", ...args); };
console.error = (...args) => { writeLog("ERROR", ...args); };

console.log("🚀 Starting Hospital Edge Connector (Bun/TypeScript)...");
console.log(`🏥 Hospital Code: ${HOSPITAL_CODE}`);

// ---------------------------------------------------------
// Report Malware Event to Central SOC
// ---------------------------------------------------------
async function reportMalwareEvent(eventData: {
    hash_sha256: string;
    hash_md5: string;
    filename: string;
    filepath: string;
    yara_rule_matched: string;
    agent_id: string;
    agent_name: string;
    action_taken: string;
}) {
    const API_BASE = process.env.API_URL || "https://rh4cloudcenter.moph.go.th/api/v1";
    const payload = {
        ...eventData,
        hospital_code: HOSPITAL_CODE,
        hospital_name: HOSPITAL_NAME,
        timestamp: new Date().toISOString()
    };
    try {
        const res = await fetch(`${API_BASE}/malware-events`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${API_KEY}`,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            },
            body: JSON.stringify(payload)
        });
        console.log(`📤 Malware event reported to SOC: ${res.status}`);
        await appendFile('/var/ossec/logs/integrations.log',
            `[malware-event] ${payload.filepath} -> ${res.status}\n`
        ).catch(() => { });
    } catch (err) {
        console.error("❌ Failed to report malware event to SOC:", err);
        // Log locally so we don't lose the event
        await appendFile('/var/ossec/logs/integrations.log',
            `[malware-event-fail] ${JSON.stringify(payload)}\n`
        ).catch(() => { });
    }
}

async function processQueueItem(item: any, ws?: WebSocket) {
    const { id: log_id, command, srcip, timeout, agent_id, agent_name } = item;

    const API_BASE_URL = WS_URL.replace("wss://", "https://").replace("ws://", "http://").replace("/ws/active-response", "/api/v1");

    // Send ACK Received via API
    fetch(`${API_BASE_URL}/active-response/receive`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_id, hospital_code: HOSPITAL_CODE })
    }).catch(err => console.error("Failed to send receive ACK:", err));

    if (command === "soc-firewall-drop" || command === "firewall-drop") {
        if (srcip && agent_id) {
            const dropMsg = `🛡️ Requesting Firewall Drop for IP ${srcip} on Agent ${agent_id} (${agent_name || 'unknown'}) with timeout ${timeout || 3600}s`;
            console.log(dropMsg);
            // ส่งเข้า syslog
            await $`logger -t HOS-Edge-Connector ${dropMsg}`.catch((err: any) => console.error("Syslog error:", err));

            try {
                if (agent_id === "000") {
                    // 1. Wazuh Manager (Agent 000): Use local log file injection to trigger native local rule
                    const logEntry = {
                        timestamp: new Date().toISOString(),
                        source: "central_soc",
                        command: "firewall-drop",
                        srcip: srcip,
                        timeout: timeout || 3600,
                        log_id: log_id,
                        agent: { id: "000", name: agent_name || "Manager" }
                    };
                    await appendFile('/var/ossec/logs/active-responses.log', JSON.stringify(logEntry) + '\n');
                    console.log(`✅ Successfully wrote log for Manager (000) to trigger local block for ${srcip}`);
                } else {
                    // 2. Remote Agent (Agent 001+): Use agent_control to push AR over the network
                    // Detect agent OS first
                    const infoOutput = await $`/var/ossec/bin/agent_control -i ${agent_id}`.text();
                    const isWindows = infoOutput.toLowerCase().includes('windows');

                    const arOutput = await $`/var/ossec/bin/agent_control -L`.text();

                    let arName = 'firewalld-drop';
                    if (isWindows) {
                        const match = arOutput.match(/Response name: (netsh\d*|win_route-null\d*)/);
                        arName = match ? match[1] : 'netsh';
                    } else {
                        const match = arOutput.match(/Response name: ((?:firewalld?-drop|host-deny)\d*)/);
                        arName = match ? match[1] : 'firewalld-drop';
                    }

                    await $`/var/ossec/bin/agent_control -b ${srcip} -f ${arName} -u ${agent_id}`;
                    console.log(`✅ Successfully triggered ${arName} on remote agent ${agent_id} to block ${srcip}`);
                }
            } catch (err) {
                console.error(`❌ Failed to trigger active response via agent_control:`, err);
            }

            // Send ACK back if WebSocket is provided
            if (ws) {
                const ackMsg = { type: "ack", hospital_code: HOSPITAL_CODE, status: "success", log_id };
                ws.send(JSON.stringify(ackMsg));
            }

            // Send HTTP REST API ACK for success
            fetch(`${API_BASE_URL}/active-response/success`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ log_id, hospital_code: HOSPITAL_CODE })
            }).catch(err => console.error("Failed to send success ACK:", err));

            console.log(`✅ Queue item ${log_id} processed. (Sent HTTP ACK)`);
        } else {
            console.error(`⚠️ Cannot drop firewall: Missing srcip (${srcip}) or agent_id (${agent_id})`);
        }
    } else if (command === "yara-scan") {
        // Determine the filepath from arguments or payload
        const filepath = item.filepath || item.srcip || (item.arguments ? item.arguments[0] : null);
        if (filepath) {
            console.log(`🔍 Received YARA scan request for file: ${filepath}`);
            try {
                let yaraOutput = "";
                if (agent_id && agent_id !== "000") {
                    // Detect agent OS
                    const infoOutput = await $`/var/ossec/bin/agent_control -i ${agent_id}`.text();
                    const isWindows = infoOutput.toLowerCase().includes('windows');
                    const arName = isWindows ? 'yara_windows' : 'yara_linux';

                    console.log(`📡 Agent ${agent_id} is ${isWindows ? 'Windows' : 'Linux'}. Triggering ${arName}...`);
                    await $`/var/ossec/bin/agent_control -b ${filepath} -f ${arName} -u ${agent_id}`;
                    yaraOutput = `Sent command ${arName} to agent ${agent_id} for file ${filepath}`;
                    console.log(`✅ ${yaraOutput}`);
                } else {
                    // Local fallback (agent_id = "000" — Manager itself)
                    yaraOutput = await $`/usr/bin/yara -w -r /app/yara_rules.yar ${filepath}`.text();
                    console.log(`✅ YARA Scan complete.`);
                    if (yaraOutput.trim() !== "") {
                        console.log(`🚨 Malware Detected! Results:\n${yaraOutput}`);

                        // Step 1: Compute hashes BEFORE deleting
                        const sha256Result = await $`sha256sum ${filepath}`.text().catch(() => "");
                        const md5Result = await $`md5sum ${filepath}`.text().catch(() => "");
                        const sha256 = sha256Result.split(" ")[0] || "";
                        const md5 = md5Result.split(" ")[0] || "";

                        // Step 2: Delete the malware file
                        await $`rm -f ${filepath}`.catch((e: any) => console.error(`❌ Failed to delete ${filepath}:`, e));
                        console.log(`🗑️ Malware file deleted: ${filepath}`);

                        // Step 3: Write QUARANTINED log for Wazuh Decoder
                        await appendFile('/var/ossec/logs/active-responses.log',
                            `QUARANTINED src=${filepath} dest=DELETED sha256=${sha256} md5=${md5} yara_match=${yaraOutput.trim().replace(/\n/g, '|')}\n`
                        ).catch((e: any) => console.error("❌ Failed to write QUARANTINED log:", e));

                        // Step 4: Report Hash + Event to Central SOC
                        await reportMalwareEvent({
                            hash_sha256: sha256,
                            hash_md5: md5,
                            filename: filepath.split("/").pop() || filepath,
                            filepath,
                            yara_rule_matched: yaraOutput.trim(),
                            agent_id: agent_id || "000",
                            agent_name: agent_name || "Manager",
                            action_taken: "DELETED"
                        });
                    } else {
                        console.log(`🟢 No malware found in ${filepath}`);
                    }
                }

                // Send ACK back if WebSocket is provided
                if (ws) {
                    const ackMsg = { type: "ack", hospital_code: HOSPITAL_CODE, status: "success", log_id, scan_result: yaraOutput };
                    ws.send(JSON.stringify(ackMsg));
                }

                // Send HTTP REST API ACK for success
                fetch(`${API_BASE_URL}/active-response/success`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ log_id, hospital_code: HOSPITAL_CODE, scan_result: yaraOutput })
                }).catch(err => console.error("Failed to send success ACK:", err));
            } catch (err) {
                console.error(`❌ YARA Scan failed:`, err);
            }
        } else {
            console.error(`⚠️ Cannot perform YARA scan: Missing filepath.`);
        }
    }
}

// ---------------------------------------------------------
// WebSocket Flow (Push-based)
// ---------------------------------------------------------
function connect() {
    console.log(`🔗 Connecting to Central SOC WebSocket at ${WS_URL}...`);
    const ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        console.log("✅ Connected to Central SOC WebSocket!");

        const registerMsg = {
            type: "register",
            hospital_code: HOSPITAL_CODE,
            hospital_name: HOSPITAL_NAME,
            province: PROVINCE,
            zone: ZONE,
            api_key: API_KEY,
            indexer_url: INDEXER_URL,
            indexer_user: INDEXER_USER,
            indexer_password: INDEXER_PASSWORD
        };
        ws.send(JSON.stringify(registerMsg));
    };

    ws.onmessage = async (event) => {
        try {
            const data = JSON.parse(event.data.toString());
            console.log("📥 Received message:", data);

            // 1. Handle old single payload push format
            if (data.action === "execute_active_response") {
                const { log_id, command, arguments: args, agent_id, agent_name } = data.payload || {};
                await processQueueItem({
                    id: log_id,
                    command: command,
                    srcip: args ? args[0] : null,
                    timeout: args ? args[1] : 3600,
                    agent_id,
                    agent_name
                }, ws);
            }

            // Handle rule policy update action
            if (data.action === "update_policy") {
                console.log("📥 Received update_policy trigger from Central SOC");
                await syncRulePolicy();
            }

            // Handle threat intel sync
            if (data.action === "SYNC_THREAT_INTEL") {
                console.log("📥 Received SYNC_THREAT_INTEL trigger from Central SOC");
                await downloadMispCdb();
            }

            // Handle agent patch update action
            if (data.action === "update_agent") {
                console.log("📥 Received update_agent trigger from Central SOC");
                console.log("🔄 Exiting to allow bootloader to apply update...");
                process.exit(0);
            }

            // 2. Handle new Array payload format (if pushed via WS)
            if (Array.isArray(data) && data[0]?.success && data[0]?.queues) {
                const queues = data[0].queues;
                console.log(`📥 Processing ${queues.length} queue items from WS array`);
                for (const item of queues) {
                    await processQueueItem(item, ws);
                }
            }

        } catch (e) {
            console.error("❌ Error processing message:", e);
        }
    };

    ws.onclose = () => {
        console.log("❌ Disconnected from Central SOC. Reconnecting in 5 seconds...");
        setTimeout(connect, 5000);
    };

    ws.onerror = (error) => {
        console.error("⚠️ WebSocket Error:", error);
        ws.close();
    };
}



// ---------------------------------------------------------
// HTTP Polling Flow (Pull-based API) - Optional
// ---------------------------------------------------------
async function pollApiQueue() {
    const API_QUEUE_URL = process.env.API_QUEUE_URL || "https://rh4cloudcenter.moph.go.th/api/v1/active-response/queues";

    try {
        const response = await fetch(`${API_QUEUE_URL}?hospital_code=${HOSPITAL_CODE}`, {
            method: "GET",
            headers: { "Authorization": `Bearer ${API_KEY}` }
        });

        if (response.ok) {
            const data = await response.json();
            if (Array.isArray(data) && data[0]?.success && data[0]?.queues) {
                const queues = data[0].queues;
                if (queues.length > 0) {
                    console.log(`🔄 Polled ${queues.length} items from API`);
                    for (const item of queues) {
                        await processQueueItem(item);

                        // Note: After processing, you should call DELETE API to clear the queue
                        await fetch(`${API_QUEUE_URL}?hospital_code=${HOSPITAL_CODE}&srcip=${item.srcip}`, {
                            method: "DELETE",
                            headers: { "Authorization": `Bearer ${API_KEY}` }
                        });
                        console.log(`🗑️ Cleared queue for ${item.srcip}`);
                    }
                }
            }
        }
    } catch (err) {
        console.error("❌ API Polling Error:", err);
    }
}

// ---------------------------------------------------------
// YARA Rules Synchronization (Pull-based)
// ---------------------------------------------------------
async function fetchYaraRules() {
    try {
        console.log(`📥 Checking YARA rules version at ${YARA_API_URL}/version...`);

        const RULES_PATH = "/var/ossec/etc/shared/default/yara_rules.yar";

        // Version check to avoid redundant downloads (bandwidth optimization)
        try {
            const versionRes = await fetch(`${YARA_API_URL}/version`, { signal: AbortSignal.timeout(5000) });
            if (versionRes.ok) {
                const vData = await versionRes.json();
                const versionFile = '/app/yara_rules_version.txt';
                const fileExists = await Bun.file(versionFile).exists();
                if (fileExists) {
                    const localVersion = (await Bun.file(versionFile).text()).trim();
                    if (localVersion === String(vData.version)) {
                        console.log(`✅ YARA Rules already up to date (version: ${vData.version}). Skipping download.`);
                        return;
                    }
                }
                // Will save version after successful download below
                console.log(`📥 YARA Rules update available (remote: ${vData.version}). Downloading...`);
                const response = await fetch(YARA_API_URL);
                if (response.ok) {
                    const data = await response.json();
                    if (data.success && data.rules) {
                        let combinedRules = "";
                        for (const rule of data.rules) {
                            const decodedContent = Buffer.from(rule.content, 'base64').toString('utf-8');
                            combinedRules += decodedContent + "\n";
                        }
                        await Bun.write(RULES_PATH, combinedRules);
                        await $`chown wazuh:wazuh ${RULES_PATH} && chmod 660 ${RULES_PATH}`.catch(() => { });
                        await Bun.write(versionFile, String(vData.version));
                        console.log(`✅ Successfully updated YARA rules at ${RULES_PATH} (version: ${vData.version})`);
                    }
                } else {
                    console.error(`❌ Failed to fetch YARA rules: ${response.statusText}`);
                }
                return; // Done via version-check path
            }
        } catch {
            // Version endpoint not available — fall through to full download
            console.log(`⚠️ YARA version API not available. Falling back to full download...`);
        }

        // Fallback: full download without version check
        console.log(`📥 Fetching latest YARA rules from ${YARA_API_URL}...`);
        const response = await fetch(YARA_API_URL);
        if (response.ok) {
            const data = await response.json();
            if (data.success && data.rules) {
                let combinedRules = "";
                for (const rule of data.rules) {
                    const decodedContent = Buffer.from(rule.content, 'base64').toString('utf-8');
                    combinedRules += decodedContent + "\n";
                }
                await Bun.write(RULES_PATH, combinedRules);
                await $`chown wazuh:wazuh ${RULES_PATH} && chmod 660 ${RULES_PATH}`.catch(() => { });
                console.log(`✅ Successfully updated YARA rules at ${RULES_PATH}`);
            }
        } else {
            console.error(`❌ Failed to fetch YARA rules: ${response.statusText}`);
        }
    } catch (err) {
        console.error(`❌ Error fetching YARA rules:`, err);
    }
}

// ---------------------------------------------------------
// SOC Rule Policy Synchronization (New Queue System)
// ---------------------------------------------------------
async function syncRulePolicy() {
    const CENTRAL_API = WS_URL.replace("wss://", "https://").replace("ws://", "http://").replace("/ws/active-response", "");
    const VERSION_FILE = `${import.meta.dir}/soc_rules_version.txt`;
    try {
        console.log(`📥 Querying SOC for latest policy queues...`);
        const res = await fetch(`${CENTRAL_API}/api/v1/rules/queues?hospital_code=${HOSPITAL_CODE}`);
        if (!res.ok) return;
        const data = await res.json();
        const updates = data.queues;

        if (updates && updates.length > 0) {
            const latestUpdate = updates[0];
            const expectedTarget = `${latestUpdate.version_hash} used`;

            let currentTopLine = '';
            if (existsSync(VERSION_FILE)) {
                const content = await Bun.file(VERSION_FILE).text();
                const lines = content.split('\n').filter(l => l.trim().length > 0);
                currentTopLine = lines.length > 0 ? lines[0].trim() : '';
            }

            if (currentTopLine !== expectedTarget) {
                console.log(`🔍 Checking queued updates... Found patch version: ${latestUpdate.version_hash}`);
                console.log(`[SYNC] Version mismatch detected. Local: '${currentTopLine}', Remote: '${expectedTarget}'. Updating...`);
                console.log(`📥 Downloading configuration payload for patch: ${latestUpdate.version_hash}...`);

                let configUrl = `${CENTRAL_API}/api/v1/rules/configs`;
                if (latestUpdate.action === 'rollback') {
                    configUrl = `${CENTRAL_API}/api/v1/rules/backup/${latestUpdate.version_hash}`;
                }

                const configRes = await fetch(configUrl);
                if (configRes.ok) {
                    const configData = await configRes.json();
                    const { agent_xml, manager_xml, wazuh_files } = configData;

                    await Bun.write('/var/ossec/etc/shared/default/agent_mockup.xml', agent_xml);
                    await Bun.write('/var/ossec/etc/manager_mockup.xml', manager_xml);

                    if (wazuh_files && Array.isArray(wazuh_files)) {
                        for (const file of wazuh_files) {
                            if (file.type === 'rule') {
                                const p = `/var/ossec/etc/rules/${file.filename}`;
                                await Bun.write(p, file.content);
                                await $`chown root:wazuh ${p} && chmod 660 ${p}`.catch(() => { });
                            } else if (file.type === 'decoder') {
                                const p = `/var/ossec/etc/decoders/${file.filename}`;
                                await Bun.write(p, file.content);
                                await $`chown root:wazuh ${p} && chmod 660 ${p}`.catch(() => { });
                            }
                        }
                    }

                    // Auto inject configurations into ossec.conf and agent.conf
                    // Note: autoInjectWazuhConfigs expects base64 encoded strings
                    await autoInjectWazuhConfigs({
                        mockup_agent: agent_xml ? Buffer.from(agent_xml).toString('base64') : null,
                        mockup_manager: manager_xml ? Buffer.from(manager_xml).toString('base64') : null
                    });

                    await Bun.write(VERSION_FILE, expectedTarget + '\n');
                    console.log(`[SYNC] Rules applied successfully for ${latestUpdate.version_hash}`);

                    // Restart Wazuh Manager
                    await $`SYSTEMD_IGNORE_CHROOT=1 systemctl restart wazuh-manager`.catch(() => { });
                }
            } else {
                console.log(`[SYNC] Edge is already up to date with ${expectedTarget}.`);
            }

            await fetch(`${CENTRAL_API}/api/v1/rules/queues?hospital_code=${HOSPITAL_CODE}`, {
                method: "DELETE"
            });
        }
    } catch (err: any) {
        console.error(`[SYNC ERROR]: ${err.message}`);
    }
}

// ---------------------------------------------------------
// SOC Wazuh Rules & Decoders Synchronization
// ---------------------------------------------------------

async function autoInjectWazuhConfigs(data: any) {
    if (!data.mockup_agent && !data.mockup_manager) return;

    const ossecConfPath = '/var/ossec/etc/ossec.conf';
    const agentConfPath = '/var/ossec/etc/shared/default/agent.conf';

    try {
        let confContent = await Bun.file(ossecConfPath).text();
        let agentConfContent = await Bun.file(agentConfPath).text();
        let needsRestart = false;

        // In API v1/v2, data.mockup_agent is the FULL yara_deployment/agent.conf file.
        // data.mockup_manager is the FULL manager_mockup.xml file.
        let managerMockup = "";
        let agentMockup = "";

        if (data.mockup_agent) {
            agentMockup = Buffer.from(data.mockup_agent, 'base64').toString('utf-8');
        }

        if (data.mockup_manager) {
            managerMockup = Buffer.from(data.mockup_manager, 'base64').toString('utf-8');
        }

        // 1. Update Manager Config (ossec.conf) — remove old block, inject new
        if (managerMockup) {
            const START = '<!-- INJECTED BY EDGE CONNECTOR';

            // Clean up the incoming payload so it strictly starts at the INJECTED tag
            const mockupStartIdx = managerMockup.indexOf(START);
            if (mockupStartIdx !== -1) {
                managerMockup = managerMockup.substring(mockupStartIdx);
            }

            const END = '<!-- USER CUSTOM CONFIGURATION BLOCK ENDS HERE   -->';
            let startIdx = confContent.indexOf(START);
            let endIdx = confContent.indexOf(END);

            // Remove ALL existing injected blocks (if any duplicates exist due to old bugs)
            while (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
                // Find if there are stray "<!-- ========================================== -->" and newlines right above startIdx
                let realStartIdx = startIdx;
                const precedingText = confContent.substring(0, startIdx);
                const match = precedingText.match(/(?:<!-- ========================================== -->\s*)+$/);
                if (match) {
                    realStartIdx -= match[0].length;
                }

                confContent = confContent.substring(0, realStartIdx) + confContent.substring(endIdx + END.length);
                startIdx = confContent.indexOf(START);
                endIdx = confContent.indexOf(END);
            }

            // Inject new block right before </ossec_config>
            confContent = confContent.replace('</ossec_config>', `\n${managerMockup}\n</ossec_config>`);

            await Bun.write(ossecConfPath, confContent);
            await $`chown root:wazuh ${ossecConfPath} && chmod 660 ${ossecConfPath}`;
            needsRestart = true;
            console.log("✅ Manager mockup updated in ossec.conf.");
        }

        // 2. Inject Agent Config (agent.conf)
        if (agentMockup) {
            console.log("⚙️ Overwriting agent.conf with central SOC mockup...");
            await Bun.write(agentConfPath, agentMockup);
            await $`chown wazuh:wazuh ${agentConfPath} && chmod 660 ${agentConfPath}`;
            needsRestart = true;
            console.log("✅ Agent config synchronized.");
        }

    } catch (err) {
        console.error("❌ Error injecting mockups:", err);
    }
}

async function fetchSocConfigs() {
    const SOC_CONFIG_URL = process.env.SOC_CONFIG_URL || "https://rh4cloudcenter.moph.go.th/api/v1/wazuh-configs";
    try {
        console.log(`📥 Checking for SOC configs updates at ${SOC_CONFIG_URL}/version...`);
        const versionRes = await fetch(`${SOC_CONFIG_URL}/version`);
        if (versionRes.ok) {
            const vData = await versionRes.json();
            if (vData.success && vData.version) {
                const currentDir = import.meta.dir;
                const versionFile = `${currentDir}/soc_rules_version.txt`;
                const fileExists = await Bun.file(versionFile).exists();
                if (fileExists) {
                    const content = await Bun.file(versionFile).text();
                    const localVersion = content.split('\n').filter(l => l.trim().length > 0)[0]?.trim() || "";
                    const remoteVersion = String(vData.version).split('\n').filter(l => l.trim().length > 0)[0]?.trim() || "";
                    if (localVersion === remoteVersion || localVersion === `${remoteVersion} used`) {
                        console.log("✅ SOC Configs are already up to date. Skipping download.");
                        return;
                    }
                }

                console.log(`📥 Updates found! Fetching latest SOC configs from ${SOC_CONFIG_URL}...`);
                const response = await fetch(SOC_CONFIG_URL);
                if (response.ok) {
                    const data = await response.json();
                    if (data.success) {
                        console.log("📦 Extracting SOC configs to /var/ossec/etc/...");

                        // Write rules
                        if (data.rules) {
                            for (const rule of data.rules) {
                                const filepath = `/var/ossec/etc/rules/${rule.filename}`;
                                const decodedContent = Buffer.from(rule.content, 'base64').toString('utf-8');
                                await Bun.write(filepath, decodedContent);
                                await $`chmod 640 ${filepath}`.catch(() => { });
                                await $`chown root:wazuh ${filepath}`.catch((e) => {
                                    console.log(`⚠️ Note: Could not set root:wazuh on ${filepath}`);
                                });
                            }
                        }

                        // Write decoders
                        if (data.decoders) {
                            for (const decoder of data.decoders) {
                                const filepath = `/var/ossec/etc/decoders/${decoder.filename}`;
                                const decodedContent = Buffer.from(decoder.content, 'base64').toString('utf-8');
                                await Bun.write(filepath, decodedContent);
                                await $`chown root:wazuh ${filepath} && chmod 750 ${filepath}`;
                            }
                        }

                        // Save the new version
                        const remoteVersion = String(vData.version).split('\n').filter(l => l.trim().length > 0)[0]?.trim() || "";
                        await Bun.write(versionFile, remoteVersion + " used\n");
                        // Permissions for version file might not be strictly needed since it's in our dir, but just in case
                        await $`chmod 640 ${versionFile}`.catch(() => { });

                        // Auto inject configurations
                        await autoInjectWazuhConfigs(data);

                        console.log("🔄 Restarting Wazuh Manager to apply new configs...");
                        await $`SYSTEMD_IGNORE_CHROOT=1 systemctl restart wazuh-manager`;
                        console.log("✅ Wazuh configs synced successfully!");
                    }
                } else {
                    console.error(`❌ Failed to fetch SOC configs: ${response.statusText}`);
                }
            }
        } else {
            console.error(`❌ Failed to fetch config version: ${versionRes.statusText}`);
        }
    } catch (err) {
        console.error(`❌ Error fetching SOC configs:`, err);
    }
}

// ---------------------------------------------------------
// Automated YARA WPK Deployment Orchestrator
// ---------------------------------------------------------
async function deployYaraWpk() {
    // Deprecated: YARA deployment is now handled natively via Docker and agent.conf
    return;
}

// ---------------------------------------------------------
// Custom SOC Updater Mechanism
// ---------------------------------------------------------
async function checkCustomSocUpdate() {
    const CENTRAL_API = WS_URL.replace("wss://", "https://").replace("ws://", "http://").replace("/ws/active-response", "");
    const currentDir = import.meta.dir;
    const versionFile = `${currentDir}/version_custom_soc.txt`;
    const scriptFile = `${currentDir}/custom-soc`;
    const wazuhIntegrationPath = "/var/ossec/integrations/custom-soc";

    try {
        let localVersion = "";
        if (existsSync(versionFile)) {
            localVersion = (await Bun.file(versionFile).text()).trim();
        } else {
            await Bun.write(versionFile, "");
        }

        // 1. Ensure local script is copied to Wazuh if it's missing in Wazuh but exists locally
        if (!existsSync(wazuhIntegrationPath) && existsSync(scriptFile)) {
            console.log(`📥 Restoring missing custom-soc to Wazuh from local backup...`);
            const scriptText = await Bun.file(scriptFile).text();
            await Bun.write(wazuhIntegrationPath, scriptText);
            await $`chmod 750 ${wazuhIntegrationPath}`.catch(() => { });
            await $`chown root:wazuh ${wazuhIntegrationPath}`.catch(() => { });
            console.log(`✅ Successfully restored custom-soc to ${wazuhIntegrationPath}.`);
        }

        // 2. Check for updates from Central API
        console.log(`📥 Querying API for latest Custom SOC patches...`);
        const res = await fetch(`${CENTRAL_API}/api/v1/custom-soc/version`);
        if (res.ok) {
            const data = await res.json();

            if (data.success && data.version && data.version !== localVersion) {
                console.log(`🚀 [UPDATE] Custom SOC check! Remote: ${data.version}, Local: ${localVersion}.`);
                console.log(`📥 Downloading new custom-soc script...`);
                const scriptRes = await fetch(`${CENTRAL_API}/api/v1/custom-soc/script`);
                if (scriptRes.ok) {
                    const scriptText = await scriptRes.text();

                    // Save locally
                    await Bun.write(scriptFile, scriptText);
                    await Bun.write(versionFile, data.version);
                    await $`chmod +x ${scriptFile}`.catch(() => { });

                    // Deploy to Wazuh
                    await Bun.write(wazuhIntegrationPath, scriptText);
                    await $`chmod 750 ${wazuhIntegrationPath}`.catch(() => { });
                    await $`chown root:wazuh ${wazuhIntegrationPath}`.catch((e) => {
                        console.log(`⚠️ Note: Could not set root:wazuh ownership on ${wazuhIntegrationPath}`);
                    });

                    console.log(`✅ [UPDATE] Successfully overwrote local custom-soc and deployed to ${wazuhIntegrationPath}.`);
                }
            }
        }
    } catch (err) {
        console.error("❌ Failed to check for Custom SOC updates:", err);
    }
}

async function checkMispUpdates() {
    try {
        console.log(`📥 Checking for MISP updates at /api/v1/threat-intel/misp-version...`);
        const res = await fetch(`${BASE_API_URL}/api/v1/threat-intel/misp-version`, {
            headers: { "Authorization": `Bearer ${API_KEY}` }
        });
        if (res.ok) {
            const data = await res.json();
            if (data.success && data.version) {
                const currentDir = import.meta.dir;
                const versionFile = `${currentDir}/version_misp_ioc.txt`;
                const fileExists = await Bun.file(versionFile).exists();
                if (fileExists) {
                    const localVersion = (await Bun.file(versionFile).text()).trim();
                    if (localVersion === data.version) {
                        return;
                    }
                }

                console.log(`📥 MISP IOC updates found (${data.version})!`);
                await downloadMispCdb();
                await Bun.write(versionFile, data.version);

                console.log("🔄 Restarting wazuh-manager to apply new MISP DB...");
                exec("systemctl restart wazuh-manager.service", (err) => {
                    if (err) console.error("❌ Failed to restart wazuh-manager:", err.message);
                    else console.log("✅ Successfully restarted wazuh-manager.");
                });
            }
        }
    } catch (err) {
        console.error("❌ Failed to check for MISP updates:", err);
    }
}

async function downloadMispCdb() {
    console.log("📥 Downloading MISP CDB lists from Central SOC...");
    try {
        const listDir = "/var/ossec/etc/lists";
        if (!existsSync(listDir)) {
            exec(`mkdir -p ${listDir}`);
        }

        const types = [
            { url: 'misp-ip.txt', file: 'misp_ip' },
            { url: 'misp-domain.txt', file: 'misp_domain' },
            { url: 'misp-hash.txt', file: 'misp_hash' }
        ];

        let downloadedCount = 0;

        for (const { url, file } of types) {
            const res = await fetch(`${BASE_API_URL}/api/v1/threat-intel/${url}`, {
                headers: { "Authorization": `Bearer ${API_KEY}` }
            });
            if (res.ok) {
                const text = await res.text();
                await Bun.write(`/var/ossec/etc/lists/${file}`, text);
                console.log(`✅ Saved ${file} to /var/ossec/etc/lists/`);
                downloadedCount++;
            } else if (res.status === 404) {
                console.log(`ℹ️ No MISP CDB list found for ${file} on Central SOC yet.`);
            } else {
                console.error(`❌ Failed to download ${file}. Status: ${res.status}`);
            }
        }

        if (downloadedCount > 0) {
            console.log("✅ Successfully downloaded MISP CDB lists. Awaiting wazuh restart to apply.");
        }
    } catch (e: any) {
        console.error("❌ Error downloading MISP CDBs:", e.message);
    }
}

// Start WebSocket connection
connect();

// ---------------------------------------------------------
// Policy Sync (API v2)
// ---------------------------------------------------------
async function fetchPoliciesV2() {
    const API_BASE_V2 = process.env.API_URL_V2 || "https://rh4cloudcenter.moph.go.th/api/v2";
    try {
        const response = await fetch(`${API_BASE_V2}/policies/${HOSPITAL_CODE}`, {
            method: "GET",
            headers: { "Authorization": `Bearer ${API_KEY}` }
        });

        if (response.ok) {
            const data = await response.json();
            if (data.success && data.policy) {
                await Bun.write('/var/ossec/etc/runtime_policy.json', JSON.stringify(data.policy, null, 2));
                console.log(`✅ OpenXDR Phase 1: Fetched and saved runtime_policy.json (v${data.policy.version})`);
            }
        }
    } catch (err) {
        console.error("❌ API v2 Policy Fetch Error:", err);
    }
}

// Initial fetch and set interval for Policy updates (5 mins)
fetchPoliciesV2();
setInterval(fetchPoliciesV2, 5 * 60 * 1000);

// Initial fetch and set interval for daily YARA updates (24h)
fetchYaraRules();
setInterval(fetchYaraRules, 24 * 60 * 60 * 1000);

// Initial fetch and set interval for daily SOC Configs updates (24h)
fetchSocConfigs();
setInterval(fetchSocConfigs, 24 * 60 * 60 * 1000);

// Run Rule Policy Sync periodically (every 1 min)
syncRulePolicy();
setInterval(syncRulePolicy, 60000);

// Run WPK Deployment Orchestrator periodically (every 5 mins)
deployYaraWpk();
setInterval(deployYaraWpk, 5 * 60 * 1000);

// Run Custom SOC Updater periodically (every 5 mins)
checkCustomSocUpdate();
setInterval(checkCustomSocUpdate, 5 * 60 * 1000);

// Run MISP updates periodically (every 1 min)
checkMispUpdates();
setInterval(checkMispUpdates, 60000);

// Uncomment to enable HTTP API Polling every 10 seconds
setInterval(pollApiQueue, 10000);



// ---------------------------------------------------------
// Master Server API (Only runs if IS_MASTER=true)
// ---------------------------------------------------------
if (process.env.IS_MASTER === "true") {
    console.log("👑 Starting Master API Server on port 5050...");
    Bun.serve({
        port: 5050,
        async fetch(req) {
            const url = new URL(req.url);

            if (url.pathname === "/api/v1/edge-connector/version") {
                try {
                    const versionContent = await Bun.file(`${import.meta.dir}/agent_version.txt`).text();
                    const lines = versionContent.split('\n').filter(l => l.trim().length > 0);
                    const usedLine = lines.find(l => l.endsWith(' used')) || lines[0] || '';
                    const currentHash = usedLine.replace(' used', '').trim();
                    return Response.json({ success: true, version: currentHash });
                } catch (err) {
                    return Response.json({ success: false, error: "agent_version.txt not found" }, { status: 404 });
                }
            }

            if (url.pathname === "/api/v1/edge-connector/script") {
                try {
                    const script = await Bun.file('/app/index.ts').text();
                    return new Response(script, {
                        headers: { "Content-Type": "text/plain" }
                    });
                } catch (err) {
                    return Response.json({ success: false, error: "index.ts not found" }, { status: 404 });
                }
            }

            return Response.json({ success: false, error: "Not Found" }, { status: 404 });
        }
    });
}