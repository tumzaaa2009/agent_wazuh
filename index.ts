import { $ } from "bun";

const HOSPITAL_CODE = process.env.HOSPITAL_CODE || "141";
const WS_URL = process.env.WS_URL || "wss://rh4cloudcenter.moph.go.th/ws/active-response";
const HOSPITAL_NAME = process.env.HOSPITAL_NAME || "";
const PROVINCE = process.env.PROVINCE || "";
const ZONE = process.env.ZONE || "";
const API_KEY = process.env.API_KEY || "";
const INDEXER_URL = process.env.INDEXER_URL || "";
const INDEXER_USER = process.env.INDEXER_USER || "";
const INDEXER_PASSWORD = process.env.INDEXER_PASSWORD || "";
const YARA_API_URL = process.env.YARA_API_URL || "https://rh4cloudcenter.moph.go.th/api/v1/yara-rules";

import { appendFile } from "fs/promises";
import { existsSync } from "fs";

// Override console.log and console.error to write to separate log files
const originalConsoleLog = console.log;
const originalConsoleError = console.error;

const logDir = "/app/logs";
if (!existsSync(logDir)) {
  import("fs").then(fs => fs.mkdirSync(logDir, { recursive: true })).catch(() => {});
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
  
  await appendFile(`${logDir}/${system}.log`, logStr).catch(() => {});
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
      console.log(`🛡️ Requesting Firewall Drop for IP ${srcip} on Agent ${agent_id} (${agent_name || 'unknown'}) with timeout ${timeout || 3600}s`);

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
          const arOutput = await $`/var/ossec/bin/agent_control -L`.text();
          const match = arOutput.match(/Response name: (firewall-drop\d*)/);
          const arName = match ? match[1] : 'firewall-drop';

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

    // 1. Inject Manager Config (ossec.conf)
    if (!confContent.includes("custom-soc_engine") && !confContent.includes("custom-soc")) {
      console.log("⚙️ Injecting manager mockup into ossec.conf...");
      confContent = confContent.replace('</ossec_config>', `\n<!-- INJECTED BY EDGE CONNECTOR -->\n${managerMockup}\n</ossec_config>`);
      await Bun.write(ossecConfPath, confContent);
      await $`chown root:wazuh ${ossecConfPath} && chmod 660 ${ossecConfPath}`;
      needsRestart = true;
      console.log("✅ Manager injection complete.");
    } else {
      console.log("✅ Manager mockup already injected in ossec.conf.");
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
        const versionFile = '/var/ossec/etc/soc_rules_version.txt';
        const fileExists = await Bun.file(versionFile).exists();
        if (fileExists) {
          const localVersion = (await Bun.file(versionFile).text()).trim();
          if (localVersion === vData.version) {
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
                await $`chown root:wazuh ${filepath} && chmod 750 ${filepath}`;
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
            await Bun.write('/var/ossec/etc/soc_rules_version.txt', vData.version);
            await $`chown root:wazuh /var/ossec/etc/soc_rules_version.txt && chmod 640 /var/ossec/etc/soc_rules_version.txt`;

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

// Run WPK Deployment Orchestrator periodically (every 5 mins)
deployYaraWpk();
setInterval(deployYaraWpk, 5 * 60 * 1000);

// Uncomment to enable HTTP API Polling every 10 seconds
setInterval(pollApiQueue, 10000);


