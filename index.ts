import { $, serve } from "bun";
import * as os from "os";
import { exec } from "child_process";
import { existsSync } from "fs";

//ปวดกระบาล V5////

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

function getWazuhLogTimestamp() {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

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

const LOG_MAX_BYTES = 10 * 1024 * 1024; // 10 MB per log file

async function rotateIfNeeded(filepath: string) {
  try {
    const file = Bun.file(filepath);
    if (await file.exists() && file.size > LOG_MAX_BYTES) {
      const backupPath = filepath.replace('.log', '.old.log');
      await $`mv -f ${filepath} ${backupPath}`.quiet();
    }
  } catch { }
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

  const logPath = `${logDir}/${system}.log`;
  await rotateIfNeeded(logPath);
  await appendFile(logPath, logStr).catch(() => { });
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

// ---------------------------------------------------------
// IP Validation helper to prevent catastrophic blocks
// ---------------------------------------------------------
function isSafeToBlock(ip: string): boolean {
  if (!ip || typeof ip !== "string") return false;
  const tIp = ip.trim();

  // Protect localhost
  if (tIp === "127.0.0.1" || tIp === "::1" || tIp === "0.0.0.0" || tIp === "0.0.0.0/0") return false;

  // Auto-detect: protect this machine's own IPs
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.address === tIp) return false;
    }
  }

  const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  return ipv4Regex.test(tIp);
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
      if (!isSafeToBlock(srcip)) {
        console.error(`⚠️ BLOCKED ACTION: Attempted to drop invalid/unsafe IP: ${srcip}. Ignored.`);

        // Send ACK back so SOC knows it was rejected
        if (ws) {
          const ackMsg = { type: "ack", hospital_code: HOSPITAL_CODE, status: "rejected", reason: "Unsafe IP", log_id };
          ws.send(JSON.stringify(ackMsg));
        }
        fetch(`${API_BASE_URL}/active-response/success`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ log_id, hospital_code: HOSPITAL_CODE, status: "rejected_unsafe_ip" })
        }).catch(err => console.error("Failed to send reject ACK:", err));

        return;
      }

      const dropMsg = `🛡️ Requesting Firewall Drop for IP ${srcip} on Agent ${agent_id} (${agent_name || 'unknown'}) with timeout ${timeout || 3600}s`;
      console.log(dropMsg);
      // ส่งเข้า syslog
      await $`logger -t HOS-Edge-Connector ${dropMsg}`.catch((err: any) => console.error("Syslog error:", err));

      try {
        // Detect OS dynamically
        let isWindows = false;
        let isUbuntu = false;
        let isCentosAlma = false;

        if (agent_id === "000") {
          try {
            const osRelease = await Bun.file('/etc/os-release').text();
            const osLower = osRelease.toLowerCase();
            if (osLower.includes('ubuntu') || osLower.includes('debian')) isUbuntu = true;
            else if (osLower.includes('centos') || osLower.includes('alma') || osLower.includes('rocky') || osLower.includes('rhel')) isCentosAlma = true;
          } catch (e) { }
        } else {
          try {
            const infoOutput = await $`/var/ossec/bin/agent_control -i ${agent_id}`.text();
            const osLine = infoOutput.split('\n').find((l: string) => l.toLowerCase().includes('operating system:'));
            if (osLine) {
              const osLower = osLine.toLowerCase();
              if (osLower.includes('windows')) isWindows = true;
              else if (osLower.includes('ubuntu') || osLower.includes('debian')) isUbuntu = true;
              else if (osLower.includes('centos') || osLower.includes('alma') || osLower.includes('rocky') || osLower.includes('rhel')) isCentosAlma = true;
            }
          } catch (e) { }
        }

        if (agent_id === "000") {
          // 1. Local Manager (Agent 000)
          let arScript = '/var/ossec/active-response/bin/firewall-drop';
          if (isUbuntu) arScript = '/var/ossec/active-response/bin/firewall-drop';
          else if (isCentosAlma) arScript = '/var/ossec/active-response/bin/firewalld-drop';

          try {
            console.log(`🚀 Executing local ${arScript} to block ${srcip}`);
            const child = Bun.spawn([arScript], {
              stdin: 'pipe',
              stdout: 'pipe',
              stderr: 'pipe'
            });

            // Write initial ADD message
            const addMsg = JSON.stringify({
              command: "add",
              parameters: {
                extra_args: [],
                alert: { data: { srcip: srcip } },
                program: "active-response/bin/firewall-drop"
              }
            });
            child.stdin.write(addMsg + "\n");
            child.stdin.flush();

            // We need to read stdout to consume the continue request
            (async () => {
              try {
                const reader = child.stdout.getReader();
                while (true) {
                  const { done, value } = await reader.read();
                  if (done) break;
                  const output = new TextDecoder().decode(value);
                  if (output.includes('"command":"continue"')) {
                    const continueMsg = JSON.stringify({
                      command: "continue",
                      parameters: { keys: [srcip] }
                    });
                    child.stdin.write(continueMsg + "\n");
                    child.stdin.flush();
                    child.stdin.end();
                    break;
                  }
                }
              } catch (e) {
                console.error("Error reading AR stdout:", e);
              }
            })();

            await child.exited;
            console.log(`✅ Successfully executed local block for ${srcip}`);
          } catch (spawnErr) {
            console.error(`❌ Failed to spawn local AR script:`, spawnErr);
          }
        } else {
          // 2. Remote Agent (Agent 001+)
          let arName = 'firewall-drop';
          try {
            const arOutput = await $`/var/ossec/bin/agent_control -L`.text();
            if (isWindows) {
              const match = arOutput.match(/Response name: (netsh\d*|win_route-null\d*)/);
              arName = match ? match[1] : 'netsh';
            } else if (isCentosAlma) {
              const match = arOutput.match(/Response name: (firewalld?-drop\d*)/);
              arName = match ? match[1] : 'firewalld-drop';
            } else {
              const match = arOutput.match(/Response name: (firewall-drop\d*|host-deny\d*)/);
              arName = match ? match[1] : 'firewall-drop';
            }
          } catch (e) {
            if (isWindows) arName = 'netsh';
            else if (isCentosAlma) arName = 'firewalld-drop';
            else arName = 'firewall-drop';
          }

          console.log(`🚀 Triggering ${arName} on remote agent ${agent_id} (${isWindows ? 'Windows' : (isUbuntu ? 'Ubuntu' : 'CentOS/Linux')}) to block ${srcip}`);
          await $`/var/ossec/bin/agent_control -b ${srcip} -f ${arName} -u ${agent_id}`;
          console.log(`✅ Successfully triggered ${arName} on remote agent ${agent_id}`);
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
        console.log("🔄 Deleting agent_version.txt to force edge-updater to pull new version...");
        try {
          if (existsSync(`${import.meta.dir}/agent_version.txt`)) {
            await Bun.file(`${import.meta.dir}/agent_version.txt`).delete();
          }
        } catch (e) {
          console.error("❌ Failed to delete agent_version.txt:", e);
        }
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
  const API_QUEUE_URL = process.env.API_QUEUE_URL || `${WS_URL.replace("wss://", "https://").replace("ws://", "http://").replace("/ws/active-response", "")}/api/v1/active-response/queues`;

  try {
    const response = await fetch(`${API_QUEUE_URL}?hospital_code=${HOSPITAL_CODE}`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });

    if (response.ok) {
      const data = await response.json();
      if (data && data.success && Array.isArray(data.queues)) {
        const queues = data.queues;
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

          // If there are more items in the queue, fetch the next batch quickly
          if (data.total_queued && data.total_queued > queues.length) {
            console.log(`⏩ More items remaining (${data.total_queued} total), fetching next batch...`);
            setTimeout(pollApiQueue, 2000);
          }
        }
      }
    }
  } catch (err) {
    console.error("❌ API Polling Error:", err);
  }
}


// HTTP API Polling fallback (every 30 seconds — WebSocket is primary)
pollApiQueue(); // Call immediately on startup
setInterval(pollApiQueue, 30 * 1000);



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