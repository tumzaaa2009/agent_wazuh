import { $, serve } from "bun";
import * as os from "os";
import { exec } from "child_process";
import { existsSync } from "fs";

//patch update update telegram update .device_id////

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

const HOSPITAL_CODE = process.env.HOSPITAL_CODE || "";
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
          // 1. Local Agent (000): Execute the Active Response binary directly with JSON payload
          let executable = "/var/ossec/active-response/bin/firewall-drop";
          if (existsSync("/var/ossec/active-response/bin/firewalld-drop")) {
            executable = "/var/ossec/active-response/bin/firewalld-drop";
          }

          const arPayload = JSON.stringify({
            version: 1,
            origin: { name: "edge-connector", module: "active-response" },
            command: "add",
            parameters: {
              extra_args: [],
              alert: { data: { srcip: srcip } },
              program: executable.replace("/var/ossec/", "")
            }
          });

          console.log(`🚀 Executing local AR: ${executable} with payload: ${arPayload}`);

          try {
            const child = Bun.spawn([executable], { stdin: "pipe" });
            child.stdin.write(arPayload);
            child.stdin.flush();
            child.stdin.end();
            await child.exited;
            console.log(`✅ Successfully executed local block for ${srcip}`);
          } catch (spawnErr) {
            console.error(`❌ Failed to spawn local AR script:`, spawnErr);
          }
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
        const ackMsg = { type: "ack", hospital_code: HOSPITAL_CODE, hardware_id: await getHardwareId(), status: "success", log_id };
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
          const ackMsg = { type: "ack", hospital_code: HOSPITAL_CODE, hardware_id: await getHardwareId(), status: "success", log_id, scan_result: yaraOutput };
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

  ws.onopen = async () => {
    console.log("✅ Connected to Central SOC WebSocket!");

    const registerMsg = {
      type: "register",
      hospital_code: HOSPITAL_CODE,
      hardware_id: await getHardwareId(),
      device_id: await getHardwareId(),
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
        console.log("📥 Received update_policy trigger from Central SOC. (Delegated to boot.ts polling loop)");
      }

      // Handle threat intel sync
      if (data.action === "SYNC_THREAT_INTEL") {
        console.log("📥 Received SYNC_THREAT_INTEL trigger from Central SOC. (Delegated to boot.ts polling loop)");
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
      if (Array.isArray(data)) {
        let queues: any[] = [];
        if (data[0]?.success && data[0]?.queues) {
          queues = data[0].queues;
        } else if (data.length > 0 && (data[0]?.id || data[0]?.command)) {
          queues = data;
        }

        if (queues.length > 0) {
          console.log(`📥 Processing ${queues.length} queue items from WS array`);
          for (const item of queues) {
            await processQueueItem(item, ws);
          }
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

async function pollApiQueue() {
  const API_QUEUE_URL = process.env.API_QUEUE_URL || "https://rh4cloudcenter.moph.go.th/api/v1/active-response/queues";

  try {
    const response = await fetch(`${API_QUEUE_URL}?hospital_code=${HOSPITAL_CODE}`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });

    if (response.ok) {
      const data = await response.json();
      let queues: any[] = [];

      if (Array.isArray(data)) {
        if (data[0]?.success && data[0]?.queues) {
          queues = data[0].queues;
        } else if (data.length > 0 && (data[0]?.id || data[0]?.command)) {
          queues = data;
        }
      } else if (data?.success && data?.queues) {
        queues = data.queues;
      }

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
  } catch (err) {
    console.error("❌ API Polling Error:", err);
  }
}

// Start WebSocket connection
connect();

// Enable HTTP API Polling every 10 seconds
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

// ---------------------------------------------------------
// SOC Watchdog — Monitor integrations.log & alert Telegram
// Case 1: No HTTP 200 OK for 30 minutes
// Case 2: ERROR / 502 / Read timed out detected
// ---------------------------------------------------------

const WATCHDOG_BOT_TOKEN = "8185344494:AAG3-DKdv_TH8OmHor9dEjedgoMfd6pAp5M";
const WATCHDOG_CHAT_ID = "8169792272";
const WATCHDOG_LOG_FILE = "/var/ossec/logs/integrations.log";
const WATCHDOG_STATE_FILE = "/var/ossec/logs/.soc-watchdog-state.json";
const WATCHDOG_NO200_THRESHOLD_MS = 30 * 60 * 1000; // 30 minutes
const WATCHDOG_DEDUP_WINDOW_MS = 30 * 60 * 1000;    // 30 minutes
const WATCHDOG_CHECK_INTERVAL_MS = 5 * 60 * 1000;   // every 5 minutes

interface WatchdogState {
  [key: string]: number;
}

async function loadWatchdogState(): Promise<WatchdogState> {
  try {
    const file = Bun.file(WATCHDOG_STATE_FILE);
    if (await file.exists()) {
      return await file.json();
    }
  } catch { }
  return {};
}

async function saveWatchdogState(state: WatchdogState) {
  try {
    await Bun.write(WATCHDOG_STATE_FILE, JSON.stringify(state));
  } catch { }
}

async function sendTelegramAlert(message: string) {
  try {
    const res = await fetch(`https://api.telegram.org/bot${WATCHDOG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: WATCHDOG_CHAT_ID,
        text: message,
        parse_mode: "HTML",
      }),
    });
    if (!res.ok) {
      console.error(`[soc-watchdog] Telegram API error: ${res.status}`);
    }
  } catch (err) {
    console.error(`[soc-watchdog] Telegram send failed:`, err);
  }
}

async function getOsType(): Promise<string> {
  try {
    const content = await Bun.file("/etc/os-release").text();
    const idMatch = content.match(/^ID="?([^"\n]*)"?$/m);
    const idLikeMatch = content.match(/^ID_LIKE="?([^"\n]*)"?$/m);
    const id = idMatch ? idMatch[1].trim() : "";
    const idLike = idLikeMatch ? idLikeMatch[1].trim() : "";
    return [id, idLike].filter(Boolean).join(" / ") || "unknown";
  } catch {
    return "unknown";
  }
}

async function getHardwareId(): Promise<string> {
  const paths = [
    "/var/hos-edge-connector/.device_id",
    "/app/.device_id",
    `${import.meta.dir}/.device_id`,
    "./.device_id"
  ];
  for (const p of paths) {
    try {
      const file = Bun.file(p);
      if (await file.exists()) {
        const hwid = await file.text();
        if (hwid.trim()) return hwid.trim();
      }
    } catch {}
  }
  return "unknown";
}

async function runSocWatchdog() {
  const now = Date.now();
  const state = await loadWatchdogState();

  // Read log file
  let lines: string[] = [];
  try {
    const file = Bun.file(WATCHDOG_LOG_FILE);
    if (!(await file.exists())) return;
    const content = await file.text();
    lines = content.split("\n");
  } catch {
    return;
  }

  const fileMtime = Date.now(); // approximate: we just read it

  // Scan for last HTTP 200 and errors
  let last200Time = 0;
  const errors = new Set<string>();
  let lastErrorRawLine = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    let lineTime = 0;
    const timeMatch = line.match(/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]/);
    if (timeMatch) {
      lineTime = new Date(timeMatch[1].replace(' ', 'T') + '+07:00').getTime();
    }

    if (line.includes("[custom-soc]") || line.includes("[malware-event]")) {
      // Check for success (HTTP 200)
      if (line.includes("200") || line.includes("HTTP 200")) {
        if (lineTime > 0) last200Time = lineTime;
      }

      // Check for errors (only if within the check interval, e.g., last 5 minutes)
      if (lineTime > 0 && now - lineTime <= WATCHDOG_CHECK_INTERVAL_MS) {
        if (line.includes("HTTP 502") || line.includes("502 Bad Gateway") || line.includes("502")) {
          errors.add("502_bad_gateway");
          lastErrorRawLine = line;
        } else if (line.includes("Read timed out")) {
          errors.add("read_timeout");
          lastErrorRawLine = line;
        } else if (line.includes("Connection refused")) {
          errors.add("connection_refused");
          lastErrorRawLine = line;
        } else if (line.includes("ERROR") && line.includes("timed out")) {
          errors.add("read_timeout");
          lastErrorRawLine = line;
        } else if (line.includes("ERROR") && line.includes("HTTPSConnectionPool")) {
          errors.add("read_timeout");
          lastErrorRawLine = line;
        }
      }
    }
  }

  const last200StaleMs = last200Time > 0 ? (now - last200Time) : 0;

  const header =
    `🏥 <b>${HOSPITAL_NAME}</b>\n` +
    `📋 รหัส: <b>${HOSPITAL_CODE}</b>\n` +
    `📍 จังหวัด: <b>${PROVINCE}</b>\n` +
    `⏰ เวลา: ${new Date().toLocaleString("th-TH", { timeZone: "Asia/Bangkok" })}\n` +
    `${"─".repeat(30)}\n`;

  // ── Case 1: No data logged for 30 minutes ──
  const isLagging = last200Time > 0 && last200StaleMs > WATCHDOG_NO200_THRESHOLD_MS;
  if (isLagging) {
    const lastAlert = state["last_lag_alert"] || 0;
    if (now - lastAlert > WATCHDOG_DEDUP_WINDOW_MS) {
      const minutesAgo = Math.round(last200StaleMs / 60000);
      const msg =
        `${header}` +
        `🔴 <b>แจ้งเตือน: ข้อมูลขาดหายเกิน 30 นาที</b>\n\n` +
        `ไม่มีข้อมูลส่งสำเร็จใน 30 นาที\n` +
        `เวลาล่าสุดที่เชื่อมต่อสำเร็จ: ${new Date(last200Time).toLocaleString("th-TH", { timeZone: "Asia/Bangkok" })}\n` +
        `ขาดช่วงมาแล้ว: ~${minutesAgo} นาที\n\n` +
        `⚠️ กรุณาตรวจสอบ Wazuh Agent หรือระบบเครือข่าย`;
      await sendTelegramAlert(msg);
      state["last_lag_alert"] = now;
      console.log("[soc-watchdog] Sent lag alert");
    }
  } else if (last200Time > 0 && last200StaleMs <= WATCHDOG_NO200_THRESHOLD_MS) {
    state["last_lag_alert"] = 0;
  }

  // ── Case 2: Error / 502 / Timeout detected ──
  for (const errKey of errors) {
    const stateKey = `last_err_${errKey}`;
    const lastAlert = state[stateKey] || 0;
    if (now - lastAlert > WATCHDOG_DEDUP_WINDOW_MS) {
      const msg =
        `${header}` +
        `🔴 <b>แจ้งเตือน: ไม่สามารถติดต่อจากส่วนกลางได้</b>\n\n` +
        `รหัสโรงพยาบาล: <b>${HOSPITAL_CODE}</b>\n` +
        `ชื่อโรงพยาบาล: <b>${HOSPITAL_NAME}</b>\n` +
        `แจ้ง: ไม่สามารถติดต่อจากส่วนกลางได้\n\n` +
        `<i>${lastErrorRawLine.length > 200 ? lastErrorRawLine.substring(0, 200) + '...' : lastErrorRawLine}</i>`;
      await sendTelegramAlert(msg);
      state[stateKey] = now;
      console.log(`[soc-watchdog] Sent error alert: ${errKey}`);
    }
  }

  await saveWatchdogState(state);
}

// Start watchdog — run immediately once, then every 5 minutes
console.log("🐕 SOC Watchdog started (check every 5 min, alert via Telegram)");
runSocWatchdog().catch(err => console.error("[soc-watchdog] Initial run error:", err));
setInterval(() => {
  runSocWatchdog().catch(err => console.error("[soc-watchdog] Error:", err));
}, WATCHDOG_CHECK_INTERVAL_MS);