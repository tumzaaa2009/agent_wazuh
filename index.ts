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

console.log("🚀 Starting Hospital Edge Connector (Bun/TypeScript)...");
console.log(`🏥 Hospital Code: ${HOSPITAL_CODE}`);

import { appendFile } from "fs/promises";

async function processQueueItem(item: any, ws?: WebSocket) {
  const { id: log_id, command, srcip, timeout, agent_id, agent_name } = item;

  if (command === "soc-firewall-drop" || command === "firewall-drop") {
    if (srcip && agent_id) {
      console.log(`🛡️ Requesting Firewall Drop for IP ${srcip} on Agent ${agent_id} (${agent_name || 'unknown'}) with timeout ${timeout || 3600}s`);
      
      try {
         const actualTimeout = timeout || 3600;
         if (agent_id === "000") {
            // For Manager (000), agent_control has issues in Wazuh 4.x.
            // We append a custom log to trigger the localfile rule 100100 natively.
            const logEntry = {
               timestamp: new Date().toISOString(),
               source: "central_soc",
               command: "firewall-drop",
               srcip: srcip,
               timeout: actualTimeout.toString(),
               log_id: log_id
            };
            await appendFile('/var/ossec/logs/active-responses.log', JSON.stringify(logEntry) + '\n');
            console.log(`[${new Date().toISOString()}] ✅ Successfully triggered firewall-drop locally on agent 000 via localfile rule for IP ${srcip}`);
         } else {
            // 1. Get the exact Active Response name available in Wazuh Manager
            const arOutput = await $`/var/ossec/bin/agent_control -L`.text();
            const match = arOutput.match(/Response name: (firewall-drop\d*)/);
            const arName = match ? match[1] : 'firewall-drop';
            
            // 2. Execute the block specifically on the targeted agent
            await $`/var/ossec/bin/agent_control -b ${srcip} -f ${arName} -u ${agent_id}`;
            console.log(`[${new Date().toISOString()}] ✅ Successfully triggered ${arName} on agent ${agent_id} to block ${srcip}`);
         }
      } catch (err) {
         console.error(`[${new Date().toISOString()}] ❌ Failed to trigger active response:`, err);
      }

      // Send ACK back if WebSocket is provided
      if (ws) {
        const ackMsg = { type: "ack", hospital_code: HOSPITAL_CODE, status: "success", log_id };
        ws.send(JSON.stringify(ackMsg));
      } else {
        // HTTP REST API processing (Optional)
        console.log(`✅ Queue item ${log_id} processed. (Ready for HTTP ACK)`);
      }
    } else {
      console.error(`⚠️ Cannot drop firewall: Missing srcip (${srcip}) or agent_id (${agent_id})`);
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

// Start WebSocket connection
connect();

// Uncomment to enable HTTP API Polling every 10 seconds
// setInterval(pollApiQueue, 10000);

