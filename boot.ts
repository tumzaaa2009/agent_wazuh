import { spawn, exec, execFile } from "child_process";
import { promisify } from "util";
import { existsSync, readdirSync, watch } from "fs";
import { readFile, writeFile, appendFile, chown, chmod, stat } from "fs/promises";
import * as path from "path";
import { $ } from "bun";

const execFileAsync = promisify(execFile);

const WS_URL = process.env.WS_URL || "wss://rh4cloudcenter.moph.go.th/ws/active-response";
const CENTRAL_API = WS_URL.replace("wss://", "https://").replace("ws://", "http://").replace("/ws/active-response", "");
const BASE_API_URL = CENTRAL_API;
const API_BASE_V2 = process.env.API_URL_V2 || "https://rh4cloudcenter.moph.go.th/api/v2";
const YARA_API_URL = process.env.YARA_API_URL || "https://rh4cloudcenter.moph.go.th/api/v1/yara-rules";
const SOC_CONFIG_URL = process.env.SOC_CONFIG_URL || "https://rh4cloudcenter.moph.go.th/api/v1/wazuh-configs";

const HOSPITAL_CODE = process.env.HOSPITAL_CODE || "";
const API_KEY = process.env.API_KEY || "";

let WAZUH_UID = process.env.WAZUH_UID || "";
let WAZUH_GID = process.env.WAZUH_GID || "";
const ROOT_UID = process.env.ROOT_UID || "0";
const IS_LINUX = process.platform === "linux";

const LOG_DIR = process.env.LOG_DIR || "/logs";
const LOG_FILE = path.join(LOG_DIR, "boots.log");
const LOG_MAX_BYTES = 10 * 1024 * 1024;

let logDirReady = false;

async function ensureLogDir() {
  try {
    await $`mkdir -p ${LOG_DIR}`.quiet().catch(() => { });
  } catch { /* best-effort */ }
}

async function rotateLogIfNeeded() {
  try {
    if (existsSync(LOG_FILE)) {
      const size = Bun.file(LOG_FILE).size;
      if (size > LOG_MAX_BYTES) {
        await $`mv -f ${LOG_FILE} ${LOG_FILE}.1`.quiet().catch(() => { });
      }
    }
  } catch { /* never block boot loop on log rotation failure */ }
}

async function bootLog(message: string, isError = false) {
  if (isError) {
    console.error(message);
  } else {
    console.log(message);
  }
  try {
    if (!logDirReady) {
      await ensureLogDir();
      logDirReady = true;
    }
    await rotateLogIfNeeded();
    const ts = new Date().toISOString();
    await appendFile(LOG_FILE, `[${ts}] ${message}\n`);
  } catch { /* never block boot loop on logging failure */ }
}

async function getOsType(): Promise<string> {
  try {
    const content = await readFile("/etc/os-release", "utf-8");
    const idMatch = content.match(/^ID="?([^"\n]*)"?$/m);
    const idLikeMatch = content.match(/^ID_LIKE="?([^"\n]*)"?$/m);
    const id = idMatch ? idMatch[1].trim() : "";
    const idLike = idLikeMatch ? idLikeMatch[1].trim() : "";
    return [id, idLike].filter(Boolean).join(" / ") || "unknown";
  } catch {
    return "unknown";
  }
}

async function detectWazuhIds() {
  if (!IS_LINUX) {
    await bootLog(`[PERM] ℹ️ Platform is '${process.platform}', not Linux — skipping unix chown/chmod entirely.`);
    return;
  }
  if (WAZUH_UID && WAZUH_GID) {
    await bootLog(`[PERM] ℹ️ Using WAZUH_UID/WAZUH_GID from env: ${WAZUH_UID}:${WAZUH_GID}`);
    return;
  }

  const osType = await getOsType();
  await bootLog(`[PERM] ℹ️ Host OS family: ${osType}`);

  try {
    const { stdout } = await execFileAsync("id", ["wazuh"]);
    const uidMatch = stdout.match(/uid=(\d+)/);
    const gidMatch = stdout.match(/gid=(\d+)/);
    if (uidMatch && gidMatch) {
      WAZUH_UID = uidMatch[1];
      WAZUH_GID = gidMatch[1];
      await bootLog(`[PERM] ✅ Detected wazuh uid:gid = ${WAZUH_UID}:${WAZUH_GID} (via 'id wazuh', OS: ${osType})`);
      return;
    }
    await bootLog(`[PERM] ⚠️ 'id wazuh' returned unexpected output, could not parse uid/gid: ${stdout.trim()}`, true);
  } catch (e: any) {
    await bootLog(`[PERM] ⚠️ 'id wazuh' failed (${e.stderr?.toString().trim() || e.message}) — trying distro-agnostic fallback ('getent')...`, true);
  }

  try {
    const { stdout: passwdLine } = await execFileAsync("getent", ["passwd", "wazuh"]);
    const parts = passwdLine.trim().split(":");
    if (parts.length >= 4 && parts[2] && parts[3]) {
      WAZUH_UID = parts[2];
      WAZUH_GID = parts[3];
      await bootLog(`[PERM] ✅ Detected wazuh uid:gid = ${WAZUH_UID}:${WAZUH_GID} (via 'getent passwd wazuh', OS: ${osType})`);
      return;
    }
    await bootLog(`[PERM] ⚠️ 'getent passwd wazuh' returned unexpected output: ${passwdLine.trim()}`, true);
  } catch (e: any) {
    await bootLog(`[PERM] ⚠️ 'getent passwd wazuh' failed (${e.stderr?.toString().trim() || e.message}) — trying stat-based fallback on known wazuh paths...`, true);
  }

  const probePaths = ["/var/ossec/logs", "/var/ossec/queue", "/var/ossec/var/run", "/var/ossec/etc/shared"];
  for (const p of probePaths) {
    try {
      const { stdout } = await execFileAsync("stat", ["-c", "%u:%g", p]);
      const [uid, gid] = stdout.trim().split(":");
      if (uid && gid && uid !== "0") {
        WAZUH_UID = uid;
        WAZUH_GID = gid;
        await bootLog(`[PERM] ✅ Detected wazuh uid:gid = ${uid}:${gid} (via stat fallback on ${p}, OS: ${osType})`);
        return;
      }
    } catch { /* try next path */ }
  }

  await bootLog(`[PERM] ❌ Could not auto-detect wazuh uid/gid on this host via 'id', 'getent', or stat probe (OS: ${osType}, tried: ${probePaths.join(", ")}). Set WAZUH_UID/WAZUH_GID env vars manually.`, true);
}

const currentDir = import.meta.dir;
const dataDir = currentDir === '/app' ? currentDir : path.join(currentDir, "..");
const versionFile = path.join(dataDir, 'agent_version.txt');
const scriptFile = path.join(currentDir, 'index.ts');

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function applyPerm(filepath: string, owner: string, mode: string, label: string) {
  if (!IS_LINUX) {
    await bootLog(`[PERM] ⏭️ ${label}: skipped (platform '${process.platform}' has no unix chown/chmod) — ${filepath}`);
    return;
  }
  if (owner.includes("undefined") || owner.startsWith(":") || owner.endsWith(":")) {
    await bootLog(`[PERM] ❌ ${label}: skipped — wazuh uid/gid not detected yet, owner was '${owner}' on ${filepath}`, true);
    return;
  }

  const [uidStr, gidStr] = owner.split(":");
  const uid = parseInt(uidStr, 10);
  const gid = parseInt(gidStr, 10);
  if (Number.isNaN(uid) || Number.isNaN(gid)) {
    await bootLog(`[PERM] ❌ ${label}: skipped — could not parse owner '${owner}' as numeric uid:gid on ${filepath}`, true);
    return;
  }

  try {
    const modeNum = parseInt(mode, 8);
    try {
      const st = await stat(filepath);
      if (st.uid === uid && st.gid === gid && (st.mode & 0o777) === modeNum) {
        return;
      }
    } catch { /* best-effort stat check */ }

    await chown(filepath, uid, gid);
    await chmod(filepath, modeNum);
    await bootLog(`[PERM] ✅ ${label}: ${filepath} -> ${owner} ${mode}`);
  } catch (e: any) {
    await bootLog(`[PERM] ❌ ${label}: FAILED to set ${owner} ${mode} on ${filepath} — ${e.message}`, true);
  }
}

async function checkAndApplyUpdate(): Promise<boolean> {
  try {
    await bootLog(`[BOOT] 📥 Checking for edge connector updates...`);
    const res = await fetch(`${CENTRAL_API}/api/v1/edge-connector/version`);
    if (res.ok) {
      const data = await res.json();
      let localVersion = "";
      if (existsSync(versionFile)) {
        const content = await readFile(versionFile, "utf-8");
        localVersion = content.split('\n')[0].trim().replace(" used", "");
      }
      if (data.success && data.version && data.version !== localVersion) {
        await bootLog(`[BOOT] 🚀 New version detected! Remote: ${data.version}, Local: ${localVersion}`);
        await bootLog(`[BOOT] 📥 Downloading new index.ts...`);
        const scriptRes = await fetch(`${CENTRAL_API}/api/v1/edge-connector/script`);
        if (scriptRes.ok) {
          const scriptText = await scriptRes.text();
          await writeFile(scriptFile, scriptText);
          await writeFile(versionFile, data.version + " used\n");
          await bootLog(`[BOOT] ✅ Successfully updated local script to version ${data.version}.`);
          await bootLog(`[BOOT] 🔄 Running update_version.sh to apply changes...`);
          await $`./update_version.sh ${data.version}`.quiet().catch(() => { });
          return true;
        } else {
          await bootLog(`[BOOT] ❌ Failed to download script. Status: ${scriptRes.status}`, true);
        }
      } else {
        await bootLog(`[BOOT] ✅ Agent is up to date (Local: ${localVersion}).`);
      }
    } else {
      await bootLog(`[BOOT] ❌ Failed to fetch version info. Status: ${res.status}`, true);
    }
  } catch (err: any) {
    await bootLog(`[BOOT] ❌ Update check error: ${err.message}`, true);
  }
  return false;
}

async function checkCustomSocUpdate(): Promise<boolean> {
  const versionFileSOC = `${dataDir}/version_custom_soc.txt`;
  exec(`mkdir -p /var/hos-edge-connector`);
  const scriptFileSOC = `${dataDir}/custom-soc`;
  const wazuhIntegrationPath = "/var/ossec/integrations/custom-soc";

  try {
    let localVersion = "";
    if (existsSync(versionFileSOC)) {
      const content = await Bun.file(versionFileSOC).text();
      localVersion = content.split('\n')[0].trim().replace(" used", "");
    } else {
      await Bun.write(versionFileSOC, "");
    }

    if (!existsSync(wazuhIntegrationPath) && existsSync(scriptFileSOC)) {
      await bootLog(`[BOOT] 📥 Restoring missing custom-soc to Wazuh from local backup...`);
      const scriptText = await Bun.file(scriptFileSOC).text();
      await $`rm -f ${wazuhIntegrationPath}`.quiet().catch((e) => bootLog(`[PERM] ❌ rm failed on ${wazuhIntegrationPath}: ${e.stderr?.toString() || e.message}`, true));
      await Bun.write(wazuhIntegrationPath, scriptText);
      await applyPerm(wazuhIntegrationPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "custom-soc restore (integrations)");
    } else if (existsSync(wazuhIntegrationPath)) {
      await applyPerm(wazuhIntegrationPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "custom-soc perm verify (integrations)");
    }
    if (existsSync(scriptFileSOC)) {
      await applyPerm(scriptFileSOC, `${ROOT_UID}:${WAZUH_GID}`, "750", "custom-soc perm verify (backup)");
    }

    await bootLog(`[BOOT] 📥 Querying API for latest Custom SOC patches...`);
    const res = await fetch(`${CENTRAL_API}/api/v1/custom-soc/version`);
    if (res.ok) {
      const data = await res.json();
      if (data.success && data.version && data.version !== localVersion) {
        await bootLog(`[BOOT] 🚀 [UPDATE] Custom SOC check! Remote: ${data.version}, Local: ${localVersion}.`);
        const scriptRes = await fetch(`${CENTRAL_API}/api/v1/custom-soc/script`);
        if (scriptRes.ok) {
          const scriptText = await scriptRes.text();
          await $`rm -f ${scriptFileSOC}`.quiet().catch((e) => bootLog(`[PERM] ❌ rm failed on ${scriptFileSOC}: ${e.stderr?.toString() || e.message}`, true));
          await Bun.write(scriptFileSOC, scriptText);
          await Bun.write(versionFileSOC, data.version + " used\n");
          await applyPerm(scriptFileSOC, `${ROOT_UID}:${WAZUH_GID}`, "750", "custom-soc backup copy");
          await $`rm -f ${wazuhIntegrationPath}`.quiet().catch((e) => bootLog(`[PERM] ❌ rm failed on ${wazuhIntegrationPath}: ${e.stderr?.toString() || e.message}`, true));
          await Bun.write(wazuhIntegrationPath, scriptText);
          await applyPerm(wazuhIntegrationPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "custom-soc update (integrations)");
          await bootLog("[BOOT] ✅ custom-soc updated.");
          return true;
        }
      }
    }
  } catch (err: any) {
    await bootLog(`[BOOT] ❌ custom-soc: ${err.message}`, true);
  }
  return false;
}

async function fetchYaraRules(): Promise<boolean> {
  try {
    await bootLog(`[BOOT] 📥 Checking YARA rules version...`);
    const RULES_PATH = "/var/ossec/etc/shared/default/yara_rules.yar";
    try {
      const versionRes = await fetch(`${YARA_API_URL}/version`, { signal: AbortSignal.timeout(5000) });
      if (versionRes.ok) {
        const vData = await versionRes.json();
        const versionFile = `${dataDir}/yara_rules_version.txt`;
        if (existsSync(versionFile)) {
          const content = await Bun.file(versionFile).text();
          let localVersion = content.split('\n')[0].trim().replace(" used", "");
          if (localVersion === String(vData.version)) return false;
        }
        const response = await fetch(YARA_API_URL);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.rules) {
            let combinedRules = "";
            for (const rule of data.rules) {
              combinedRules += Buffer.from(rule.content, 'base64').toString('utf-8') + "\n";
            }
            await Bun.write(RULES_PATH, combinedRules);
            await applyPerm(RULES_PATH, `${WAZUH_UID}:${WAZUH_GID}`, "660", "YARA rules");
            await Bun.write(versionFile, String(vData.version) + " used\n");
            await bootLog(`[BOOT] ✅ Successfully updated YARA rules.`);
            return true;
          }
        }
      }
    } catch { }
  } catch (err) { }
  return false;
}

async function ensureWazuhTimeouts(): Promise<boolean> {
  const confPath = "/var/ossec/etc/local_internal_options.conf";
  try {
    let content = "";
    if (existsSync(confPath)) {
      content = await Bun.file(confPath).text();
    }
    let changed = false;
    const settings = {
      "monitord.monitor_time": "120",
      "wazuh_modulesd.timeout": "120",
      "wazuh_analysisd.timeout": "120"
    };
    let lines = content.split('\n');
    for (const [key, val] of Object.entries(settings)) {
      const pattern = new RegExp(`^\\s*${key}\\s*=`);
      if (!lines.some(l => pattern.test(l))) {
        lines.push(`${key}=${val}`);
        changed = true;
      }
    }
    if (changed) {
      await Bun.write(confPath, lines.join('\n').trim() + '\n');
      await applyPerm(confPath, `${ROOT_UID}:${WAZUH_GID}`, "640", "local_internal_options.conf");
      await bootLog(`[BOOT] ✅ Applied extended Wazuh timeouts (I/O heavy load protection).`);
      return true;
    }
  } catch (err: any) {
    await bootLog(`[BOOT] ❌ Timeout config error: ${err.message}`, true);
  }
  return false;
}

async function checkMispUpdates(): Promise<boolean> {
  try {
    await bootLog(`[BOOT] 📥 Checking for MISP updates...`);
    const res = await fetch(`${BASE_API_URL}/api/v1/threat-intel/misp-version`, {
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });
    if (res.ok) {
      const data = await res.json();
      if (data.success && data.version) {
        const versionFile = `${dataDir}/version_misp_ioc.txt`;
        if (existsSync(versionFile)) {
          const content = await Bun.file(versionFile).text();
          let localVersion = content.split('\n')[0].trim().replace(" used", "");
          if (localVersion === data.version) return false;
        }
        await bootLog(`[BOOT] 📥 MISP IOC updates found (${data.version})! Downloading...`);

        const types = [
          { url: 'misp-ip.txt', file: 'misp_ip' },
          { url: 'misp-domain.txt', file: 'misp_domain' },
          { url: 'misp-hash.txt', file: 'misp_hash' },
          { url: 'queue-c2.txt', file: 'queue_c2_servers' },
          { url: 'queue-virus.txt', file: 'queue_virus_sigs' },
          { url: 'queue-compromised.txt', file: 'queue_compromised' },
          { url: 'queue-urls.txt', file: 'queue_malicious_urls' }
        ];
        let hasChanges = false;
        exec(`mkdir -p /var/ossec/etc/lists`);
        for (const { url, file } of types) {
          const r = await fetch(`${BASE_API_URL}/api/v1/threat-intel/${url}`, { headers: { "Authorization": `Bearer ${API_KEY}` } });
          if (r.ok) {
            const content = await r.text();
            const filepath = `/var/ossec/etc/lists/${file}`;
            let oldContent = "";
            if (existsSync(filepath)) {
              oldContent = await Bun.file(filepath).text();
            }
            if (content !== oldContent) {
              await Bun.write(filepath, content);
              await applyPerm(filepath, `${WAZUH_UID}:${WAZUH_GID}`, "660", `MISP list (${file})`);
              hasChanges = true;
            }
          }
          await sleep(5000);
        }
        await Bun.write(versionFile, data.version + " used\n");

        return hasChanges;
      }
    }
  } catch (err) { }
  return false;
}

async function fetchSocConfigs(): Promise<boolean> {
  try {
    await bootLog(`[BOOT] 📥 Checking for SOC configs updates...`);
    const versionRes = await fetch(`${SOC_CONFIG_URL}/version`);
    if (versionRes.ok) {
      const vData = await versionRes.json();
      if (vData.success && vData.version) {
        const versionFile = `${dataDir}/version_wazuh_configs.txt`;
        if (existsSync(versionFile)) {
          const localVersion = (await Bun.file(versionFile).text()).split('\n')[0]?.trim() || "";
          const remoteVersion = String(vData.version).split('\n')[0]?.trim() || "";
          if (localVersion === remoteVersion || localVersion === `${remoteVersion} used`) return false;
        }
        await bootLog(`[BOOT] 📥 Updates found! Fetching latest SOC configs...`);
        const response = await fetch(SOC_CONFIG_URL);
        if (response.ok) {
          const data = await response.json();
          if (data.success) {
            if (data.rules) {
              for (const rule of data.rules) {
                const filepath = `/var/ossec/etc/rules/${rule.filename}`;
                await Bun.write(filepath, Buffer.from(rule.content, 'base64').toString('utf-8'));
                await applyPerm(filepath, `${WAZUH_UID}:${WAZUH_GID}`, "660", `SOC config rule (${rule.filename})`);
              }
            }
            if (data.decoders) {
              for (const decoder of data.decoders) {
                const filepath = `/var/ossec/etc/decoders/${decoder.filename}`;
                await Bun.write(filepath, Buffer.from(decoder.content, 'base64').toString('utf-8'));
                await applyPerm(filepath, `${WAZUH_UID}:${WAZUH_GID}`, "660", `SOC config decoder (${decoder.filename})`);
              }
            }

            if (data.mockup_agent || data.mockup_manager) {
              await autoInjectWazuhConfigs(data);
            }
            const remoteVersion = String(vData.version).split('\n')[0]?.trim() || "";
            await Bun.write(versionFile, remoteVersion + " used\n");

            await bootLog("[BOOT] ✅ Wazuh configs synced successfully!");
            return true;
          }
        }
      }
    }
  } catch (err) { }
  return false;
}

async function autoInjectWazuhConfigs(data: any) {
  const ossecConfPath = '/var/ossec/etc/ossec.conf';
  const sharedDir = '/var/ossec/etc/shared';
  const defaultAgentConfPath = path.join(sharedDir, 'default', 'agent.conf');

  try {
    let managerMockup = data && data.mockup_manager ? Buffer.from(data.mockup_manager, 'base64').toString('utf-8') : "";
    let agentMockup = data && data.mockup_agent ? Buffer.from(data.mockup_agent, 'base64').toString('utf-8') : "";

    if (managerMockup) {
      await bootLog("[BOOT] ⚙️ Overwriting ossec.conf with central SOC mockup...");
      await Bun.write(ossecConfPath, managerMockup);
      await applyPerm(ossecConfPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "ossec.conf (manager)");
    }

    if (agentMockup) {
      await Bun.write(defaultAgentConfPath, agentMockup);
      await applyPerm(defaultAgentConfPath, `${WAZUH_UID}:${WAZUH_GID}`, "750", "agent.conf in default");
    }

    const defaultDir = path.join(sharedDir, 'default');
    if (existsSync(defaultDir)) {
      const defaultFiles = readdirSync(defaultDir, { withFileTypes: true });
      if (existsSync(sharedDir)) {
        const entries = readdirSync(sharedDir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory() && entry.name !== 'default') {
            for (const file of defaultFiles) {
              if (file.isFile()) {
                const srcPath = path.join(defaultDir, file.name);
                const destPath = path.join(sharedDir, entry.name, file.name);

                const content = await readFile(srcPath, 'utf8');
                let destContent = "";
                if (existsSync(destPath)) {
                  destContent = await readFile(destPath, 'utf8');
                }

                if (content !== destContent) {
                  await Bun.write(destPath, content);
                  await applyPerm(destPath, `${WAZUH_UID}:${WAZUH_GID}`, "750", `${file.name} in ${entry.name}`);
                }
              }
            }
          }
        }
      }
    }
  } catch (err) { }
}

async function fetchPoliciesV2(): Promise<boolean> {
  const API_BASE_V2 = process.env.API_URL_V2 || "https://rh4cloudcenter.moph.go.th/api/v2";
  try {
    await bootLog(`[BOOT] 📥 Checking for OpenXDR Policy updates...`);
    const response = await fetch(`${API_BASE_V2}/policies/${HOSPITAL_CODE}`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });

    if (response.ok) {
      const data = await response.json();
      if (data.success && data.policy) {
        const remoteVersion = String(data.policy.version ?? "");
        const versionFile = `${dataDir}/version_runtime_policy.txt`;
        let localVersion = "";
        if (existsSync(versionFile)) {
          const content = await Bun.file(versionFile).text();
          localVersion = content.split('\n')[0].trim().replace(" used", "");
        }

        if (remoteVersion && remoteVersion === localVersion) {
          return false;
        }

        const filepath = '/var/ossec/etc/runtime_policy.json';
        await Bun.write(filepath, JSON.stringify(data.policy, null, 2));
        await applyPerm(filepath, `${WAZUH_UID}:${WAZUH_GID}`, "660", "runtime_policy.json");
        await Bun.write(versionFile, remoteVersion + " used\n");
        await bootLog(`[BOOT] ✅ OpenXDR Phase 1: Fetched and saved runtime_policy.json (v${remoteVersion})`);
        return true;
      }
    }
  } catch (err: any) {
    await bootLog(`[BOOT] ❌ API v2 Policy Fetch Error: ${err.message}`, true);
  }
  return false;
}

let lastWazuhRestartTime = 0;
const RESTART_COOLDOWN_MS = 15 * 60 * 1000;
const RESTART_RETRY_COOLDOWN_MS = 2 * 60 * 1000;

async function anyWazuhProcessAlive(): Promise<boolean> {
  try {
    const { stdout } = await $`nsenter -t 1 -m -u -i -n -p pgrep -f "wazuh-(authd|db|execd|analysisd|syscheckd|remoted|logcollector|monitord|modulesd|clusterd|apid|integratord|csyslogd|agentlessd)"`.nothrow();
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

async function waitForWazuhStopped(maxWaitMs = 30000, intervalMs = 1000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    if (!(await anyWazuhProcessAlive())) return true;
    await sleep(intervalMs);
  }
  return false;
}

async function waitForPortsFree(maxRetries = 60) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const { stdout } = await $`nsenter -t 1 -m -u -i -n -p ss -tnl`.nothrow();
      if (!stdout.includes(":1515 ") && !stdout.includes(":1514 ") && !stdout.includes(":55000 ")) {
        return true;
      }
    } catch { /* ignore */ }
    await sleep(1000);
  }
  return false;
}

async function verifyWazuhManagerHealthy(retries = 60, delayMs = 5000): Promise<boolean> {
  for (let i = 0; i < retries; i++) {
    try {
      const { stdout } = await $`nsenter -t 1 -m -u -i -n -p /var/ossec/bin/wazuh-control status`.nothrow();
      const coreOk = /wazuh-modulesd is running/i.test(stdout) && /wazuh-analysisd is running/i.test(stdout);
      const apiOk = /wazuh-apid is running/i.test(stdout);

      if (coreOk && apiOk) {
        const { stdout: curlOut } = await $`curl -sk -o /dev/null -w "%{http_code}" --max-time 3 https://127.0.0.1:55000/`.nothrow();
        if (curlOut.trim() && curlOut.trim() !== "000") {
          return true;
        }
      }
    } catch { /* manager อาจยังไม่ตอบ ลองรอบถัดไป */ }
    await sleep(delayMs);
  }
  return false;
}

async function stopWazuhManagerSafely() {
  await bootLog(`[BOOT] 🔄 Stopping Wazuh Manager gracefully...`);
  await $`nsenter -t 1 -m -u -i -n -p systemctl stop wazuh-manager`.quiet().catch(() => { });

  const stoppedGracefully = await waitForWazuhStopped(30000, 1000);
  if (!stoppedGracefully) {
    await bootLog(`[BOOT] ⚠️ Graceful stop timed out after 30s — escalating to force kill (last resort)...`, true);
    await $`nsenter -t 1 -m -u -i -n -p bash -c "fuser -k 55000/tcp; fuser -k 1514/tcp; fuser -k 1515/tcp; killall -9 wazuh-authd wazuh-db wazuh-execd wazuh-analysisd wazuh-syscheckd wazuh-remoted wazuh-logcollector wazuh-monitord wazuh-modulesd wazuh-clusterd wazuh-apid wazuh-integratord wazuh-csyslogd wazuh-agentlessd; pkill -9 -f '[w]azuh_apid'"`.quiet().catch(() => { });
    await waitForWazuhStopped(15000, 1000);
  }

  const trulyStopped = !(await anyWazuhProcessAlive());
  if (trulyStopped) {
    await bootLog(`[BOOT] 🧹 Manager confirmed stopped — safe to clear SQLite WAL/SHM lock files...`);
    await $`rm -f /var/ossec/var/run/.restart`.quiet().catch(() => { });
    await $`rm -f /var/ossec/queue/db/*.db-wal /var/ossec/queue/db/*.db-shm /var/ossec/queue/db/*-wal /var/ossec/queue/db/*-shm`.quiet().catch(() => { });
  } else {
    await bootLog(`[BOOT] ⚠️ Could not confirm manager fully stopped — skipping WAL/SHM cleanup to avoid corrupting an in-use database.`, true);
  }
}

async function restartWazuhManagerThrottled(force = false) {
  const now = Date.now();
  if (!force && lastWazuhRestartTime > 0 && (now - lastWazuhRestartTime < RESTART_COOLDOWN_MS)) {
    const remainingSec = Math.round((RESTART_COOLDOWN_MS - (now - lastWazuhRestartTime)) / 1000);
    await bootLog(`[BOOT] ⏳ Wazuh Manager restart skipped (Cooldown active: ${remainingSec}s remaining)...`);
    return;
  }
  lastWazuhRestartTime = Date.now();

  try {
    await bootLog(`[BOOT] 🔄 Restarting Wazuh Manager via systemctl...`);
    await $`nsenter -t 1 -m -u -i -n -p bash -c "systemctl restart wazuh-manager >/dev/null 2>&1"`.quiet();
    await bootLog(`[BOOT] ✅ success restart wazuh manager`);
  } catch (e: any) {
    await bootLog(`[BOOT] ❌ Restart command failed: ${e.stderr?.toString().trim() || e.message}`, true);
  }
}

async function main() {
  await bootLog(`[BOOT] 🚀 Updater service started. Polling every 1 minute.`);
  await detectWazuhIds();
  await autoInjectWazuhConfigs({});

  try {
    const sharedDir = '/var/ossec/etc/shared';
    if (existsSync(sharedDir)) {
      watch(sharedDir, (eventType: string, filename: string | Buffer | null) => {
        if (filename && filename.toString() !== 'default') {
          bootLog(`[BOOT] 📂 Detected change in shared groups (${eventType}: ${filename}), syncing default configs...`);
          autoInjectWazuhConfigs({}).catch((e) => bootLog(`[BOOT] ❌ Group sync error: ${e.message}`, true));
        }
      });
      await bootLog(`[BOOT] 👁️ Watching ${sharedDir} for new groups...`);
    }
  } catch (err: any) {
    await bootLog(`[BOOT] ❌ Failed to setup watch: ${err.message}`, true);
  }

  while (true) {
    if (IS_LINUX) {
      try {
        let loggedWait = false;
        while (true) {
          const res = await $`nsenter -t 1 -m -u -i -n -p bash -c "systemctl is-active wazuh-manager"`.nothrow().quiet();
          if (res.stdout.toString().trim() === "active") {
            if (loggedWait) await bootLog(`[BOOT] 🟢 Wazuh Manager is active. Resuming boot.ts operation...`);
            break;
          } else {
            if (!loggedWait) {
              await bootLog(`[BOOT] ⏳ Wazuh Manager is restarting or inactive. Pausing boot.ts until it finishes...`);
              loggedWait = true;
            }
            await sleep(5000);
          }
        }
      } catch (e) { }
    }

    let updatedPatches: string[] = [];

    if (IS_LINUX && (!WAZUH_UID || !WAZUH_GID)) {
      await detectWazuhIds();
    }

    if (await ensureWazuhTimeouts()) updatedPatches.push("WazuhTimeouts");
    if (await checkAndApplyUpdate()) { /* script update itself restarts via ./update_version.sh */ }
    await fetchPoliciesV2();
    if (await checkCustomSocUpdate()) updatedPatches.push("CustomSOC");
    if (await fetchYaraRules()) updatedPatches.push("YaraRules");
    if (await checkMispUpdates()) updatedPatches.push("MISP");
    if (await fetchSocConfigs()) updatedPatches.push("SOCConfigs");
    if (await syncRulePolicy()) updatedPatches.push("RulePolicy");

    if (updatedPatches.length > 0) {
      await bootLog(`[BOOT] 🔄 Updates downloaded successfully for: ${updatedPatches.join(', ')}. (Restart Wazuh bypassed)`);
      await bootLog(`[BOOT] 🚀 Executing update_version.sh on host...`);
      await $`nsenter -t 1 -m -u -i -n -p bash -c "cd /var/hos-edge-connector && sh update_version.sh"`.quiet();
      await bootLog(`[BOOT] ✅ Successfully triggered update_version.sh`);
    }

    await sleep(60 * 1000);
  }
}

main().catch(async (err) => {
  await bootLog(`[BOOT] 💥 Critical Updater Error: ${err.message || err}`, true);
  process.exit(1);
});

async function syncRulePolicy(): Promise<boolean> {
  try {
    await bootLog(`[BOOT] 📥 Querying SOC for latest policy queues...`);
    const versionFile = `${dataDir}/soc_rules_version.txt`;
    let currentTopLine = '';
    if (existsSync(versionFile)) {
      const content = await Bun.file(versionFile).text();
      currentTopLine = content.split('\n')[0]?.trim() || '';
    }

    const res = await fetch(`${CENTRAL_API}/api/v1/rules/queues?hospital_code=${HOSPITAL_CODE}`);
    if (!res.ok) return false;
    const data = await res.json();
    const updates = data.queues;

    let targetHash = "";
    let isQueue = false;
    let isRollback = false;

    if (updates && updates.length > 0) {
      targetHash = updates[0].version_hash;
      isQueue = true;
      isRollback = updates[0].action === 'rollback';
    } else {
      const statusRes = await fetch(`${CENTRAL_API}/api/v1/rules/status`);
      if (statusRes.ok) {
        const statusData: any = await statusRes.json();
        targetHash = statusData.current_hash;
      }
    }

    if (targetHash && currentTopLine !== `${targetHash} used`) {
      await bootLog(`[BOOT] 🔍 Checking updates... Found target patch: ${targetHash}`);
      await bootLog(`[BOOT] 📥 Downloading configuration payload for patch: ${targetHash}...`);

      let configUrl = `${CENTRAL_API}/api/v1/rules/configs`;
      if (isRollback) {
        configUrl = `${CENTRAL_API}/api/v1/rules/backup/${targetHash}`;
      }

      const configRes = await fetch(configUrl);
      if (configRes.ok) {
        const configData = await configRes.json();
        const { agent_xml, manager_xml, wazuh_files } = configData;

        const agentMockupPath = '/var/ossec/etc/shared/default/agent_mockup.xml';
        const managerMockupPath = '/var/ossec/etc/manager_mockup.xml';

        await Bun.write(agentMockupPath, agent_xml);
        await applyPerm(agentMockupPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "agent_mockup.xml");

        await Bun.write(managerMockupPath, manager_xml);
        await applyPerm(managerMockupPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "manager_mockup.xml");

        if (wazuh_files && Array.isArray(wazuh_files)) {
          for (const file of wazuh_files) {
            if (file.type === 'rule') {
              const p = `/var/ossec/etc/rules/${file.filename}`;
              await Bun.write(p, file.content);
              await applyPerm(p, `${WAZUH_UID}:${WAZUH_GID}`, "660", `queued rule (${file.filename})`);
            } else if (file.type === 'decoder') {
              const p = `/var/ossec/etc/decoders/${file.filename}`;
              await Bun.write(p, file.content);
              await applyPerm(p, `${WAZUH_UID}:${WAZUH_GID}`, "660", `queued decoder (${file.filename})`);
            }
            await sleep(3000);
          }
        }

        await autoInjectWazuhConfigs({
          mockup_manager: manager_xml ? Buffer.from(manager_xml).toString('base64') : null,
          mockup_agent: agent_xml ? Buffer.from(agent_xml).toString('base64') : null
        });

        await Bun.write(versionFile, `${targetHash} used\n`);
        await bootLog(`[BOOT] ✅ Rules applied successfully for ${targetHash}`);

        if (isQueue) {
          await fetch(`${CENTRAL_API}/api/v1/rules/queues?hospital_code=${HOSPITAL_CODE}`, {
            method: "DELETE"
          });
        }

        return true;
      }
    }
  } catch (err: any) {
    await bootLog(`[BOOT] ❌ [SYNC ERROR]: ${err.message}`, true);
  }
  return false;
}