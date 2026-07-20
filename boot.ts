import { spawn, exec, execFile } from "child_process";
import { promisify } from "util";
import { existsSync } from "fs";
import { readFile, writeFile, appendFile } from "fs/promises";
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

// The updater runs inside a container whose own /etc/passwd does NOT have the
// "wazuh" user/group, even though /var/ossec is bind-mounted from the host where it does.
// chown/chmod by NAME fails inside the container because name resolution happens in the
// container's own nsswitch, not the host's. Numeric uid:gid works regardless of names,
// BUT the actual uid/gid differ across distros (Ubuntu vs AlmaLinux install wazuh with
// different ids), so we can't hardcode a single number — we detect it at runtime.
// Env override (WAZUH_UID / WAZUH_GID) always wins if set.
let WAZUH_UID = process.env.WAZUH_UID || "";
let WAZUH_GID = process.env.WAZUH_GID || "";
const ROOT_UID = process.env.ROOT_UID || "0";
const IS_LINUX = process.platform === "linux";

// Reads /etc/os-release to identify the distro family (Ubuntu/Debian, RHEL/AlmaLinux/CentOS/Rocky, ...).
// Used purely for logging/diagnostics so we know which fallback path was needed on which distro.
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
    console.log(`[PERM] ℹ️ Platform is '${process.platform}', not Linux — skipping unix chown/chmod entirely.`);
    return;
  }
  if (WAZUH_UID && WAZUH_GID) {
    console.log(`[PERM] ℹ️ Using WAZUH_UID/WAZUH_GID from env: ${WAZUH_UID}:${WAZUH_GID}`);
    return;
  }

  const osType = await getOsType();
  console.log(`[PERM] ℹ️ Host OS family: ${osType}`);

  // Method 1 (primary): `id wazuh`
  // Output format: uid=115(wazuh) gid=125(wazuh) groups=125(wazuh)
  // This is POSIX/coreutils standard and works the same way on Ubuntu/Debian, RHEL/AlmaLinux/
  // CentOS/Rocky, etc. — as long as the container can resolve the "wazuh" user (e.g. /etc/passwd
  // is shared/bind-mounted, or nsswitch is configured to see it).
  try {
    const { stdout } = await execFileAsync("id", ["wazuh"]);
    const uidMatch = stdout.match(/uid=(\d+)/);
    const gidMatch = stdout.match(/gid=(\d+)/);
    if (uidMatch && gidMatch) {
      WAZUH_UID = uidMatch[1];
      WAZUH_GID = gidMatch[1];
      console.log(`[PERM] ✅ Detected wazuh uid:gid = ${WAZUH_UID}:${WAZUH_GID} (via 'id wazuh', OS: ${osType})`);
      return;
    }
    console.error(`[PERM] ⚠️ 'id wazuh' returned unexpected output, could not parse uid/gid: ${stdout.trim()}`);
  } catch (e: any) {
    console.error(`[PERM] ⚠️ 'id wazuh' failed (${e.stderr?.toString().trim() || e.message}) — trying distro-agnostic fallback ('getent')...`);
  }

  // Method 2 (fallback): `getent passwd wazuh`
  // Reads directly from whatever nsswitch source is configured (files, ldap, sssd, ...), so it
  // covers the same distros as Method 1 but can succeed in cases where `id` itself isn't on PATH
  // or behaves oddly in a minimal container image.
  // Format: wazuh:x:115:125:wazuh:/var/ossec:/sbin/nologin
  try {
    const { stdout: passwdLine } = await execFileAsync("getent", ["passwd", "wazuh"]);
    const parts = passwdLine.trim().split(":");
    if (parts.length >= 4 && parts[2] && parts[3]) {
      WAZUH_UID = parts[2];
      WAZUH_GID = parts[3];
      console.log(`[PERM] ✅ Detected wazuh uid:gid = ${WAZUH_UID}:${WAZUH_GID} (via 'getent passwd wazuh', OS: ${osType})`);
      return;
    }
    console.error(`[PERM] ⚠️ 'getent passwd wazuh' returned unexpected output: ${passwdLine.trim()}`);
  } catch (e: any) {
    console.error(`[PERM] ⚠️ 'getent passwd wazuh' failed (${e.stderr?.toString().trim() || e.message}) — trying stat-based fallback on known wazuh paths...`);
  }

  // Method 3 (last resort): stat-based probe.
  // If the "wazuh" user can't be resolved at all inside the container (e.g. fully detached from
  // the host's user database), the bind-mounted files still carry the correct numeric ownership,
  // so we infer uid/gid from a path Wazuh itself already owns.
  const probePaths = ["/var/ossec/logs", "/var/ossec/queue", "/var/ossec/var/run", "/var/ossec/etc/shared"];
  for (const p of probePaths) {
    try {
      const { stdout } = await execFileAsync("stat", ["-c", "%u:%g", p]);
      const [uid, gid] = stdout.trim().split(":");
      if (uid && gid && uid !== "0") {
        WAZUH_UID = uid;
        WAZUH_GID = gid;
        console.log(`[PERM] ✅ Detected wazuh uid:gid = ${uid}:${gid} (via stat fallback on ${p}, OS: ${osType})`);
        return;
      }
    } catch { /* try next path */ }
  }

  console.error(`[PERM] ❌ Could not auto-detect wazuh uid/gid on this host via 'id', 'getent', or stat probe (OS: ${osType}, tried: ${probePaths.join(", ")}). Set WAZUH_UID/WAZUH_GID env vars manually.`);
}

const currentDir = import.meta.dir;
const dataDir = currentDir === '/app' ? currentDir : path.join(currentDir, "..");
const versionFile = path.join(dataDir, 'agent_version.txt');
const scriptFile = path.join(currentDir, 'index.ts');

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Applies owner:group + chmod to a path using the REAL system chown/chmod binaries
// (via execFile, no shell involved) — avoids Bun Shell's built-in chown mis-parsing "user:group".
// No-ops safely on non-Linux platforms (e.g. Windows agents) since unix ownership doesn't apply there.
// Always logs the result (success, failure, or skip).
async function applyPerm(filepath: string, owner: string, mode: string, label: string) {
  if (!IS_LINUX) {
    console.log(`[PERM] ⏭️ ${label}: skipped (platform '${process.platform}' has no unix chown/chmod) — ${filepath}`);
    return;
  }
  if (owner.includes("undefined") || owner.startsWith(":") || owner.endsWith(":")) {
    console.error(`[PERM] ❌ ${label}: skipped — wazuh uid/gid not detected yet, owner was '${owner}' on ${filepath}`);
    return;
  }
  try {
    await execFileAsync("chown", [owner, filepath]);
    await execFileAsync("chmod", [mode, filepath]);
    console.log(`[PERM] ✅ ${label}: ${filepath} -> ${owner} ${mode}`);
  } catch (e: any) {
    console.error(`[PERM] ❌ ${label}: FAILED to set ${owner} ${mode} on ${filepath} — ${e.stderr?.toString().trim() || e.message}`);
  }
}

async function checkAndApplyUpdate(): Promise<boolean> {
  try {
    console.log(`[BOOT] 📥 Checking for edge connector updates...`);
    const res = await fetch(`${CENTRAL_API}/api/v1/edge-connector/version`);
    if (res.ok) {
      const data = await res.json();
      let localVersion = "";
      if (existsSync(versionFile)) {
        const content = await readFile(versionFile, "utf-8");
        localVersion = content.split('\n')[0].trim().replace(" used", "");
      }
      if (data.success && data.version && data.version !== localVersion) {
        console.log(`[BOOT] 🚀 New version detected! Remote: ${data.version}, Local: ${localVersion}`);
        console.log(`[BOOT] 📥 Downloading new index.ts...`);
        const scriptRes = await fetch(`${CENTRAL_API}/api/v1/edge-connector/script`);
        if (scriptRes.ok) {
          const scriptText = await scriptRes.text();
          await writeFile(scriptFile, scriptText);
          await writeFile(versionFile, data.version + " used\n");
          console.log(`[BOOT] ✅ Successfully updated local script to version ${data.version}.`);
          console.log(`[BOOT] 🔄 Running update_version.sh to apply changes...`);
          await $`./update_version.sh ${data.version}`.quiet().catch(() => { });
          return true;
        } else {
          console.error(`[BOOT] ❌ Failed to download script. Status: ${scriptRes.status}`);
        }
      } else {
        console.log(`[BOOT] ✅ Agent is up to date (Local: ${localVersion}).`);
      }
    } else {
      console.error(`[BOOT] ❌ Failed to fetch version info. Status: ${res.status}`);
    }
  } catch (err: any) {
    console.error(`[BOOT] ❌ Update check error: ${err.message}`);
  }
  return false;
}

async function checkCustomSocUpdate() {
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
      console.log(`[BOOT] 📥 Restoring missing custom-soc to Wazuh from local backup...`);
      const scriptText = await Bun.file(scriptFileSOC).text();
      await $`rm -f ${wazuhIntegrationPath}`.quiet().catch((e) => console.error(`[PERM] ❌ rm failed on ${wazuhIntegrationPath}: ${e.stderr?.toString() || e.message}`));
      await Bun.write(wazuhIntegrationPath, scriptText);
      await applyPerm(wazuhIntegrationPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "custom-soc restore (integrations)");
    }

    console.log(`[BOOT] 📥 Querying API for latest Custom SOC patches...`);
    const res = await fetch(`${CENTRAL_API}/api/v1/custom-soc/version`);
    if (res.ok) {
      const data = await res.json();
      if (data.success && data.version && data.version !== localVersion) {
        console.log(`[BOOT] 🚀 [UPDATE] Custom SOC check! Remote: ${data.version}, Local: ${localVersion}.`);
        const scriptRes = await fetch(`${CENTRAL_API}/api/v1/custom-soc/script`);
        if (scriptRes.ok) {
          const scriptText = await scriptRes.text();
          await $`rm -f ${scriptFileSOC}`.quiet().catch((e) => console.error(`[PERM] ❌ rm failed on ${scriptFileSOC}: ${e.stderr?.toString() || e.message}`));
          await Bun.write(scriptFileSOC, scriptText);
          await Bun.write(versionFileSOC, data.version + " used\n");
          await applyPerm(scriptFileSOC, `${ROOT_UID}:${WAZUH_GID}`, "750", "custom-soc backup copy");
          await $`rm -f ${wazuhIntegrationPath}`.quiet().catch((e) => console.error(`[PERM] ❌ rm failed on ${wazuhIntegrationPath}: ${e.stderr?.toString() || e.message}`));
          await Bun.write(wazuhIntegrationPath, scriptText);
          await applyPerm(wazuhIntegrationPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "custom-soc remote update (integrations)");
          await $`SYSTEMD_IGNORE_CHROOT=1 systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart`.quiet().catch(() => { });
          console.log(`[BOOT] ✅ Successfully updated custom-soc.`);
        }
      }
    }
  } catch (err) { }
}

async function fetchYaraRules() {
  try {
    console.log(`[BOOT] 📥 Checking YARA rules version...`);
    const RULES_PATH = "/var/ossec/etc/shared/default/yara_rules.yar";
    try {
      const versionRes = await fetch(`${YARA_API_URL}/version`, { signal: AbortSignal.timeout(5000) });
      if (versionRes.ok) {
        const vData = await versionRes.json();
        const versionFile = `${dataDir}/yara_rules_version.txt`;
        if (existsSync(versionFile)) {
          const content = await Bun.file(versionFile).text();
          let localVersion = content.split('\n')[0].trim().replace(" used", "");
          if (localVersion === String(vData.version)) return;
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
            console.log(`[BOOT] ✅ Successfully updated YARA rules.`);
          }
        }
      }
    } catch { }
  } catch (err) { }
}

async function checkMispUpdates() {
  try {
    console.log(`[BOOT] 📥 Checking for MISP updates...`);
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
          if (localVersion === data.version) return;
        }
        console.log(`[BOOT] 📥 MISP IOC updates found (${data.version})! Downloading...`);
        const types = [
          { url: 'misp-ip.txt', file: 'misp_ip' },
          { url: 'misp-domain.txt', file: 'misp_domain' },
          { url: 'misp-hash.txt', file: 'misp_hash' }
        ];
        exec(`mkdir -p /var/ossec/etc/lists`);
        for (const { url, file } of types) {
          const r = await fetch(`${BASE_API_URL}/api/v1/threat-intel/${url}`, { headers: { "Authorization": `Bearer ${API_KEY}` } });
          if (r.ok) {
            const filepath = `/var/ossec/etc/lists/${file}`;
            await Bun.write(filepath, await r.text());
            await applyPerm(filepath, `${WAZUH_UID}:${WAZUH_GID}`, "660", `MISP list (${file})`);
          }
        }
        await Bun.write(versionFile, data.version + " used\n");
        await $`SYSTEMD_IGNORE_CHROOT=1 systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart`.quiet().catch(() => { });
      }
    }
  } catch (err) { }
}

async function fetchSocConfigs() {
  try {
    console.log(`[BOOT] 📥 Checking for SOC configs updates...`);
    const versionRes = await fetch(`${SOC_CONFIG_URL}/version`);
    if (versionRes.ok) {
      const vData = await versionRes.json();
      if (vData.success && vData.version) {
        const versionFile = `${dataDir}/version_wazuh_configs.txt`;
        if (existsSync(versionFile)) {
          const localVersion = (await Bun.file(versionFile).text()).split('\n')[0]?.trim() || "";
          const remoteVersion = String(vData.version).split('\n')[0]?.trim() || "";
          if (localVersion === remoteVersion || localVersion === `${remoteVersion} used`) return;
        }
        console.log(`[BOOT] 📥 Updates found! Fetching latest SOC configs...`);
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
            const remoteVersion = String(vData.version).split('\n')[0]?.trim() || "";
            await Bun.write(versionFile, remoteVersion + " used\n");

            if (data.mockup_agent || data.mockup_manager) {
              await autoInjectWazuhConfigs(data);
            }

            await $`SYSTEMD_IGNORE_CHROOT=1 systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart`.quiet().catch(() => { });
            console.log("[BOOT] ✅ Wazuh configs synced successfully!");
          }
        }
      }
    }
  } catch (err) { }
}

async function autoInjectWazuhConfigs(data: any) {
  if (!data.mockup_agent && !data.mockup_manager) return;
  const ossecConfPath = '/var/ossec/etc/ossec.conf';
  const agentConfPath = '/var/ossec/etc/shared/default/agent.conf';
  try {
    let managerMockup = data.mockup_manager ? Buffer.from(data.mockup_manager, 'base64').toString('utf-8') : "";
    let agentMockup = data.mockup_agent ? Buffer.from(data.mockup_agent, 'base64').toString('utf-8') : "";

    if (managerMockup) {
      console.log("⚙️ Overwriting ossec.conf with central SOC mockup...");
      await Bun.write(ossecConfPath, managerMockup);
      await applyPerm(ossecConfPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "ossec.conf (manager)");
    }

    if (agentMockup) {
      await Bun.write(agentConfPath, agentMockup);
      await applyPerm(agentConfPath, `${ROOT_UID}:${WAZUH_GID}`, "750", "agent.conf");
    }
  } catch (err) { }
}

async function fetchPoliciesV2() {
  const API_BASE_V2 = process.env.API_URL_V2 || "https://rh4cloudcenter.moph.go.th/api/v2";
  try {
    console.log(`[BOOT] 📥 Checking for OpenXDR Policy updates...`);
    const response = await fetch(`${API_BASE_V2}/policies/${HOSPITAL_CODE}`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${API_KEY}` }
    });

    if (response.ok) {
      const data = await response.json();
      if (data.success && data.policy) {
        const filepath = '/var/ossec/etc/runtime_policy.json';
        await Bun.write(filepath, JSON.stringify(data.policy, null, 2));
        await applyPerm(filepath, `${WAZUH_UID}:${WAZUH_GID}`, "660", "runtime_policy.json");
        console.log(`[BOOT] ✅ OpenXDR Phase 1: Fetched and saved runtime_policy.json (v${data.policy.version})`);
      }
    }
  } catch (err) {
    console.error("[BOOT] ❌ API v2 Policy Fetch Error:", err);
  }
}

async function main() {
  console.log(`[BOOT] 🚀 Updater service started. Polling every 1 minute.`);
  await detectWazuhIds();

  while (true) {
    if (IS_LINUX && (!WAZUH_UID || !WAZUH_GID)) {
      await detectWazuhIds();
    }

    await checkAndApplyUpdate();
    await fetchPoliciesV2();
    await checkCustomSocUpdate();
    await fetchYaraRules();
    await checkMispUpdates();
    await fetchSocConfigs();
    await syncRulePolicy();

    await sleep(60 * 1000);
  }
}

main().catch((err) => {
  console.error(`[BOOT] 💥 Critical Updater Error:`, err);
  process.exit(1);
});

async function syncRulePolicy() {
  try {
    console.log(`[BOOT] 📥 Querying SOC for latest policy queues...`);
    const versionFile = `${dataDir}/soc_rules_version.txt`;
    let currentTopLine = '';
    if (existsSync(versionFile)) {
      const content = await Bun.file(versionFile).text();
      currentTopLine = content.split('\n')[0]?.trim() || '';
    }

    const res = await fetch(`${CENTRAL_API}/api/v1/rules/queues?hospital_code=${HOSPITAL_CODE}`);
    if (!res.ok) return;
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
      console.log(`[BOOT] 🔍 Checking updates... Found target patch: ${targetHash}`);
      console.log(`[BOOT] 📥 Downloading configuration payload for patch: ${targetHash}...`);

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
          }
        }

        await autoInjectWazuhConfigs({
          mockup_manager: manager_xml ? Buffer.from(manager_xml).toString('base64') : null,
          mockup_agent: agent_xml ? Buffer.from(agent_xml).toString('base64') : null
        });

        await Bun.write(versionFile, `${targetHash} used\n`);
        console.log(`[BOOT] ✅ Rules applied successfully for ${targetHash}`);

        await $`SYSTEMD_IGNORE_CHROOT=1 systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart`.quiet().catch(() => { });
      }
    }

    if (isQueue) {
      await fetch(`${CENTRAL_API}/api/v1/rules/queues?hospital_code=${HOSPITAL_CODE}`, {
        method: "DELETE"
      });
    }

  } catch (err: any) {
    console.error(`[BOOT] ❌ [SYNC ERROR]: ${err.message}`);
  }
}