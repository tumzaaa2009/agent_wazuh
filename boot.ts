import { spawn, exec } from "child_process";
import { existsSync } from "fs";
import { readFile, writeFile, appendFile } from "fs/promises";
import * as path from "path";
import { $ } from "bun";

const WS_URL = process.env.WS_URL || "wss://rh4cloudcenter.moph.go.th/ws/active-response";
const CENTRAL_API = WS_URL.replace("wss://", "https://").replace("ws://", "http://").replace("/ws/active-response", "");
const BASE_API_URL = CENTRAL_API;
const API_BASE_V2 = process.env.API_URL_V2 || "https://rh4cloudcenter.moph.go.th/api/v2";
const YARA_API_URL = process.env.YARA_API_URL || "https://rh4cloudcenter.moph.go.th/api/v1/yara-rules";
const SOC_CONFIG_URL = process.env.SOC_CONFIG_URL || "https://rh4cloudcenter.moph.go.th/api/v1/wazuh-configs";

const HOSPITAL_CODE = process.env.HOSPITAL_CODE || "141";
const API_KEY = process.env.API_KEY || "";

const currentDir = import.meta.dir;
const dataDir = currentDir === '/app' ? currentDir : path.join(currentDir, "..");
const versionFile = path.join(dataDir, 'agent_version.txt');
const scriptFile = path.join(currentDir, 'index.ts');

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

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
            await Bun.write(wazuhIntegrationPath, scriptText);
            await $`chmod 750 ${wazuhIntegrationPath}`.quiet().catch(() => { });
            await $`chown root:125 ${wazuhIntegrationPath}`.quiet().catch(() => { });
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
                    await Bun.write(scriptFileSOC, scriptText);
                    await Bun.write(versionFileSOC, data.version + " used\n");
                    await $`chmod 750 ${scriptFileSOC}`.quiet().catch(() => { });
                    await $`chown root:125 ${scriptFileSOC}`.quiet().catch(() => { });
                    await Bun.write(wazuhIntegrationPath, scriptText);
                    await $`chmod 750 ${wazuhIntegrationPath}`.quiet().catch(() => { });
                    await $`chown root:125 ${wazuhIntegrationPath}`.quiet().catch(() => { });
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
                        await $`chown 115:125 ${RULES_PATH} && chmod 660 ${RULES_PATH}`.quiet().catch(() => { });
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
                        await Bun.write(`/var/ossec/etc/lists/${file}`, await r.text());
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
                                await $`chown 115:125 ${filepath} && chmod 660 ${filepath}`.quiet().catch(() => { });
                            }
                        }
                        if (data.decoders) {
                            for (const decoder of data.decoders) {
                                const filepath = `/var/ossec/etc/decoders/${decoder.filename}`;
                                await Bun.write(filepath, Buffer.from(decoder.content, 'base64').toString('utf-8'));
                                await $`chown 115:125 ${filepath} && chmod 660 ${filepath}`.quiet().catch(() => { });
                            }
                        }
                        const remoteVersion = String(vData.version).split('\n')[0]?.trim() || "";
                        await Bun.write(versionFile, remoteVersion + " used\n");

                        // Re-inject wazuh configs
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

        // 1. Update Manager Config (ossec.conf) — Full Overwrite
        if (managerMockup) {
            console.log("⚙️ Overwriting ossec.conf with central SOC mockup...");
            await Bun.write(ossecConfPath, managerMockup);
            await $`chown root:wazuh ${ossecConfPath} && chmod 660 ${ossecConfPath}`.quiet().catch(() => { });
        }

        if (agentMockup) {
            await Bun.write(agentConfPath, agentMockup);
            await $`chown 115:125 ${agentConfPath} && chmod 660 ${agentConfPath}`.quiet().catch(() => { });
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
                await Bun.write('/var/ossec/etc/runtime_policy.json', JSON.stringify(data.policy, null, 2));
                console.log(`[BOOT] ✅ OpenXDR Phase 1: Fetched and saved runtime_policy.json (v${data.policy.version})`);
            }
        }
    } catch (err) {
        console.error("[BOOT] ❌ API v2 Policy Fetch Error:", err);
    }
}

async function main() {
    console.log(`[BOOT] 🚀 Updater service started. Polling every 1 minute.`);

    while (true) {
        // 0. Check for Edge Connector script updates
        await checkAndApplyUpdate();

        // 1. Check for OpenXDR Policy updates
        await fetchPoliciesV2();

        // 2. Check for Custom SOC updates
        await checkCustomSocUpdate();

        // 3. Check for YARA rule updates
        await fetchYaraRules();

        // 4. Check for MISP updates
        await checkMispUpdates();

        // 5. Check for SOC Config updates
        await fetchSocConfigs();

        // 6. Check for queued rules/decoders patches
        await syncRulePolicy();

        // Wait 1 minute before checking again
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
            // Fallback: check status API in case the local version is missing or truncated
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

                await Bun.write('/var/ossec/etc/shared/default/agent_mockup.xml', agent_xml);
                await Bun.write('/var/ossec/etc/manager_mockup.xml', manager_xml);

                if (wazuh_files && Array.isArray(wazuh_files)) {
                    for (const file of wazuh_files) {
                        if (file.type === 'rule') {
                            const p = `/var/ossec/etc/rules/${file.filename}`;
                            await Bun.write(p, file.content);
                            await $`chown 115:125 ${p} && chmod 660 ${p}`.quiet().catch(() => { });
                        } else if (file.type === 'decoder') {
                            const p = `/var/ossec/etc/decoders/${file.filename}`;
                            await Bun.write(p, file.content);
                            await $`chown 115:125 ${p} && chmod 660 ${p}`.quiet().catch(() => { });
                        }
                    }
                }

                // Inject the newly downloaded configs into ossec.conf and agent.conf
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

