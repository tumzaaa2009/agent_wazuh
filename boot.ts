import { spawn } from "child_process";
import { existsSync } from "fs";
import { readFile, writeFile } from "fs/promises";
import * as path from "path";

const WS_URL = process.env.WS_URL || "wss://rh4cloudcenter.moph.go.th/ws/active-response";
const CENTRAL_API = WS_URL.replace("wss://", "https://").replace("ws://", "http://").replace("/ws/active-response", "");

const currentDir = import.meta.dir;
const versionFile = path.join(currentDir, 'agent_version.txt');
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
                localVersion = (await readFile(versionFile, "utf-8")).trim();
            }

            if (data.success && data.version && data.version !== localVersion) {
                console.log(`[BOOT] 🚀 New version detected! Remote: ${data.version}, Local: ${localVersion}`);
                console.log(`[BOOT] 📥 Downloading new index.ts...`);
                const scriptRes = await fetch(`${CENTRAL_API}/api/v1/edge-connector/script`);
                if (scriptRes.ok) {
                    const scriptText = await scriptRes.text();
                    await writeFile(scriptFile, scriptText);
                    await writeFile(versionFile, data.version);
                    console.log(`[BOOT] ✅ Successfully updated local script to version ${data.version}.`);
                    return true; // Update applied
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

async function main() {
    console.log(`[UPDATER] 🚀 Updater service started. Polling every 1 minute.`);

    while (true) {
        // Check for updates
        const updated = await checkAndApplyUpdate();
        if (updated) {
            console.log(`[UPDATER] ✅ Update applied. The edge-connector container (running bun --watch) will automatically restart index.ts shortly.`);
        }

        // Wait 1 minute before checking again
        await sleep(60 * 1000);
    }
}

main().catch((err) => {
    console.error(`[UPDATER] 💥 Critical Updater Error:`, err);
    process.exit(1);
});
