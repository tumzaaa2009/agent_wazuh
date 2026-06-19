import { $ } from "bun";
const output = await $`/var/ossec/bin/agent_control -L`.text();
console.log("OUTPUT:", JSON.stringify(output));
const match = output.match(/Response name: (firewall-drop\d*)/);
console.log("MATCH:", match ? JSON.stringify(match[1]) : null);
