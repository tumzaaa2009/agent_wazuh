import { $ } from "bun";
const ossecConfPath = '/var/ossec/etc/ossec.conf';
try {
  let confContent = await Bun.file(ossecConfPath).text();
  console.log("Read confContent, length: " + confContent.length);
} catch (e: any) {
  console.log("Error reading: " + e.message);
}
