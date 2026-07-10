import * as net from 'net';
import * as fs from 'fs/promises';
import { prisma } from '../lib/prisma';
import { Logger } from '../utils/logger';

const N8N_WEBHOOK = process.env.N8N_ALERTS_WEBHOOK || 'https://rh4cloudcenter.moph.go.th/n8n/webhook/wazuh-alerts';
const TRIGGER_GROUPS = ['authentication_failed', 'invalid_login', 'brute_force', 'attacks', 'recon', 'modsecurity', 'suricata', 'suricata_event', 'owasp', 'web'];

export async function ingestAlert(alertRaw: any, hospital: any) {
  const enrichedAlert = {
    ...alertRaw,
    hospital_code: hospital.hospital_code,
    hospital_name: hospital.hospital_name,
    province: hospital.province,
    zone: hospital.zone,
    received_at: new Date().toISOString(),
  };

  try {
    // Send directly to Central SOC Wazuh Master (10.0.192.15) via TCP
    const client = new net.Socket();
    client.connect(9999, '10.0.192.15', () => {
      client.write(JSON.stringify(enrichedAlert) + '\n');
      client.destroy();
    });

    client.on('error', (err: any) => {
      Logger.error('AlertService', 'tcp_send_error', `Failed to send alert to 10.0.192.15: ${err.message}`, { error: err.message });
    });

    Logger.info('AlertService', 'alert_ingested', `Sent alert ${alertRaw.rule?.id} from ${hospital.hospital_name} to 10.0.192.15`, {
      rule_id: alertRaw.rule?.id,
      agent_id: alertRaw.agent?.id,
    });
  } catch (err: any) {
    Logger.error('AlertService', 'tcp_write_error', `Failed to write alert: ${err.message}`, { error: err.message });
  }

  // Auto-upsert Agent
  if (alertRaw.agent?.id && alertRaw.agent?.name) {
    try {
      await prisma.agent.upsert({
        where: { hospital_id_agent_id: { hospital_id: hospital.id, agent_id: alertRaw.agent.id } },
        update: { agent_name: alertRaw.agent.name, last_seen_at: new Date() },
        create: { hospital_id: hospital.id, agent_id: alertRaw.agent.id, agent_name: alertRaw.agent.name, last_seen_at: new Date() },
      });
    } catch (err) {
      console.error('Agent Upsert Error:', err);
    }
  }

  // Forward to n8n SOAR (fire-and-forget)
  const rule = alertRaw.rule || {};
  const level = parseInt(rule.level || '0');
  const groups: string[] = rule.groups || [];
  const matchesGroup = groups.some((g: string) => TRIGGER_GROUPS.includes(g));

  if ((level >= 5 || matchesGroup) && rule.id !== 'N/A' && rule.id !== '81644') {
    const payload = {
      severity: level >= 5 && level <= 7 ? 2 : 3,
      pretext: 'WAZUH Alert',
      title: rule.description || 'N/A',
      text: alertRaw.full_log || '',
      rule_id: rule.id,
      timestamp: alertRaw.timestamp || 'N/A',
      id: alertRaw.id || 'N/A',
      all_fields: enrichedAlert,
    };
    fetch(N8N_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then(() => Logger.info('AlertService', 'n8n_triggered', `Forwarded PUSH alert ${rule.id} to n8n`, { hospital_code: hospital.hospital_code }))
      .catch((e: any) => Logger.error('AlertService', 'n8n_error', `Failed to send PUSH alert to n8n`, { error: e.message }));
  }

  return enrichedAlert;
}

export async function storeAlertLog(data: any) {
  // Skip Fortigate block policy (spam)
  if (data.rule_id == 81644 || data.rule_id === '81644') return null;

  let method = data.method || null;
  let uri = data.uri || null;
  let host = data.host || null;

  if (data.full_log) {
    const m = data.full_log.match(/"(GET|POST|PUT|DELETE|HEAD|OPTIONS) (.+?) HTTP\/\d\.\d" \d+ \d+ "[^"]*" ".*?"/);
    if (m) { method = method ?? m[1]; uri = uri ?? m[2]; }
    const em = data.full_log.match(/request: "(GET|POST|PUT|DELETE|HEAD|OPTIONS) (.+?) HTTP\/\d\.\d"/);
    if (em) { method = method ?? em[1]; uri = uri ?? em[2]; }
    const hm = data.full_log.match(/host: "([^"]+)"/);
    if (hm) host = host ?? hm[1];
  }

  return prisma.alertLog.create({
    data: {
      hospital_code: data.hospital_code || null,
      agent_id: data.agent_id || null,
      rule_id: data.rule_id || null,
      rule_level: data.rule_level ? parseInt(data.rule_level) : null,
      description: data.description || null,
      srcip: data.srcip || null,
      method, uri, host,
      category: data.category || null,
      full_log: data.full_log || null,
      location: data.location || null,
      timestamp: data.timestamp || null,
    },
  });
}

export async function storeAccessLog(data: any) {
  return prisma.accessLogThreat.create({
    data: {
      hospital_code: data.hospital_code || null,
      agent_id: data.agent_id || null,
      rule_id: data.rule_id || null,
      rule_level: data.rule_level ? parseInt(data.rule_level.toString()) : null,
      description: data.description || null,
      srcip: data.srcip || null,
      hostname: data.hostname || null,
      request: data.request || null,
      misp_matched: data.misp_matched !== undefined ? data.misp_matched : true,
      threat_type: data.threat_type || null,
      full_log: data.full_log || null,
      location: data.location || null,
      timestamp: data.timestamp || null,
    },
  });
}

export async function storeIdsLog(data: any) {
  return prisma.idsLog.create({
    data: {
      hospital_code: data.hospital_code || null,
      agent_id: data.agent_id || null,
      rule_id: data.rule_id || null,
      rule_level: data.rule_level ? parseInt(data.rule_level.toString()) : null,
      description: data.description || null,
      srcip: data.srcip || null,
      category: data.category || null,
      full_log: data.full_log || null,
      location: data.location || null,
      timestamp: data.timestamp || null,
    },
  });
}

export async function storeSyslog(hospital: any, logLine: string) {
  const logDir = `/var/center-syslog/${hospital.hospital_code}`;
  await fs.mkdir(logDir, { recursive: true });
  await fs.appendFile(`${logDir}/syslog.log`, logLine + '\n');

  // Forward to Wazuh Master via TCP (fire-and-forget)
  const net = await import('net');
  const client = new net.Socket();
  client.connect(15140, '10.0.192.14', () => {
    client.write(logLine + '\n');
    client.destroy();
  });
  client.on('error', (err: any) => {
    Logger.error('AlertService', 'syslog_forward_error', 'Failed to forward syslog to Wazuh Master', { error: err.message });
  });
}

export async function storeAntivirusLog(data: any) {
  return prisma.antivirusLog.create({
    data: {
      hospital_code: data.hospital_code || null,
      agent_id: data.agent_id || null,
      rule_id: data.rule_id || null,
      rule_level: data.rule_level ? parseInt(data.rule_level.toString()) : null,
      description: data.description || null,
      vendor: data.vendor || null,
      file_hash: data.file_hash || null,
      full_log: data.full_log || null,
      location: data.location || null,
      timestamp: data.timestamp || null,
    },
  });
}
