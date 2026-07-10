import { Elysia } from 'elysia';
import { cron } from '@elysiajs/cron';
import { Client } from '@opensearch-project/opensearch';
import { prisma } from '../lib/prisma';
import { osClient } from '../lib/opensearch';
import { Logger } from '../utils/logger';
import { getConnectedHospitals } from '../websocket/hospitalSocket';

const N8N_WEBHOOK = process.env.N8N_ALERTS_WEBHOOK || 'https://rh4cloudcenter.moph.go.th/n8n/webhook/wazuh-alerts';
const TRIGGER_GROUPS = ['authentication_failed', 'invalid_login', 'brute_force', 'attacks', 'recon', 'modsecurity', 'suricata', 'suricata_event', 'owasp', 'web'];

async function runPullWorker() {
  Logger.info('CronWorker', 'job_started', 'Running scheduled pull worker...');
  const hospitals = await prisma.hospital.findMany({
    where: { indexer_url: { not: null }, status: 'active' },
  });

  for (const hospital of hospitals) {
    if (!hospital.indexer_url) continue;

    try {
      Logger.info('CronWorker', 'fetch_started', `Pulling alerts for hospital: ${hospital.hospital_name}`, { hospital_code: hospital.hospital_code });

      const remoteOsClient = new Client({
        node: hospital.indexer_url,
        auth: hospital.indexer_user && hospital.indexer_password
          ? { username: hospital.indexer_user, password: hospital.indexer_password }
          : undefined,
        ssl: { rejectUnauthorized: false },
        requestTimeout: 60000,
      });

      const lastPulled = hospital.last_pulled_at
        ? hospital.last_pulled_at.toISOString()
        : new Date(Date.now() - 3600000).toISOString();
      const today = new Date().toISOString().split('T')[0]!.replace(/-/g, '.');
      const searchIndex = `wazuh-alerts-4.x-${today}`;

      const response = await remoteOsClient.search({
        index: searchIndex,
        size: 1000,
        body: { query: { range: { timestamp: { gt: lastPulled } } }, sort: [{ timestamp: { order: 'asc' } }] },
      });

      const hits = (response.body.hits.hits as any[]) || [];
      let latestTimestamp = hospital.last_pulled_at;

      if (hits.length > 0) {
        // Open single TCP socket for the batch
        const net = require('net');
        const client = new net.Socket();
        
        await new Promise((resolve, reject) => {
          client.connect(9999, '10.0.192.15', resolve);
          client.on('error', reject);
        }).catch(err => {
          Logger.error('CronWorker', 'tcp_connect_error', `Failed to connect to 10.0.192.15:9999`);
        });

        for (const hit of hits) {
          const alert = hit._source;
          if (alert.timestamp) latestTimestamp = new Date(alert.timestamp);

          const enrichedAlert = {
            ...alert,
            hospital_code: hospital.hospital_code,
            hospital_name: hospital.hospital_name,
            province: hospital.province,
            zone: hospital.zone,
            received_at: new Date().toISOString(),
          };

          // Send to Central SOC Wazuh Master via TCP
          if (!client.destroyed) {
            client.write(JSON.stringify(enrichedAlert) + '\n');
          }

          // Auto-upsert Agent
          if (alert.agent?.id && alert.agent?.name) {
            try {
              await prisma.agent.upsert({
                where: {
                  hospital_id_agent_id: { hospital_id: hospital.id, agent_id: alert.agent.id }
                },
                update: { agent_name: alert.agent.name, last_seen_at: new Date() },
                create: { hospital_id: hospital.id, agent_id: alert.agent.id, agent_name: alert.agent.name, last_seen_at: new Date() }
              });
            } catch (err: any) {
              Logger.error('CronWorker', 'agent_upsert_error', `Failed to upsert agent: ${err.message}`);
            }
          }

          const rule = alert.rule || {};
          const level = parseInt(rule.level || '0');
          const groups: string[] = rule.groups || [];
          const matchesGroup = groups.some((g: string) => TRIGGER_GROUPS.includes(g));

          if ((level >= 5 || matchesGroup) && rule.id !== 'N/A' && rule.id !== '81644') {
            const payload = {
              severity: level >= 5 && level <= 7 ? 2 : 3,
              pretext: 'WAZUH Alert',
              title: rule.description || 'N/A',
              text: alert.full_log || '',
              rule_id: rule.id,
              timestamp: alert.timestamp || 'N/A',
              id: alert.id || 'N/A',
              all_fields: enrichedAlert,
            };
            try {
              await fetch(N8N_WEBHOOK, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
              });
              Logger.info('CronWorker', 'n8n_triggered', `Forwarded alert ${rule.id} to n8n`, { hospital_code: hospital.hospital_code });
            } catch (e: any) {
              Logger.error('CronWorker', 'n8n_error', `Failed to send alert to n8n`, { error: e.message });
            }
          }
        }
        
        client.destroy();
      }

      if (latestTimestamp && latestTimestamp > (hospital.last_pulled_at || new Date(0))) {
        await prisma.hospital.update({ where: { id: hospital.id }, data: { last_pulled_at: latestTimestamp } });
      }

      Logger.info('CronWorker', 'fetch_success', `Pulled ${hits.length} alerts for ${hospital.hospital_name}`, { hospital_code: hospital.hospital_code, hits: hits.length });
    } catch (err: any) {
      Logger.error('CronWorker', 'fetch_error', `Failed to pull alerts for ${hospital.hospital_name}`, { hospital_code: hospital.hospital_code, error: err.message });
    }
  }
}

export const cronWorker = new Elysia()
  .use(
    cron({
      name: 'pull-worker',
      pattern: '*/5 * * * *',
      run: runPullWorker,
    })
  )
  .use(
    cron({
      name: 'hospital-status-worker',
      pattern: '*/15 * * * *',
      run: async () => {
        Logger.info('CronWorker', 'status_job_started', 'Running scheduled hospital status worker...');
        try {
          const allHospitals = await prisma.hospital.findMany({
            select: { hospital_code: true, hospital_name: true }
          });
          const connectedCodes = getConnectedHospitals();
          
          const report = allHospitals.map(h => ({
            ...h,
            is_online: connectedCodes.includes(h.hospital_code)
          }));
          
          const N8N_STATUS_WEBHOOK = process.env.N8N_STATUS_WEBHOOK || 'https://rh4cloudcenter.moph.go.th/n8n/webhook-test/hospital-status';
          await fetch(N8N_STATUS_WEBHOOK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timestamp: new Date().toISOString(), hospitals: report })
          });
          Logger.info('CronWorker', 'status_job_success', `Reported status for ${report.length} hospitals`);
        } catch (e: any) {
          Logger.error('CronWorker', 'status_job_error', `Failed to run hospital status worker`, { error: e.message });
        }
      }
    })
  );
