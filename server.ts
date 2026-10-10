import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createClient } from '@libsql/client';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize LibSQL Client
// Uses TURSO_DATABASE_URL if configured, otherwise local file database for zero-config persistence
const dbUrl = process.env.TURSO_DATABASE_URL || 'file:local.db';
const dbAuthToken = process.env.TURSO_AUTH_TOKEN || undefined;

export const db = createClient({
  url: dbUrl,
  authToken: dbAuthToken,
});

// Initialize Schema and Seeds
export async function initDatabase() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS cloud_assets (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      region TEXT NOT NULL,
      provider TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      status TEXT NOT NULL,
      last_scanned TEXT NOT NULL
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS security_findings (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      category TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      cloud_provider TEXT NOT NULL,
      status TEXT NOT NULL,
      remediation TEXT NOT NULL,
      detected_at TEXT NOT NULL
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS threat_events (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      target_service TEXT NOT NULL,
      severity TEXT NOT NULL,
      action_taken TEXT NOT NULL,
      timestamp TEXT NOT NULL
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS compliance_frameworks (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      score INTEGER NOT NULL,
      total_controls INTEGER NOT NULL,
      passed_controls INTEGER NOT NULL,
      status TEXT NOT NULL
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      status TEXT NOT NULL
    );
  `);

  // Check if seeding is needed
  const existingAssets = await db.execute('SELECT COUNT(*) as count FROM cloud_assets');
  const count = Number(existingAssets.rows[0]?.count || 0);

  if (count === 0) {
    // Seed initial assets
    const assets = [
      { id: 'ast-101', name: 'prod-vpc-gateway', type: 'VPC Gateway', region: 'us-east-1', provider: 'AWS', risk_score: 28, status: 'Active', last_scanned: new Date().toISOString() },
      { id: 'ast-102', name: 'k8s-cluster-auth', type: 'EKS Cluster', region: 'us-east-2', provider: 'AWS', risk_score: 85, status: 'At Risk', last_scanned: new Date().toISOString() },
      { id: 'ast-103', name: 'customer-data-s3', type: 'Storage Bucket', region: 'us-west-2', provider: 'AWS', risk_score: 92, status: 'Critical', last_scanned: new Date().toISOString() },
      { id: 'ast-104', name: 'billing-db-instance', type: 'Cloud SQL / Aurora', region: 'europe-west1', provider: 'GCP', risk_score: 42, status: 'Active', last_scanned: new Date().toISOString() },
      { id: 'ast-105', name: 'oauth-identity-vault', type: 'Key Vault', region: 'eastus', provider: 'Azure', risk_score: 15, status: 'Compliant', last_scanned: new Date().toISOString() },
      { id: 'ast-106', name: 'api-gateway-edge', type: 'CloudFront / CDN', region: 'global', provider: 'AWS', risk_score: 35, status: 'Active', last_scanned: new Date().toISOString() }
    ];

    for (const a of assets) {
      await db.execute({
        sql: `INSERT INTO cloud_assets (id, name, type, region, provider, risk_score, status, last_scanned) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [a.id, a.name, a.type, a.region, a.provider, a.risk_score, a.status, a.last_scanned]
      });
    }

    // Seed security findings
    const findings = [
      {
        id: 'fnd-201',
        title: 'S3 Bucket Public Read/Write ACL Detected',
        severity: 'CRITICAL',
        category: 'Storage',
        resource_id: 'customer-data-s3',
        cloud_provider: 'AWS',
        status: 'OPEN',
        remediation: 'Enable S3 Block Public Access and attach restrictive bucket policy',
        detected_at: new Date(Date.now() - 3600000 * 2).toISOString()
      },
      {
        id: 'fnd-202',
        title: 'Unrestricted Security Group Inbound (0.0.0.0/0 on port 22)',
        severity: 'HIGH',
        category: 'Network',
        resource_id: 'k8s-cluster-auth',
        cloud_provider: 'AWS',
        status: 'OPEN',
        remediation: 'Restrict SSH ingress to bastion CIDR or VPN endpoints',
        detected_at: new Date(Date.now() - 3600000 * 5).toISOString()
      },
      {
        id: 'fnd-203',
        title: 'IAM Root User Access Key Active Without MFA',
        severity: 'CRITICAL',
        category: 'IAM',
        resource_id: 'root-account-credentials',
        cloud_provider: 'AWS',
        status: 'IN_PROGRESS',
        remediation: 'Deactivate root access keys and enforce multi-factor authentication (MFA)',
        detected_at: new Date(Date.now() - 3600000 * 8).toISOString()
      },
      {
        id: 'fnd-204',
        title: 'Unencrypted Database Storage Volume at Rest',
        severity: 'MEDIUM',
        category: 'Encryption',
        resource_id: 'billing-db-instance',
        cloud_provider: 'GCP',
        status: 'OPEN',
        remediation: 'Enable KMS customer-managed key encryption for disk snapshot',
        detected_at: new Date(Date.now() - 3600000 * 18).toISOString()
      },
      {
        id: 'fnd-205',
        title: 'CloudTrail Logging Disabled in Secondary Region',
        severity: 'LOW',
        category: 'Audit',
        resource_id: 'prod-vpc-gateway',
        cloud_provider: 'AWS',
        status: 'RESOLVED',
        remediation: 'Enable multi-region trail logging in organization account',
        detected_at: new Date(Date.now() - 3600000 * 36).toISOString()
      }
    ];

    for (const f of findings) {
      await db.execute({
        sql: `INSERT INTO security_findings (id, title, severity, category, resource_id, cloud_provider, status, remediation, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [f.id, f.title, f.severity, f.category, f.resource_id, f.cloud_provider, f.status, f.remediation, f.detected_at]
      });
    }

    // Seed threat events
    const threats = [
      { id: 'thr-301', event_type: 'Brute Force SSH Attempt', source_ip: '194.26.29.112', target_service: 'k8s-cluster-auth', severity: 'HIGH', action_taken: 'IP Blocked by WAF', timestamp: new Date(Date.now() - 60000 * 14).toISOString() },
      { id: 'thr-302', event_type: 'Anomalous Token Generation', source_ip: '45.154.255.89', target_service: 'oauth-identity-vault', severity: 'CRITICAL', action_taken: 'Session Revoked', timestamp: new Date(Date.now() - 60000 * 32).toISOString() },
      { id: 'thr-303', event_type: 'Port Scan Sweep', source_ip: '185.220.101.5', target_service: 'prod-vpc-gateway', severity: 'MEDIUM', action_taken: 'Rate Limited', timestamp: new Date(Date.now() - 60000 * 75).toISOString() },
      { id: 'thr-304', event_type: 'Exfiltration Burst Attempt', source_ip: '91.240.118.23', target_service: 'customer-data-s3', severity: 'CRITICAL', action_taken: 'Egress Throttled', timestamp: new Date(Date.now() - 60000 * 120).toISOString() }
    ];

    for (const t of threats) {
      await db.execute({
        sql: `INSERT INTO threat_events (id, event_type, source_ip, target_service, severity, action_taken, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        args: [t.id, t.event_type, t.source_ip, t.target_service, t.severity, t.action_taken, t.timestamp]
      });
    }

    // Seed compliance frameworks
    const frameworks = [
      { id: 'cis-aws', name: 'CIS AWS Foundations v2.0', score: 82, total_controls: 54, passed_controls: 44, status: 'Needs Review' },
      { id: 'soc-2', name: 'SOC 2 Type II Security', score: 94, total_controls: 40, passed_controls: 38, status: 'Compliant' },
      { id: 'iso-27001', name: 'ISO / IEC 27001:2022', score: 88, total_controls: 93, passed_controls: 82, status: 'In Audit' },
      { id: 'pci-dss', name: 'PCI-DSS v4.0 Cloud', score: 76, total_controls: 64, passed_controls: 49, status: 'Non-Compliant' },
      { id: 'hipaa', name: 'HIPAA Security Safeguards', score: 91, total_controls: 36, passed_controls: 33, status: 'Compliant' }
    ];

    for (const fw of frameworks) {
      await db.execute({
        sql: `INSERT INTO compliance_frameworks (id, name, score, total_controls, passed_controls, status) VALUES (?, ?, ?, ?, ?, ?)`,
        args: [fw.id, fw.name, fw.score, fw.total_controls, fw.passed_controls, fw.status]
      });
    }

    // Seed initial audit log
    await db.execute({
      sql: `INSERT INTO audit_logs (id, actor, action, target, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)`,
      args: ['aud-001', 'system:init', 'BOOTSTRAP_DATABASE', 'CyberSentinel X Schema', new Date().toISOString(), 'SUCCESS']
    });
  }
}

// Helper to log audit events
export async function logAuditEvent(actor: string, action: string, target: string, status: string = 'SUCCESS') {
  try {
    const id = `aud-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    await db.execute({
      sql: `INSERT INTO audit_logs (id, actor, action, target, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)`,
      args: [id, actor, action, target, new Date().toISOString(), status]
    });
  } catch (err) {
    console.error('Audit log error:', err);
  }
}

export async function createServer() {
  const app = express();
  app.use(express.json());

  // Initialize DB tables and seed
  await initDatabase();

  // API Health Endpoint
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      app: 'CyberSentinel X',
      port: Number(process.env.PORT) || 3000,
      timestamp: new Date().toISOString(),
      database: 'connected (libsql)',
      runtime: process.version,
    });
  });

  // API Overview & Metrics
  app.get('/api/overview', async (req: Request, res: Response) => {
    try {
      const assetsCountRes = await db.execute('SELECT COUNT(*) as count FROM cloud_assets');
      const findingsCountRes = await db.execute("SELECT COUNT(*) as count FROM security_findings WHERE status != 'RESOLVED'");
      const criticalCountRes = await db.execute("SELECT COUNT(*) as count FROM security_findings WHERE severity = 'CRITICAL' AND status != 'RESOLVED'");
      const resolvedCountRes = await db.execute("SELECT COUNT(*) as count FROM security_findings WHERE status = 'RESOLVED'");
      const complianceAvgRes = await db.execute('SELECT AVG(score) as avgScore FROM compliance_frameworks');
      const threatsCountRes = await db.execute('SELECT COUNT(*) as count FROM threat_events');

      res.json({
        totalAssets: Number(assetsCountRes.rows[0]?.count || 0),
        activeFindings: Number(findingsCountRes.rows[0]?.count || 0),
        criticalFindings: Number(criticalCountRes.rows[0]?.count || 0),
        resolvedFindings: Number(resolvedCountRes.rows[0]?.count || 0),
        averageCompliance: Math.round(Number(complianceAvgRes.rows[0]?.avgScore || 0)),
        totalThreatsDetected: Number(threatsCountRes.rows[0]?.count || 0)
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API Cloud Assets
  app.get('/api/assets', async (req: Request, res: Response) => {
    try {
      const provider = req.query.provider as string | undefined;
      let query = 'SELECT * FROM cloud_assets';
      const args: any[] = [];

      if (provider && provider !== 'ALL') {
        query += ' WHERE provider = ?';
        args.push(provider);
      }
      query += ' ORDER BY risk_score DESC';

      const result = await db.execute({ sql: query, args });
      res.json(result.rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/assets', async (req: Request, res: Response) => {
    try {
      const { name, type, region, provider, risk_score = 10, status = 'Active' } = req.body;
      if (!name || !type || !region || !provider) {
        return res.status(400).json({ error: 'Missing required fields' });
      }
      const id = `ast-${Date.now().toString(36)}`;
      const last_scanned = new Date().toISOString();

      await db.execute({
        sql: `INSERT INTO cloud_assets (id, name, type, region, provider, risk_score, status, last_scanned) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [id, name, type, region, provider, risk_score, status, last_scanned]
      });

      await logAuditEvent('security_admin', 'ADD_CLOUD_ASSET', `${provider}:${name}`);
      res.status(201).json({ id, name, type, region, provider, risk_score, status, last_scanned });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API Security Findings
  app.get('/api/findings', async (req: Request, res: Response) => {
    try {
      const severity = req.query.severity as string | undefined;
      const status = req.query.status as string | undefined;
      let query = 'SELECT * FROM security_findings WHERE 1=1';
      const args: any[] = [];

      if (severity && severity !== 'ALL') {
        query += ' AND severity = ?';
        args.push(severity);
      }
      if (status && status !== 'ALL') {
        query += ' AND status = ?';
        args.push(status);
      }
      query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, detected_at DESC";

      const result = await db.execute({ sql: query, args });
      res.json(result.rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.patch('/api/findings/:id', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const { status } = req.body;
      if (!status) {
        return res.status(400).json({ error: 'Status is required' });
      }

      await db.execute({
        sql: 'UPDATE security_findings SET status = ? WHERE id = ?',
        args: [status, id]
      });

      await logAuditEvent('security_analyst', 'UPDATE_FINDING_STATUS', `${id} -> ${status}`);
      res.json({ success: true, id, status });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Automated Remediation Endpoint
  app.post('/api/findings/:id/remediate', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const findingRes = await db.execute({
        sql: 'SELECT * FROM security_findings WHERE id = ?',
        args: [id]
      });

      if (findingRes.rows.length === 0) {
        return res.status(404).json({ error: 'Finding not found' });
      }

      const finding = findingRes.rows[0];

      // Mark finding resolved
      await db.execute({
        sql: "UPDATE security_findings SET status = 'RESOLVED' WHERE id = ?",
        args: [id]
      });

      // Lower risk score on associated resource
      if (finding.resource_id) {
        await db.execute({
          sql: "UPDATE cloud_assets SET risk_score = MAX(10, risk_score - 25), status = 'Active' WHERE id = ? OR name = ?",
          args: [finding.resource_id, finding.resource_id]
        });
      }

      await logAuditEvent('sentinel_auto_remediator', 'EXECUTE_AUTO_REMEDIATION', `${id} (${finding.title})`);
      res.json({
        success: true,
        remediatedId: id,
        message: `Successfully remediated: ${finding.remediation}`,
        status: 'RESOLVED'
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Trigger CSPM Scan Endpoint
  app.post('/api/scan', async (req: Request, res: Response) => {
    try {
      const now = new Date().toISOString();
      await db.execute({
        sql: 'UPDATE cloud_assets SET last_scanned = ?',
        args: [now]
      });

      // Update compliance frameworks slightly
      await db.execute(`
        UPDATE compliance_frameworks 
        SET score = MIN(100, score + 1)
        WHERE score < 95
      `);

      await logAuditEvent('security_scanner', 'RUN_CSPM_SCAN', 'ALL_CLOUD_RESOURCES');

      res.json({
        success: true,
        timestamp: now,
        scannedAssetsCount: 6,
        policiesEvaluated: 142,
        newViolationsDetected: 0,
        status: 'Scan Completed Successfully'
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API Real-Time Threat Events
  app.get('/api/threats', async (req: Request, res: Response) => {
    try {
      const result = await db.execute('SELECT * FROM threat_events ORDER BY timestamp DESC LIMIT 20');
      res.json(result.rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/threats', async (req: Request, res: Response) => {
    try {
      const { event_type, source_ip, target_service, severity = 'HIGH', action_taken = 'Blocked' } = req.body;
      const id = `thr-${Date.now().toString(36)}`;
      const timestamp = new Date().toISOString();

      await db.execute({
        sql: `INSERT INTO threat_events (id, event_type, source_ip, target_service, severity, action_taken, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        args: [id, event_type, source_ip, target_service, severity, action_taken, timestamp]
      });

      await logAuditEvent('threat_engine', 'INGEST_THREAT_EVENT', `${event_type} from ${source_ip}`);
      res.status(201).json({ id, event_type, source_ip, target_service, severity, action_taken, timestamp });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API Compliance Frameworks
  app.get('/api/compliance', async (req: Request, res: Response) => {
    try {
      const result = await db.execute('SELECT * FROM compliance_frameworks ORDER BY score ASC');
      res.json(result.rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // API Audit Logs
  app.get('/api/audit-logs', async (req: Request, res: Response) => {
    try {
      const result = await db.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 25');
      res.json(result.rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Static files or Vite dev middleware
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    // Dynamic import to prevent loading Vite in production bundle
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  return app;
}

// Start Server listening on 0.0.0.0 and process.env.PORT
async function start() {
  const app = await createServer();
  const PORT = Number(process.env.PORT) || 3000;
  const HOST = '0.0.0.0';

  app.listen(PORT, HOST, () => {
    console.log(`[CyberSentinel X] Web Service successfully running on http://${HOST}:${PORT}`);
    console.log(`[CyberSentinel X] Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

// Only invoke start if executed directly
if (process.env.NODE_ENV !== 'test') {
  start().catch((err) => {
    console.error('Fatal error starting CyberSentinel X server:', err);
    process.exit(1);
  });
}
