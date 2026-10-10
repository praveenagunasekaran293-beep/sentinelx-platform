import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Server,
  Cloud,
  Terminal,
  Activity,
  CheckCircle2,
  AlertTriangle,
  RotateCw,
  Plus,
  Lock,
  Search,
  ExternalLink,
  Flame,
  Check,
  X,
  Play
} from 'lucide-react';

interface OverviewMetrics {
  totalAssets: number;
  activeFindings: number;
  criticalFindings: number;
  resolvedFindings: number;
  averageCompliance: number;
  totalThreatsDetected: number;
}

interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  resource_id: string;
  cloud_provider: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'MUTED';
  remediation: string;
  detected_at: string;
}

interface Asset {
  id: string;
  name: string;
  type: string;
  region: string;
  provider: string;
  risk_score: number;
  status: string;
  last_scanned: string;
}

interface ThreatEvent {
  id: string;
  event_type: string;
  source_ip: string;
  target_service: string;
  severity: string;
  action_taken: string;
  timestamp: string;
}

interface ComplianceFramework {
  id: string;
  name: string;
  score: number;
  total_controls: number;
  passed_controls: number;
  status: string;
}

interface AuditLog {
  id: string;
  actor: string;
  action: string;
  target: string;
  timestamp: string;
  status: string;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'assets' | 'threats' | 'compliance' | 'audit'>('overview');
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [compliance, setCompliance] = useState<ComplianceFramework[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [healthInfo, setHealthInfo] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [providerFilter, setProviderFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Asset creation modal
  const [showAddAsset, setShowAddAsset] = useState<boolean>(false);
  const [newAsset, setNewAsset] = useState({
    name: '',
    type: 'Storage Bucket',
    region: 'us-east-1',
    provider: 'AWS',
    risk_score: 25,
  });

  const fetchData = async () => {
    try {
      setLoading(true);
      const [ovRes, findRes, astRes, thrRes, compRes, audRes, hlthRes] = await Promise.all([
        fetch('/api/overview').then(r => r.json()),
        fetch('/api/findings').then(r => r.json()),
        fetch('/api/assets').then(r => r.json()),
        fetch('/api/threats').then(r => r.json()),
        fetch('/api/compliance').then(r => r.json()),
        fetch('/api/audit-logs').then(r => r.json()),
        fetch('/api/health').then(r => r.json())
      ]);

      setMetrics(ovRes);
      setFindings(findRes);
      setAssets(astRes);
      setThreats(thrRes);
      setCompliance(compRes);
      setAuditLogs(audRes);
      setHealthInfo(hlthRes);
    } catch (err) {
      console.error('Error fetching CyberSentinel data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRemediate = async (findingId: string) => {
    try {
      const res = await fetch(`/api/findings/${findingId}/remediate`, {
        method: 'POST',
      });
      if (res.ok) {
        setScanMessage(`Finding ${findingId} remediated successfully.`);
        setTimeout(() => setScanMessage(null), 4000);
        await fetchData();
      }
    } catch (err) {
      console.error('Remediation error:', err);
    }
  };

  const handleUpdateStatus = async (findingId: string, status: string) => {
    try {
      const res = await fetch(`/api/findings/${findingId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      if (res.ok) {
        await fetchData();
      }
    } catch (err) {
      console.error('Update status error:', err);
    }
  };

  const handleRunScan = async () => {
    try {
      setScanning(true);
      const res = await fetch('/api/scan', { method: 'POST' });
      const data = await res.json();
      setScanMessage(`Scan complete: ${data.policiesEvaluated} policies evaluated across all resources.`);
      setTimeout(() => setScanMessage(null), 5000);
      await fetchData();
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setScanning(false);
    }
  };

  const handleAddAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newAsset)
      });
      if (res.ok) {
        setShowAddAsset(false);
        setNewAsset({ name: '', type: 'Storage Bucket', region: 'us-east-1', provider: 'AWS', risk_score: 25 });
        await fetchData();
      }
    } catch (err) {
      console.error('Add asset error:', err);
    }
  };

  const handleSimulateThreat = async () => {
    try {
      const threatTypes = ['Unusual API Volume', 'Unauthorized IAM Access', 'Suspicious Port Scan', 'DDoS Pattern Detected'];
      const randomType = threatTypes[Math.floor(Math.random() * threatTypes.length)];
      const randomIp = `${Math.floor(Math.random() * 200 + 20)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

      await fetch('/api/threats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_type: randomType,
          source_ip: randomIp,
          target_service: 'api-gateway-edge',
          severity: 'HIGH',
          action_taken: 'Rate Limited and Flagged'
        })
      });
      await fetchData();
    } catch (err) {
      console.error('Simulate threat error:', err);
    }
  };

  const filteredFindings = findings.filter(f => {
    const matchesSev = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesStat = statusFilter === 'ALL' || f.status === statusFilter;
    const matchesSearch = searchTerm === '' || f.title.toLowerCase().includes(searchTerm.toLowerCase()) || f.resource_id.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSev && matchesStat && matchesSearch;
  });

  const filteredAssets = assets.filter(a => {
    const matchesProv = providerFilter === 'ALL' || a.provider === providerFilter;
    const matchesSearch = searchTerm === '' || a.name.toLowerCase().includes(searchTerm.toLowerCase()) || a.type.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesProv && matchesSearch;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      {/* Top Banner / Navigation */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-wider text-white">CYBERSENTINEL <span className="text-cyan-400">X</span></span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">CLOUDGUARD-X</span>
              </div>
              <p className="text-xs text-slate-400">Cloud Posture & Real-Time Threat Intelligence</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {healthInfo && (
              <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-slate-800/80 border border-slate-700 rounded-full text-xs font-mono text-slate-300">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>Node {healthInfo.runtime}</span>
                <span className="text-slate-500">|</span>
                <span>PORT {healthInfo.port}</span>
                <span className="text-slate-500">|</span>
                <span className="text-cyan-400">@libsql/client</span>
              </div>
            )}

            <button
              onClick={handleRunScan}
              disabled={scanning}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs tracking-wider uppercase rounded-lg transition shadow-lg shadow-cyan-500/20 disabled:opacity-60 cursor-pointer"
            >
              <RotateCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
              {scanning ? 'Running CSPM Scan...' : 'Trigger Scan'}
            </button>
          </div>
        </div>
      </header>

      {/* Notification Toast */}
      {scanMessage && (
        <div className="bg-cyan-500/10 border-b border-cyan-500/40 text-cyan-300 text-xs py-2 px-4 text-center font-mono flex items-center justify-center gap-2">
          <Activity className="w-3.5 h-3.5 animate-pulse text-cyan-400" />
          <span>{scanMessage}</span>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-6 overflow-x-auto text-sm">
          {[
            { id: 'overview', label: 'Posture Overview', icon: Activity },
            { id: 'findings', label: `Findings (${findings.filter(f => f.status !== 'RESOLVED').length})`, icon: ShieldAlert },
            { id: 'assets', label: `Cloud Assets (${assets.length})`, icon: Cloud },
            { id: 'threats', label: 'Threat Ingestion', icon: Flame },
            { id: 'compliance', label: 'Compliance Benchmarks', icon: ShieldCheck },
            { id: 'audit', label: 'Audit Trail', icon: Terminal },
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition cursor-pointer whitespace-nowrap ${
                  active
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <Icon className={`w-4 h-4 ${active ? 'text-cyan-400' : 'text-slate-500'}`} />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Tab 1: Overview */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Stat Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Cloud Resources</span>
                  <Cloud className="w-5 h-5 text-cyan-400" />
                </div>
                <div className="mt-3 text-3xl font-bold tracking-tight text-white">
                  {metrics?.totalAssets ?? assets.length}
                </div>
                <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-400">
                  <span className="text-emerald-400 font-semibold">100%</span>
                  <span>inventoried across AWS, GCP, Azure</span>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Critical Vulnerabilities</span>
                  <AlertTriangle className="w-5 h-5 text-rose-500" />
                </div>
                <div className="mt-3 text-3xl font-bold tracking-tight text-rose-400">
                  {metrics?.criticalFindings ?? 0}
                </div>
                <div className="mt-2 flex items-center gap-1.5 text-xs text-rose-400/80">
                  <span>Immediate remediation advised</span>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Average Compliance</span>
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                </div>
                <div className="mt-3 text-3xl font-bold tracking-tight text-emerald-400">
                  {metrics?.averageCompliance ?? 89}%
                </div>
                <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-400">
                  <span>5 Frameworks evaluated</span>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Threats Ingested</span>
                  <Flame className="w-5 h-5 text-amber-400" />
                </div>
                <div className="mt-3 text-3xl font-bold tracking-tight text-white">
                  {metrics?.totalThreatsDetected ?? threats.length}
                </div>
                <div className="mt-2 flex items-center gap-1.5 text-xs text-emerald-400">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Automated mitigations active</span>
                </div>
              </div>
            </div>

            {/* Quick Overview Panels */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Critical Findings Snapshot */}
              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold text-sm text-slate-200 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    Top Active Security Findings
                  </h3>
                  <button
                    onClick={() => setActiveTab('findings')}
                    className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1 cursor-pointer"
                  >
                    View All <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
                <div className="space-y-3">
                  {findings.filter(f => f.status !== 'RESOLVED').slice(0, 3).map(finding => (
                    <div
                      key={finding.id}
                      className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
                            finding.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                            finding.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                            'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}>
                            {finding.severity}
                          </span>
                          <span className="text-xs font-mono text-slate-400">{finding.cloud_provider} : {finding.resource_id}</span>
                        </div>
                        <p className="text-xs font-medium text-slate-200">{finding.title}</p>
                      </div>
                      <button
                        onClick={() => handleRemediate(finding.id)}
                        className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 rounded text-xs font-mono flex items-center gap-1.5 transition whitespace-nowrap cursor-pointer"
                      >
                        <Lock className="w-3 h-3 text-cyan-400" />
                        Remediate
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Real-time Threat Stream */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold text-sm text-slate-200 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    Live Threat Feed
                  </h3>
                  <button
                    onClick={handleSimulateThreat}
                    className="text-[10px] px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-mono cursor-pointer"
                  >
                    + Ingest Event
                  </button>
                </div>
                <div className="space-y-2.5">
                  {threats.slice(0, 4).map(threat => (
                    <div key={threat.id} className="p-2.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-200">{threat.event_type}</span>
                        <span className="text-[10px] font-mono text-slate-400">{threat.source_ip}</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span>Target: {threat.target_service}</span>
                        <span className="text-emerald-400 font-mono">{threat.action_taken}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Findings */}
        {activeTab === 'findings' && (
          <div className="space-y-4">
            {/* Filter controls */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
                <div className="relative flex-1 md:w-64">
                  <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search findings or resources..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>

                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="OPEN">Open</option>
                  <option value="IN_PROGRESS">In Progress</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="MUTED">Muted</option>
                </select>
              </div>

              <div className="text-xs text-slate-400 font-mono">
                Showing {filteredFindings.length} of {findings.length} findings
              </div>
            </div>

            {/* Findings List */}
            <div className="space-y-3">
              {filteredFindings.map(finding => (
                <div
                  key={finding.id}
                  className={`bg-slate-900 border rounded-xl p-5 transition ${
                    finding.status === 'RESOLVED' ? 'border-slate-800/60 opacity-70' : 'border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          finding.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          finding.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                          finding.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}>
                          {finding.severity}
                        </span>
                        <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                          {finding.cloud_provider}
                        </span>
                        <span className="text-xs font-mono text-slate-400">
                          ID: {finding.id}
                        </span>
                        <span className="text-xs font-mono text-slate-500">
                          Resource: <span className="text-slate-300">{finding.resource_id}</span>
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-100">{finding.title}</h4>
                      <p className="text-xs text-slate-400 flex items-center gap-1.5">
                        <span className="text-cyan-400 font-medium">Remediation:</span>
                        <span>{finding.remediation}</span>
                      </p>
                    </div>

                    <div className="flex items-center gap-3 pt-2 lg:pt-0">
                      <select
                        value={finding.status}
                        onChange={(e) => handleUpdateStatus(finding.id, e.target.value)}
                        className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-300 font-mono"
                      >
                        <option value="OPEN">OPEN</option>
                        <option value="IN_PROGRESS">IN_PROGRESS</option>
                        <option value="RESOLVED">RESOLVED</option>
                        <option value="MUTED">MUTED</option>
                      </select>

                      {finding.status !== 'RESOLVED' && (
                        <button
                          onClick={() => handleRemediate(finding.id)}
                          className="px-3 py-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-slate-950 font-semibold rounded text-xs flex items-center gap-1.5 transition cursor-pointer"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          Auto Fix
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 3: Cloud Assets */}
        {activeTab === 'assets' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-3">
                <select
                  value={providerFilter}
                  onChange={(e) => setProviderFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Providers (AWS, GCP, Azure)</option>
                  <option value="AWS">Amazon Web Services (AWS)</option>
                  <option value="GCP">Google Cloud Platform (GCP)</option>
                  <option value="Azure">Microsoft Azure</option>
                </select>
              </div>

              <button
                onClick={() => setShowAddAsset(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                Register Cloud Asset
              </button>
            </div>

            {/* Asset Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 font-mono border-b border-slate-800">
                    <tr>
                      <th className="p-3.5">Asset Identifier</th>
                      <th className="p-3.5">Type</th>
                      <th className="p-3.5">Provider / Region</th>
                      <th className="p-3.5">Risk Score</th>
                      <th className="p-3.5">Status</th>
                      <th className="p-3.5">Last Scanned</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredAssets.map(asset => (
                      <tr key={asset.id} className="hover:bg-slate-800/40 transition">
                        <td className="p-3.5 font-semibold text-slate-200">{asset.name}</td>
                        <td className="p-3.5 text-slate-400">{asset.type}</td>
                        <td className="p-3.5 text-slate-300">
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[11px] text-cyan-400 border border-slate-700 mr-2">
                            {asset.provider}
                          </span>
                          {asset.region}
                        </td>
                        <td className="p-3.5">
                          <span className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                            asset.risk_score >= 80 ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                            asset.risk_score >= 40 ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                            'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          }`}>
                            {asset.risk_score} / 100
                          </span>
                        </td>
                        <td className="p-3.5 text-slate-300">{asset.status}</td>
                        <td className="p-3.5 text-slate-400 text-[11px]">{new Date(asset.last_scanned).toLocaleTimeString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Modal: Add Asset */}
            {showAddAsset && (
              <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
                <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="font-semibold text-slate-200 text-sm">Register New Cloud Asset</h3>
                    <button onClick={() => setShowAddAsset(false)} className="text-slate-400 hover:text-white">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  <form onSubmit={handleAddAsset} className="space-y-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Asset Name / Resource ID</label>
                      <input
                        type="text"
                        required
                        value={newAsset.name}
                        onChange={(e) => setNewAsset({ ...newAsset, name: e.target.value })}
                        placeholder="e.g. prod-vpc-internal"
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Cloud Provider</label>
                      <select
                        value={newAsset.provider}
                        onChange={(e) => setNewAsset({ ...newAsset, provider: e.target.value })}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                      >
                        <option value="AWS">Amazon Web Services (AWS)</option>
                        <option value="GCP">Google Cloud Platform (GCP)</option>
                        <option value="Azure">Microsoft Azure</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Resource Type</label>
                      <input
                        type="text"
                        required
                        value={newAsset.type}
                        onChange={(e) => setNewAsset({ ...newAsset, type: e.target.value })}
                        placeholder="e.g. S3 Bucket, EKS Cluster, Cloud SQL"
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Region</label>
                      <input
                        type="text"
                        required
                        value={newAsset.region}
                        onChange={(e) => setNewAsset({ ...newAsset, region: e.target.value })}
                        placeholder="e.g. us-east-1, europe-west1"
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                    <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                      <button
                        type="button"
                        onClick={() => setShowAddAsset(false)}
                        className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded hover:bg-slate-700"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded"
                      >
                        Save Asset
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Threat Ingestion */}
        {activeTab === 'threats' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Real-Time Threat Intelligence Engine</h3>
                <p className="text-xs text-slate-400">Ingesting behavioral anomalies, intrusion attempts, and exfiltration patterns</p>
              </div>
              <button
                onClick={handleSimulateThreat}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600/80 hover:bg-rose-500 text-white font-semibold text-xs rounded-lg transition cursor-pointer"
              >
                <Flame className="w-3.5 h-3.5" />
                Simulate Incident Ingestion
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {threats.map(threat => (
                <div key={threat.id} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                      {threat.severity}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      {new Date(threat.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-100">{threat.event_type}</h4>
                    <p className="text-xs text-slate-400 mt-1">Target Service: <span className="font-mono text-slate-300">{threat.target_service}</span></p>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-400">Source: {threat.source_ip}</span>
                    <span className="text-emerald-400">{threat.action_taken}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 5: Compliance */}
        {activeTab === 'compliance' && (
          <div className="space-y-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-200 mb-1">Cloud Regulatory & Security Frameworks</h3>
              <p className="text-xs text-slate-400 mb-6">Continuous automated validation against recognized regulatory bodies</p>

              <div className="space-y-5">
                {compliance.map(fw => (
                  <div key={fw.id} className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-200 text-sm">{fw.name}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {fw.status}
                        </span>
                      </div>
                      <span className="font-mono font-bold text-cyan-400 text-sm">{fw.score}%</span>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-500 ${
                          fw.score >= 90 ? 'bg-emerald-400' : fw.score >= 80 ? 'bg-cyan-400' : 'bg-amber-400'
                        }`}
                        style={{ width: `${fw.score}%` }}
                      ></div>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                      <span>{fw.passed_controls} of {fw.total_controls} controls passed</span>
                      <span>Target: &gt;90% passing threshold</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Tab 6: Audit Trail */}
        {activeTab === 'audit' && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Immutable Audit Trail</h3>
                <p className="text-xs text-slate-400">Chronological history of security scans, remediations, and asset modifications</p>
              </div>
              <span className="text-xs font-mono text-cyan-400">@libsql/client Ledger</span>
            </div>

            <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="p-3">Timestamp</th>
                    <th className="p-3">Actor</th>
                    <th className="p-3">Action</th>
                    <th className="p-3">Target / Detail</th>
                    <th className="p-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {auditLogs.map(log => (
                    <tr key={log.id} className="hover:bg-slate-800/30">
                      <td className="p-3 text-slate-500">{new Date(log.timestamp).toLocaleTimeString()}</td>
                      <td className="p-3 text-cyan-400">{log.actor}</td>
                      <td className="p-3 font-semibold text-slate-200">{log.action}</td>
                      <td className="p-3 text-slate-400">{log.target}</td>
                      <td className="p-3 text-emerald-400">{log.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Render Node.js Deployment Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-4 px-4 sm:px-6 lg:px-8 text-xs font-mono text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2 mt-auto">
        <div className="flex items-center gap-2">
          <Server className="w-3.5 h-3.5 text-cyan-400" />
          <span>Render Web Service Config: 0.0.0.0:{healthInfo?.port || 3000}</span>
        </div>
        <div className="flex items-center gap-4 text-[11px]">
          <span>React 19</span>
          <span>•</span>
          <span>Express 4</span>
          <span>•</span>
          <span>Tailwind CSS 4</span>
          <span>•</span>
          <span>Vite 6.3.0</span>
          <span>•</span>
          <span>@libsql/client</span>
        </div>
      </footer>
    </div>
  );
}
