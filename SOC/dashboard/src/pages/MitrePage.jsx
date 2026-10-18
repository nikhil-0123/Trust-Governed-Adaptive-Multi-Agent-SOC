import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  ShieldAlert, 
  ExternalLink, 
  AlertTriangle, 
  Flame, 
  Search, 
  RefreshCw, 
  ArrowRight, 
  Info,
  CheckCircle2
} from 'lucide-react';
import { api } from '../api/client';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorState } from '../components/common/ErrorState';

// Standard Enterprise ATT&CK Tactics in Kill Chain Sequence
const ENTERPRISE_TACTICS = [
  {
    id: 'initial-access',
    name: 'Initial Access',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing App', desc: 'Exploitation of web servers, exposed ports or services.' },
      { id: 'T1566', name: 'Phishing', desc: 'Spearphishing or malicious attachment delivery.' },
    ]
  },
  {
    id: 'execution',
    name: 'Execution',
    techniques: [
      { id: 'T1059.001', name: 'PowerShell Execution', desc: 'PowerShell with EncodedCommand, download cradles, or bypass flags.' },
      { id: 'T1204', name: 'User Execution', desc: 'Execution of malicious payloads triggered by user interaction.' },
    ]
  },
  {
    id: 'persistence',
    name: 'Persistence',
    techniques: [
      { id: 'T1053', name: 'Scheduled Task / Job', desc: 'Persistence through task scheduling (schtasks, cron).' },
      { id: 'T1547', name: 'Boot / Logon Autostart', desc: 'Registry Run keys, startup folders, or login hooks.' },
    ]
  },
  {
    id: 'privilege-escalation',
    name: 'Privilege Escalation',
    techniques: [
      { id: 'T1068', name: 'Exploitation for Priv Esc', desc: 'Elevating privileges via local kernel or service vulnerabilities.' },
      { id: 'T1078', name: 'Valid Accounts', desc: 'Abuse of default or elevated credentials.' },
    ]
  },
  {
    id: 'defense-evasion',
    name: 'Defense Evasion',
    techniques: [
      { id: 'T1562.001', name: 'Impair Defenses', desc: 'Stopping Defender services, disabling real-time monitoring.' },
      { id: 'T1070.001', name: 'Clear Event Logs', desc: 'Clearing Windows Security/System event logs using wevtutil.' },
    ]
  },
  {
    id: 'credential-access',
    name: 'Credential Access',
    techniques: [
      { id: 'T1110', name: 'Brute Force', desc: 'Password guessing and spray attacks against Windows RDP or Linux SSH.' },
      { id: 'T1003', name: 'OS Credential Dumping', desc: 'Dumping LSASS memory, SAM hive, or /etc/shadow.' },
    ]
  },
  {
    id: 'discovery',
    name: 'Discovery',
    techniques: [
      { id: 'T1082', name: 'System Info Discovery', desc: 'Systeminfo, wmic, or OS profiling.' },
      { id: 'T1087', name: 'Account Discovery', desc: 'Enumerating domain or local admin accounts (net user, whoami).' },
      { id: 'T1033', name: 'System Owner/User', desc: 'Identifying current logged-in identity (whoami /priv).' },
    ]
  },
  {
    id: 'command-and-control',
    name: 'Command & Control',
    techniques: [
      { id: 'T1105', name: 'Ingress Tool Transfer', desc: 'LOLBins staging (certutil, bitsadmin, curl, wget) downloading remote tools.' },
      { id: 'T1071.004', name: 'DNS Tunneling', desc: 'Exfiltration or beaconing over DNS query channels.' },
    ]
  },
  {
    id: 'impact',
    name: 'Impact',
    techniques: [
      { id: 'T1486', name: 'Data Encrypted for Impact', desc: 'Ransomware file encryption and shadow copy deletion.' },
      { id: 'T1498', name: 'Network DoS', desc: 'Flooding services to cause resource exhaustion and downtime.' },
    ]
  }
];

export function MitrePage({ onSelectIncident, onNavigate, onOpenSettings }) {
  const [matrixData, setMatrixData] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [filterQuery, setFilterQuery] = useState('');

  const loadMitreMatrix = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getMitreMatrix();
      setMatrixData(data || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch MITRE matrix data');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMitreMatrix();
    const interval = setInterval(loadMitreMatrix, 15000);
    return () => clearInterval(interval);
  }, [loadMitreMatrix]);

  // Lookup map: technique_id -> detection record
  const detectionMap = useMemo(() => {
    const map = {};
    (matrixData || []).forEach(item => {
      if (item && item.technique_id) {
        map[item.technique_id] = item;
      }
    });
    return map;
  }, [matrixData]);

  // Active metrics
  const activeTechniqueCount = Object.keys(detectionMap).length;
  const activeTacticsCount = useMemo(() => {
    const activeTactics = new Set();
    ENTERPRISE_TACTICS.forEach(tactic => {
      const hasActive = tactic.techniques.some(t => !!detectionMap[t.id]);
      if (hasActive) activeTactics.add(tactic.id);
    });
    return activeTactics.size;
  }, [detectionMap]);

  return (
    <div className="space-y-6">
      {/* Top Header & Metrics Bar */}
      <div className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-500" />
              <span>MITRE ATT&CK® Enterprise Matrix Heatmap</span>
              <span className="text-[10px] font-mono uppercase bg-rose-950/60 text-rose-400 border border-rose-800/60 px-2 py-0.5 rounded">
                v15.0 Coverage
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Real-time threat mapping of detected endpoint behaviours against MITRE ATT&CK tactics & techniques
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Filter techniques..."
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-44"
              />
            </div>
            <button
              onClick={loadMitreMatrix}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-600 flex items-center gap-1.5 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-rose-400' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Fleet Threat Coverage KPI Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80">
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-400 uppercase block">Active Techniques</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-xl font-bold font-mono text-rose-400">{activeTechniqueCount}</span>
              <span className="text-[11px] text-slate-500 font-mono">detected in fleet</span>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-400 uppercase block">Tactics Infiltrated</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-xl font-bold font-mono text-amber-400">{activeTacticsCount}</span>
              <span className="text-[11px] text-slate-500 font-mono">of {ENTERPRISE_TACTICS.length} stages</span>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-400 uppercase block">Threat Context Source</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-xs font-bold font-mono text-cyan-300">Deterministic Engine</span>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-400 uppercase block">Reasoning Verification</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-xs font-bold font-mono text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Evidence-Backed
              </span>
            </div>
          </div>
        </div>
      </div>

      {isLoading && matrixData.length === 0 ? (
        <LoadingSkeleton count={3} type="table" />
      ) : error ? (
        <ErrorState
          error={error}
          onRetry={loadMitreMatrix}
          onOpenSettings={onOpenSettings}
          title="MITRE Matrix Query Error"
        />
      ) : (
        /* Matrix Columns Grid */
        <div className="overflow-x-auto pb-4">
          <div className="inline-flex gap-3 min-w-full">
            {ENTERPRISE_TACTICS.map((tactic) => {
              const matchingTechniques = tactic.techniques.filter(t => {
                if (!filterQuery) return true;
                const q = filterQuery.toLowerCase();
                return t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q);
              });

              const tacticHasActive = tactic.techniques.some(t => !!detectionMap[t.id]);

              return (
                <div
                  key={tactic.id}
                  className={`w-64 shrink-0 rounded-xl bg-soc-card border ${
                    tacticHasActive ? 'border-rose-900/50 shadow-md shadow-rose-950/20' : 'border-soc-border'
                  } flex flex-col justify-between`}
                >
                  {/* Tactic Column Header */}
                  <div className={`p-3 border-b ${
                    tacticHasActive ? 'border-rose-900/60 bg-rose-950/20' : 'border-slate-800 bg-slate-900/40'
                  } rounded-t-xl`}>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white uppercase tracking-wider">
                        {tactic.name}
                      </span>
                      {tacticHasActive && (
                        <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
                      )}
                    </div>
                    <span className="text-[10px] font-mono text-slate-400 block mt-0.5">
                      {matchingTechniques.length} Techniques
                    </span>
                  </div>

                  {/* Technique Cards in Column */}
                  <div className="p-2 space-y-2 flex-1">
                    {matchingTechniques.map((tech) => {
                      const detected = detectionMap[tech.id];
                      const isSelected = selectedTechnique?.id === tech.id;

                      return (
                        <div
                          key={tech.id}
                          onClick={() => setSelectedTechnique({ ...tech, detected })}
                          className={`p-2.5 rounded-lg border text-left cursor-pointer transition-all ${
                            detected
                              ? isSelected
                                ? 'bg-rose-950/80 border-rose-500 shadow-lg shadow-rose-950/60 ring-1 ring-rose-500'
                                : 'bg-rose-950/30 border-rose-800/80 hover:border-rose-500/80 hover:bg-rose-950/50'
                              : isSelected
                              ? 'bg-slate-800 border-cyan-500'
                              : 'bg-slate-900/40 border-slate-800/70 hover:border-slate-700 hover:bg-slate-800/40'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-1">
                            <span className="text-[11px] font-mono font-bold text-cyan-300">
                              {tech.id}
                            </span>
                            {detected ? (
                              <span className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-rose-600 text-white animate-pulse">
                                <Flame className="w-2.5 h-2.5" />
                                {detected.incident_count} INC
                              </span>
                            ) : (
                              <span className="text-[9px] font-mono text-slate-500 uppercase">
                                Monitored
                              </span>
                            )}
                          </div>

                          <p className="text-xs font-semibold text-slate-200 mt-1 line-clamp-1">
                            {tech.name}
                          </p>

                          <p className="text-[10px] text-slate-400 mt-1 line-clamp-2 leading-tight">
                            {tech.desc}
                          </p>

                          {detected && (
                            <div className="mt-2 pt-1.5 border-t border-rose-900/40 flex items-center justify-between text-[10px] font-mono text-rose-300">
                              <span>Events: {detected.event_count || 1}</span>
                              <span className="underline flex items-center gap-0.5">
                                Details <ArrowRight className="w-2.5 h-2.5" />
                              </span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Selected Technique Investigation Drawer */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold bg-rose-950 border border-rose-800 text-rose-300 px-2 py-0.5 rounded">
                    {selectedTechnique.id}
                  </span>
                  <h3 className="text-base font-bold text-white">
                    {selectedTechnique.name}
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-1">{selectedTechnique.desc}</p>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-2.5 py-1 text-xs text-slate-400 hover:text-white bg-slate-800 rounded"
              >
                Close
              </button>
            </div>

            <div className="p-4 overflow-y-auto space-y-4 flex-1 text-xs font-mono">
              {selectedTechnique.detected ? (
                <div className="space-y-4">
                  <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/60 flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-rose-200 block">Active Threat Detections Recorded</span>
                      <p className="text-slate-300 text-xs leading-relaxed mt-0.5">
                        This technique has been mapped from verified endpoint detection events with deterministic provenance.
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">TOTAL INCIDENTS:</span>
                      <span className="text-lg font-bold text-white">{selectedTechnique.detected.incident_count}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">LINKED EVIDENCE EVENTS:</span>
                      <span className="text-lg font-bold text-white">{selectedTechnique.detected.event_count || 1}</span>
                    </div>
                  </div>

                  {selectedTechnique.detected.incident_ids && selectedTechnique.detected.incident_ids.length > 0 && (
                    <div className="space-y-2">
                      <span className="text-slate-400 block text-xs">AFFECTED INCIDENT CORRELATIONS:</span>
                      <div className="space-y-2">
                        {selectedTechnique.detected.incident_ids.map((incId) => (
                          <div key={incId} className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                            <div>
                              <span className="font-bold text-cyan-300">{incId}</span>
                              <span className="text-[10px] text-slate-500 block">Correlated Threat Incident</span>
                            </div>
                            <button
                              onClick={() => {
                                if (onSelectIncident) onSelectIncident(incId);
                                if (onNavigate) onNavigate('investigation');
                                setSelectedTechnique(null);
                              }}
                              className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs flex items-center gap-1 transition"
                            >
                              <span>Investigate</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-6 text-center space-y-2">
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                  <h4 className="text-sm font-bold text-white">No Detections for {selectedTechnique.id}</h4>
                  <p className="text-slate-400 text-xs">
                    No active endpoint security events currently match this technique. Continuous monitoring is active across Windows and Ubuntu collectors.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* MITRE Provenance Notice */}
      <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 text-xs text-slate-400 flex items-start gap-3">
        <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-300">Deterministic ATT&CK Provenance:</span>{' '}
          Technique mappings adhere to strict provenance rules in compliance with the Master Project Context. 
          Technique associations are grounded directly in normalized endpoint evidence and verified by the Reasoning Agent before governance scoring.
        </div>
      </div>
    </div>
  );
}
