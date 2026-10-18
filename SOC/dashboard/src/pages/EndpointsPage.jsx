import React, { useState, useEffect, useCallback } from 'react';
import { Radio, Monitor, Terminal, Info, RefreshCw, Zap, Activity, ShieldCheck, CheckCircle2, AlertCircle } from 'lucide-react';
import { api } from '../api/client';
import { OsBadge } from '../components/common/Badges';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { EndpointBoundaryNotice } from '../components/common/ArchitectureNotices';

export function EndpointsPage({ incidents, onOpenSettings }) {
  const [endpoints, setEndpoints] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [actionStatus, setActionStatus] = useState(null);
  const [activeModalAgent, setActiveModalAgent] = useState(null);
  const [commandHistory, setCommandHistory] = useState([]);
  const [isLoadingCommands, setIsLoadingCommands] = useState(false);

  const loadEndpoints = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      // 1. Fetch registered endpoints from the Telemetry Devices Manager API
      const registered = await api.getEndpoints();

      // 2. Aggregate evidence from recent incidents for auxiliary event counts
      const evidenceCounts = {};
      const incidentSubset = incidents.slice(0, 15);
      for (const inc of incidentSubset) {
        try {
          const ev = await api.getIncidentEvidence(inc.incident_id);
          (ev || []).forEach(e => {
            if (e.agent_id) {
              evidenceCounts[e.agent_id] = (evidenceCounts[e.agent_id] || 0) + 1;
            }
          });
        } catch {
          // ignore error
        }
      }

      if (registered && registered.length > 0) {
        const mapped = registered.map(ep => ({
          ...ep,
          event_count: evidenceCounts[ep.agent_id] || 0,
        }));
        setEndpoints(mapped);
      } else {
        // Fallback to evidence aggregation if no heartbeat endpoints registered yet
        const endpointMap = {};
        for (const inc of incidentSubset) {
          try {
            const ev = await api.getIncidentEvidence(inc.incident_id);
            (ev || []).forEach(e => {
              if (!e.agent_id) return;
              if (!endpointMap[e.agent_id]) {
                endpointMap[e.agent_id] = {
                  agent_id: e.agent_id,
                  hostname: e.hostname || 'unknown-host',
                  os: e.os || 'unknown',
                  status: 'OFFLINE',
                  last_heartbeat: e.timestamp,
                  event_count: 0,
                  capabilities: [e.detector_name].filter(Boolean),
                };
              }
              endpointMap[e.agent_id].event_count++;
            });
          } catch {
            // ignore
          }
        }
        setEndpoints(Object.values(endpointMap));
      }
    } catch (err) {
      setError(err.message || 'Failed to aggregate endpoint telemetry.');
    } finally {
      setIsLoading(false);
    }
  }, [incidents]);

  useEffect(() => {
    loadEndpoints();
    const interval = setInterval(loadEndpoints, 15000);
    return () => clearInterval(interval);
  }, [loadEndpoints]);

  // Handle Command Dispatch
  const handleSendCommand = async (agentId, commandType) => {
    try {
      setActionStatus({ type: 'info', message: `Dispatching ${commandType} to ${agentId}...` });
      const res = await api.sendEndpointCommand(agentId, commandType);
      setActionStatus({
        type: 'success',
        message: `${commandType} queued (ID: ${res.command_id.slice(0, 8)}). Awaiting next agent heartbeat...`
      });
      // Auto-refresh command history if modal open
      if (activeModalAgent === agentId) {
        fetchCommandHistory(agentId);
      }
    } catch (err) {
      setActionStatus({ type: 'error', message: `Failed to dispatch ${commandType}: ${err.message}` });
    }
  };

  const fetchCommandHistory = async (agentId) => {
    setIsLoadingCommands(true);
    try {
      const cmds = await api.getEndpointCommands(agentId);
      setCommandHistory(cmds);
    } catch {
      setCommandHistory([]);
    } finally {
      setIsLoadingCommands(false);
    }
  };

  const openCommandAuditModal = (agentId) => {
    setActiveModalAgent(agentId);
    fetchCommandHistory(agentId);
  };

  return (
    <div className="space-y-6">
      {/* Scope and Boundary Notice */}
      <EndpointBoundaryNotice />

      {/* Action Notification Banner */}
      {actionStatus && (
        <div className={`p-3 rounded-lg text-xs font-mono flex items-center justify-between border ${
          actionStatus.type === 'success'
            ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
            : actionStatus.type === 'error'
            ? 'bg-rose-950/60 border-rose-800 text-rose-300'
            : 'bg-cyan-950/60 border-cyan-800 text-cyan-300'
        }`}>
          <div className="flex items-center gap-2">
            {actionStatus.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4" />}
            <span>{actionStatus.message}</span>
          </div>
          <button onClick={() => setActionStatus(null)} className="text-slate-400 hover:text-white text-xs">✕</button>
        </div>
      )}

      {/* Header Bar */}
      <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Radio className="w-5 h-5 text-cyan-400" />
            Telemetry Devices Manager & Live Agents
          </h2>
          <p className="text-xs text-slate-400">
            Real-time heartbeat monitoring and remote command polling for Windows & Ubuntu nodes
          </p>
        </div>

        <button
          onClick={loadEndpoints}
          disabled={isLoading}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-600 flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Fleet</span>
        </button>
      </div>

      {/* Architecture Scope Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3">
          <Monitor className="w-6 h-6 text-blue-400 shrink-0 mt-1" />
          <div className="text-xs space-y-1">
            <span className="font-semibold text-white">Windows Employee Endpoint (windows-telemetry)</span>
            <p className="text-slate-400 leading-relaxed">
              Active Security Event Log monitor with local detection, durable SQLite outbox, and 15s heartbeat beacon.
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3">
          <Terminal className="w-6 h-6 text-orange-400 shrink-0 mt-1" />
          <div className="text-xs space-y-1">
            <span className="font-semibold text-white">Ubuntu Employee Endpoint (ubuntu-telemetry)</span>
            <p className="text-slate-400 leading-relaxed">
              Monitors /var/log/auth.log for SSH attacks with durable SQLite delivery and remote command execution support.
            </p>
          </div>
        </div>
      </div>

      {isLoading && endpoints.length === 0 ? (
        <LoadingSkeleton count={3} type="table" />
      ) : error ? (
        <ErrorState
          error={error}
          onRetry={loadEndpoints}
          onOpenSettings={onOpenSettings}
          title="Endpoint Query Error"
        />
      ) : endpoints.length === 0 ? (
        <EmptyState
          title="No Endpoints Registered"
          description="Start windows-telemetry or ubuntu-telemetry agent to begin receiving heartbeats."
          icon={Radio}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {endpoints.map((ep) => {
            const isOnline = ep.status === 'ONLINE';
            return (
              <div
                key={ep.agent_id}
                className={`p-5 rounded-xl bg-soc-card border ${isOnline ? 'border-emerald-900/60' : 'border-soc-border'} shadow-lg flex flex-col justify-between space-y-4 hover:border-slate-600 transition`}
              >
                <div>
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                    <OsBadge os={ep.os} />
                    <span className={`flex items-center gap-1.5 text-[10px] font-mono px-2 py-0.5 rounded border ${
                      isOnline
                        ? 'text-emerald-400 bg-emerald-950/60 border-emerald-800/40'
                        : 'text-slate-400 bg-slate-900/60 border-slate-700/40'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`}></span>
                      {isOnline ? 'ONLINE' : 'OFFLINE'}
                    </span>
                  </div>

                  <div className="mt-3 space-y-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block">AGENT ID</span>
                    <p className="text-xs font-mono font-bold text-cyan-300 truncate" title={ep.agent_id}>
                      {ep.agent_id}
                    </p>
                    <div className="flex items-center justify-between text-xs text-slate-300">
                      <span>{ep.hostname}</span>
                      {ep.ip_address && (
                        <span className="font-mono text-[11px] text-slate-400">{ep.ip_address}</span>
                      )}
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/60 space-y-2 text-xs font-mono">
                    <div className="flex justify-between text-slate-400">
                      <span>Security Events:</span>
                      <span className="text-white font-bold">{ep.event_count}</span>
                    </div>
                    <div className="flex justify-between text-slate-400 text-[11px]">
                      <span>Last Heartbeat:</span>
                      <span className="text-slate-300">
                        {ep.last_heartbeat ? new Date(ep.last_heartbeat).toLocaleTimeString() : 'N/A'}
                      </span>
                    </div>
                    {ep.agent_version && (
                      <div className="flex justify-between text-slate-400 text-[11px]">
                        <span>Agent Version:</span>
                        <span className="text-slate-300">v{ep.agent_version}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Capabilities */}
                {ep.capabilities && ep.capabilities.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/40">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Capabilities:</span>
                    <div className="flex flex-wrap gap-1">
                      {ep.capabilities.map((cap, i) => (
                        <span key={i} className="text-[10px] font-mono bg-slate-900 text-slate-300 px-1.5 py-0.5 rounded border border-slate-800">
                          {cap}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Remote Management Action Buttons */}
                <div className="pt-3 border-t border-slate-800 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => handleSendCommand(ep.agent_id, 'PING')}
                      title="Send PING to verify latency"
                      className="px-2 py-1 bg-slate-800 hover:bg-cyan-900/60 hover:text-cyan-300 text-[11px] font-mono text-slate-300 rounded border border-slate-700 flex items-center gap-1 transition"
                    >
                      <Zap className="w-3 h-3 text-cyan-400" />
                      Ping
                    </button>
                    <button
                      onClick={() => handleSendCommand(ep.agent_id, 'GET_HEALTH')}
                      title="Query remote host resource health"
                      className="px-2 py-1 bg-slate-800 hover:bg-emerald-900/60 hover:text-emerald-300 text-[11px] font-mono text-slate-300 rounded border border-slate-700 flex items-center gap-1 transition"
                    >
                      <Activity className="w-3 h-3 text-emerald-400" />
                      Health
                    </button>
                    <button
                      onClick={() => handleSendCommand(ep.agent_id, 'GET_STATUS')}
                      title="Fetch agent runtime status"
                      className="px-2 py-1 bg-slate-800 hover:bg-purple-900/60 hover:text-purple-300 text-[11px] font-mono text-slate-300 rounded border border-slate-700 flex items-center gap-1 transition"
                    >
                      <ShieldCheck className="w-3 h-3 text-purple-400" />
                      Status
                    </button>
                  </div>

                  <button
                    onClick={() => openCommandAuditModal(ep.agent_id)}
                    title="View command audit trail"
                    className="p-1 hover:bg-slate-800 text-slate-400 hover:text-white rounded transition text-xs font-mono"
                  >
                    History
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Remote Command Audit Modal / Drawer */}
      {activeModalAgent && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  Remote Command History — <span className="font-mono text-cyan-300">{activeModalAgent}</span>
                </h3>
                <p className="text-xs text-slate-400">Dispatched instructions and executed agent responses</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => fetchCommandHistory(activeModalAgent)}
                  className="p-1 text-slate-400 hover:text-white"
                  title="Refresh"
                >
                  <RefreshCw className={`w-4 h-4 ${isLoadingCommands ? 'animate-spin' : ''}`} />
                </button>
                <button
                  onClick={() => setActiveModalAgent(null)}
                  className="px-2.5 py-1 text-xs text-slate-400 hover:text-white bg-slate-800 rounded"
                >
                  Close
                </button>
              </div>
            </div>

            <div className="p-4 overflow-y-auto space-y-3 flex-1 text-xs font-mono">
              {isLoadingCommands ? (
                <div className="text-center py-6 text-slate-400">Loading command execution audit...</div>
              ) : commandHistory.length === 0 ? (
                <div className="text-center py-6 text-slate-500">No commands dispatched yet. Use Ping, Health, or Status buttons to dispatch.</div>
              ) : (
                commandHistory.map((cmd) => (
                  <div key={cmd.command_id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white uppercase px-1.5 py-0.5 rounded bg-slate-800">
                          {cmd.command_type}
                        </span>
                        <span className="text-[11px] text-slate-400">{cmd.command_id.slice(0, 8)}...</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] ${
                        cmd.status === 'EXECUTED'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : cmd.status === 'SENT'
                          ? 'bg-blue-950 text-blue-300 border border-blue-800'
                          : cmd.status === 'FAILED'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}>
                        {cmd.status}
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-400 flex items-center justify-between">
                      <span>Created: {new Date(cmd.created_at).toLocaleTimeString()}</span>
                      <span>Updated: {new Date(cmd.updated_at).toLocaleTimeString()}</span>
                    </div>

                    {cmd.result && (
                      <div className="mt-2 p-2 rounded bg-slate-900 border border-slate-800/80 text-[11px] text-slate-200">
                        <span className="text-slate-500 block text-[10px] mb-1">EXECUTION RESULT:</span>
                        <pre className="overflow-x-auto text-[11px] text-emerald-300">
                          {JSON.stringify(cmd.result, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Architecture Notice */}
      <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 text-xs text-slate-400 flex items-start gap-3">
        <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-300">Telemetry Devices Manager Active:</span>{' '}
          Endpoints register via periodic 15-second heartbeats (<span className="font-mono text-slate-300">/api/v1/endpoints/heartbeat</span>)
          and poll pending remote diagnostics commands (PING, GET_HEALTH, GET_STATUS). High-impact response actions remain strictly governed by the Trust-Governed Multi-Agent layer.
        </div>
      </div>
    </div>
  );
}
