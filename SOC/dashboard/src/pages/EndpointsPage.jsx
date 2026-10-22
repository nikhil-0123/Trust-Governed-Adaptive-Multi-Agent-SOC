import React, { useState, useEffect, useCallback } from 'react';
import { 
  Radio, Monitor, Terminal, Info, RefreshCw, Zap, Activity, 
  ShieldCheck, CheckCircle2, AlertCircle, Trash2, ShieldAlert, 
  Skull, WifiOff, Wifi, UserX, AlertTriangle, Send 
} from 'lucide-react';
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

  // Active Remediation State
  const [remediateModalEndpoint, setRemediateModalEndpoint] = useState(null);
  const [remediateAction, setRemediateAction] = useState('BLOCK_SOURCE');
  const [remediateForm, setRemediateForm] = useState({
    ip: '',
    process_name: '',
    process_id: '',
    username: '',
    simulate: true,
    reason: 'Manual analyst containment via TGAM-SOC remediation console.'
  });
  const [isSubmittingRemediation, setIsSubmittingRemediation] = useState(false);

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

  const openRemediateModal = (endpoint, initialAction = 'BLOCK_SOURCE', initialParams = {}) => {
    setRemediateModalEndpoint(endpoint);
    setRemediateAction(initialAction);
    setRemediateForm({
      ip: initialParams.ip || (endpoint.ip_address && endpoint.ip_address !== '127.0.0.1' ? endpoint.ip_address : ''),
      process_name: initialParams.process_name || '',
      process_id: initialParams.process_id || '',
      username: initialParams.username || '',
      simulate: initialParams.simulate !== undefined ? initialParams.simulate : true,
      reason: initialParams.reason || 'Manual analyst containment via TGAM-SOC remediation console.'
    });
  };

  const handleExecuteRemediation = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!remediateModalEndpoint) return;
    setIsSubmittingRemediation(true);
    try {
      const params = {
        simulate: Boolean(remediateForm.simulate),
        reason: remediateForm.reason
      };

      if (remediateAction === 'BLOCK_SOURCE' || remediateAction === 'UNBLOCK_SOURCE') {
        if (!remediateForm.ip || !remediateForm.ip.trim()) {
          throw new Error('Target IP address is required for BLOCK_SOURCE.');
        }
        params.ip = remediateForm.ip.trim();
      } else if (remediateAction === 'KILL_PROCESS') {
        if (!remediateForm.process_name && !remediateForm.process_id) {
          throw new Error('Either Process Name or Process ID (PID) is required for KILL_PROCESS.');
        }
        if (remediateForm.process_id) params.process_id = parseInt(remediateForm.process_id, 10);
        if (remediateForm.process_name) params.process_name = remediateForm.process_name.trim();
      } else if (remediateAction === 'ISOLATE_HOST') {
        params.preserve_soc_communication = true;
      } else if (remediateAction === 'DISABLE_ACCOUNT') {
        if (!remediateForm.username || !remediateForm.username.trim()) {
          throw new Error('Target username is required for DISABLE_ACCOUNT.');
        }
        params.username = remediateForm.username.trim();
      }

      const agentId = remediateModalEndpoint.agent_id;
      const res = await api.sendEndpointCommand(agentId, remediateAction, params);
      setActionStatus({
        type: 'success',
        message: `Containment action [${remediateAction}] dispatched to ${agentId} (Command ID: ${res.command_id.slice(0, 8)}). Executing on next heartbeat!`
      });
      setRemediateModalEndpoint(null);
      openCommandAuditModal(agentId);
    } catch (err) {
      setActionStatus({
        type: 'error',
        message: `Remediation dispatch failed: ${err.message}`
      });
    } finally {
      setIsSubmittingRemediation(false);
    }
  };

  const handleDeleteEndpoint = async (agentId) => {
    try {
      await api.deleteEndpoint(agentId);
      setActionStatus({
        type: 'success',
        message: `Endpoint ${agentId} removed from registry.`
      });
      loadEndpoints();
    } catch (err) {
      setActionStatus({
        type: 'error',
        message: `Failed to remove endpoint: ${err.message}`
      });
    }
  };

  const handlePruneOffline = async () => {
    const offline = endpoints.filter(ep => ep.status !== 'ONLINE');
    if (offline.length === 0) return;
    try {
      setActionStatus({ type: 'info', message: `Pruning ${offline.length} offline test endpoint(s)...` });
      for (const ep of offline) {
        await api.deleteEndpoint(ep.agent_id);
      }
      setActionStatus({
        type: 'success',
        message: `Successfully pruned ${offline.length} stale endpoint(s). Fleet consolidated.`
      });
      loadEndpoints();
    } catch (err) {
      setActionStatus({
        type: 'error',
        message: `Pruning failed: ${err.message}`
      });
    }
  };

  const offlineCount = endpoints.filter(ep => ep.status !== 'ONLINE').length;

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

        <div className="flex items-center gap-2">
          {offlineCount > 0 && (
            <button
              onClick={handlePruneOffline}
              title="Remove inactive or old simulation test endpoints"
              className="px-3 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900/80 text-xs font-mono text-rose-300 border border-rose-800/80 flex items-center gap-1.5 transition"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              <span>Prune Inactive ({offlineCount})</span>
            </button>
          )}

          <button
            onClick={loadEndpoints}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-600 flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh Fleet</span>
          </button>
        </div>
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
                <div className="pt-3 border-t border-slate-800 space-y-2">
                  <div className="flex items-center justify-between gap-1.5">
                    <div className="flex items-center gap-1">
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

                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => openCommandAuditModal(ep.agent_id)}
                        title="View command audit trail"
                        className="px-2 py-1 hover:bg-slate-800 text-slate-400 hover:text-white rounded transition text-xs font-mono"
                      >
                        History
                      </button>
                      {!isOnline && (
                        <button
                          onClick={() => handleDeleteEndpoint(ep.agent_id)}
                          title="Delete inactive test endpoint"
                          className="p-1 hover:bg-rose-950/60 text-slate-500 hover:text-rose-400 rounded transition"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Active Analyst Remediation Trigger */}
                  <button
                    onClick={() => openRemediateModal(ep)}
                    className="w-full py-1.5 px-3 rounded-lg bg-rose-950/60 hover:bg-rose-900/80 border border-rose-800/70 hover:border-rose-600 text-rose-300 hover:text-white font-mono text-xs font-bold flex items-center justify-center gap-2 shadow-sm transition"
                  >
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                    <span>Remediate Endpoint (Active Defense)</span>
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

      {/* Active Defense Endpoint Containment Modal */}
      {remediateModalEndpoint && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-rose-950/80 border border-rose-800/80 text-rose-400">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    Active Endpoint Containment Console
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Host: <span className="text-cyan-300 font-bold">{remediateModalEndpoint.hostname}</span> • Agent ID: <span className="text-slate-300">{remediateModalEndpoint.agent_id}</span> • OS: <span className="text-amber-300">{remediateModalEndpoint.os}</span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setRemediateModalEndpoint(null)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                ✕
              </button>
            </div>

            {/* Modal Form Content */}
            <form onSubmit={handleExecuteRemediation} className="p-5 overflow-y-auto space-y-5 flex-1 text-xs">
              {/* Containment Action Selector */}
              <div>
                <label className="text-slate-300 font-semibold uppercase tracking-wider block mb-2 font-mono text-[11px]">
                  Select Containment Action
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {[
                    { id: 'BLOCK_SOURCE', label: 'Block Attacker IP', icon: ShieldAlert, desc: 'Firewall drop rule' },
                    { id: 'KILL_PROCESS', label: 'Kill Process', icon: Skull, desc: 'Terminate task by name/PID' },
                    { id: 'ISOLATE_HOST', label: 'Isolate Host', icon: WifiOff, desc: 'Drop all traffic except SOC' },
                    { id: 'RESTORE_HOST', label: 'Restore Network', icon: Wifi, desc: 'Remove isolation rules' },
                    { id: 'DISABLE_ACCOUNT', label: 'Disable Account', icon: UserX, desc: 'Lock compromised user' },
                    { id: 'UNBLOCK_SOURCE', label: 'Unblock IP', icon: CheckCircle2, desc: 'Remove firewall drop rule' },
                  ].map((act) => {
                    const IconComp = act.icon;
                    const isSelected = remediateAction === act.id;
                    return (
                      <button
                        type="button"
                        key={act.id}
                        onClick={() => setRemediateAction(act.id)}
                        className={`p-3 rounded-lg border text-left flex flex-col justify-between transition ${
                          isSelected
                            ? 'bg-rose-950/60 border-rose-500 text-white shadow-md shadow-rose-950/50'
                            : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <IconComp className={`w-4 h-4 ${isSelected ? 'text-rose-400' : 'text-slate-500'}`} />
                          <span className="font-bold text-xs">{act.label}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 leading-tight">{act.desc}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Action Parameter Inputs */}
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3 font-mono">
                <span className="text-[11px] font-bold text-cyan-400 block uppercase">
                  Action Parameters — {remediateAction}
                </span>

                {(remediateAction === 'BLOCK_SOURCE' || remediateAction === 'UNBLOCK_SOURCE') && (
                  <div>
                    <label className="block text-slate-300 text-[11px] mb-1">Target IP Address to Block *</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. 192.168.1.100 or 10.0.0.50"
                      value={remediateForm.ip}
                      onChange={(e) => setRemediateForm({ ...remediateForm, ip: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500 text-xs"
                    />
                    <p className="text-[10px] text-slate-500 mt-1">
                      Windows Advanced Firewall will create an inbound rule TGAM-SOC-Block-[IP] dropping all packets.
                    </p>
                  </div>
                )}

                {remediateAction === 'KILL_PROCESS' && (
                  <div className="space-y-3">
                    <div>
                      <label className="block text-slate-300 text-[11px] mb-1">Target Process Image Name</label>
                      <input
                        type="text"
                        placeholder="e.g. mimikatz.exe, malware.exe, nc.exe"
                        value={remediateForm.process_name}
                        onChange={(e) => setRemediateForm({ ...remediateForm, process_name: e.target.value })}
                        className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500 text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 text-[11px] mb-1">OR Process ID (PID)</label>
                      <input
                        type="number"
                        placeholder="e.g. 4832"
                        value={remediateForm.process_id}
                        onChange={(e) => setRemediateForm({ ...remediateForm, process_id: e.target.value })}
                        className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500 text-xs"
                      />
                    </div>
                    <div className="p-2.5 rounded bg-amber-950/30 border border-amber-800/40 text-[10px] text-amber-300 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <span>Safety Guardrail: Protected OS processes (csrss.exe, lsass.exe, svchost.exe, PID &le; 4) are automatically blocked from termination.</span>
                    </div>
                  </div>
                )}

                {remediateAction === 'ISOLATE_HOST' && (
                  <div className="p-3 rounded bg-blue-950/30 border border-blue-800/40 text-blue-200 text-xs space-y-1">
                    <span className="font-bold flex items-center gap-1 text-cyan-300">
                      <WifiOff className="w-4 h-4 text-cyan-400" /> Host Network Isolation Policy
                    </span>
                    <p className="text-[11px] text-slate-300">
                      This command will configure endpoint firewalls to block all external network communications except outbound connections to the Central SOC Ingestion Server ({typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1'}).
                    </p>
                  </div>
                )}

                {remediateAction === 'RESTORE_HOST' && (
                  <div className="p-3 rounded bg-emerald-950/30 border border-emerald-800/40 text-emerald-200 text-xs space-y-1">
                    <span className="font-bold flex items-center gap-1 text-emerald-300">
                      <Wifi className="w-4 h-4 text-emerald-400" /> Host Network Restoration
                    </span>
                    <p className="text-[11px] text-slate-300">
                      Removes isolation rules and restores normal inbound and outbound connectivity to this endpoint.
                    </p>
                  </div>
                )}

                {remediateAction === 'DISABLE_ACCOUNT' && (
                  <div>
                    <label className="block text-slate-300 text-[11px] mb-1">Target Account Username *</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. compromised_employee"
                      value={remediateForm.username}
                      onChange={(e) => setRemediateForm({ ...remediateForm, username: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500 text-xs"
                    />
                    <p className="text-[10px] text-slate-500 mt-1">
                      Disables the specified user via net user &lt;username&gt; /active:no. Protected accounts (Administrator, Guest) are guarded.
                    </p>
                  </div>
                )}
              </div>

              {/* Analyst Justification */}
              <div>
                <label className="block text-slate-300 font-semibold uppercase tracking-wider mb-1 font-mono text-[11px]">
                  Analyst Rationale / Justification
                </label>
                <input
                  type="text"
                  value={remediateForm.reason}
                  onChange={(e) => setRemediateForm({ ...remediateForm, reason: e.target.value })}
                  placeholder="Reason for manual containment intervention..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-rose-500 font-mono text-xs"
                />
              </div>

              {/* Simulation Mode Toggle */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="font-bold text-white block">Safe Simulation Mode (Dry Run)</span>
                  <p className="text-[11px] text-slate-400">
                    Agent calculates and logs the mitigation command without making destructive OS changes.
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={remediateForm.simulate}
                    onChange={(e) => setRemediateForm({ ...remediateForm, simulate: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-rose-600"></div>
                </label>
              </div>

              {/* Submit / Cancel Footer */}
              <div className="pt-2 flex items-center justify-end gap-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setRemediateModalEndpoint(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingRemediation}
                  className="px-5 py-2 bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 disabled:opacity-50 text-white font-mono text-xs font-bold rounded-lg shadow-lg shadow-rose-950/60 flex items-center gap-2 transition"
                >
                  <Send className="w-4 h-4" />
                  {isSubmittingRemediation ? 'Dispatching...' : `Dispatch ${remediateAction} to Endpoint`}
                </button>
              </div>
            </form>
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
