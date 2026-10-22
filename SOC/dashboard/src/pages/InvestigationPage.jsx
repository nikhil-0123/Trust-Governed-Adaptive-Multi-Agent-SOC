import React, { useState, useEffect, useCallback } from 'react';
import { 
  Users, Clock, Crosshair, FileCode, ShieldAlert, Skull, 
  UserX, AlertCircle, CheckCircle2, Send, AlertTriangle, RefreshCw 
} from 'lucide-react';
import { api } from '../api/client';
import { SeverityBadge, OsBadge } from '../components/common/Badges';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { JsonModal } from '../components/common/JsonModal';

export function InvestigationPage({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  onOpenSettings
}) {
  const [evidenceList, setEvidenceList] = useState([]);
  const [entitiesList, setEntitiesList] = useState([]);
  const [mitreList, setMitreList] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeJson, setActiveJson] = useState(null);

  // Quick Containment Action States
  const [actionStatus, setActionStatus] = useState(null);
  const [quickActionModal, setQuickActionModal] = useState(null);
  const [isDispatchingQuick, setIsDispatchingQuick] = useState(false);

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;

  const loadInvestigationData = useCallback(async (incidentId) => {
    setIsLoading(true);
    setError(null);
    try {
      const evRes = await api.getIncidentEvidence(incidentId);
      const entRes = await api.getIncidentEntities(incidentId);
      const mitRes = await api.getIncidentMitre(incidentId);
      setEvidenceList(evRes || []);
      setEntitiesList(entRes || []);
      setMitreList(mitRes || []);
    } catch (err) {
      setError(err.message || 'Failed to load investigation data.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!activeIncident?.incident_id) return;
    loadInvestigationData(activeIncident.incident_id);
  }, [activeIncident?.incident_id, loadInvestigationData]);

  // Target agent derived from evidence or active incident
  const targetAgentId = evidenceList.find(e => e.agent_id)?.agent_id || activeIncident?.agent_id || null;

  const handleOpenQuickAction = (type, value) => {
    setQuickActionModal({
      type,
      entityValue: value,
      agentId: targetAgentId,
      simulate: true,
      reason: `Analyst containment for entity [${value}] on incident ${activeIncident?.incident_id}`
    });
  };

  const handleExecuteQuickAction = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!quickActionModal) return;
    setIsDispatchingQuick(true);
    try {
      const { type, entityValue, agentId, simulate, reason } = quickActionModal;
      if (!agentId) throw new Error('No target endpoint agent associated with this incident.');

      const params = {
        simulate: Boolean(simulate),
        reason: reason || 'Manual containment via Investigation Page'
      };

      if (type === 'BLOCK_SOURCE') {
        params.ip = entityValue.trim();
      } else if (type === 'KILL_PROCESS') {
        if (/^\d+$/.test(entityValue.trim())) {
          params.process_id = parseInt(entityValue.trim(), 10);
        } else {
          params.process_name = entityValue.trim();
        }
      } else if (type === 'DISABLE_ACCOUNT') {
        params.username = entityValue.trim();
      }

      const res = await api.sendEndpointCommand(agentId, type, params);
      setActionStatus({
        type: 'success',
        message: `Containment action [${type}] dispatched to agent ${agentId} (Command ID: ${res.command_id.slice(0, 8)}). Executing on next heartbeat!`
      });
      setQuickActionModal(null);
    } catch (err) {
      setActionStatus({
        type: 'error',
        message: `Containment dispatch failed: ${err.message}`
      });
    } finally {
      setIsDispatchingQuick(false);
    }
  };

  if (!activeIncident) {
    return (
      <EmptyState
        title="No Incident Selected"
        description="Select an incident from the Incidents table or Overview tab to begin forensic investigation."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Action Notification Banner */}
      {actionStatus && (
        <div className={`p-3 rounded-lg text-xs font-mono flex items-center justify-between border ${
          actionStatus.type === 'success'
            ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
            : 'bg-rose-950/60 border-rose-800 text-rose-300'
        }`}>
          <div className="flex items-center gap-2">
            {actionStatus.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4" />}
            <span>{actionStatus.message}</span>
          </div>
          <button onClick={() => setActionStatus(null)} className="text-slate-400 hover:text-white text-xs">✕</button>
        </div>
      )}

      {/* Incident Selection and Context Banner */}
      <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest">
              Active Investigation Case
            </span>
            <SeverityBadge severity={activeIncident.max_severity} />
          </div>
          <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
            <span>{activeIncident.incident_id}</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            First seen: {new Date(activeIncident.first_seen).toLocaleString()} • Last seen: {new Date(activeIncident.last_seen).toLocaleString()}
          </p>
        </div>

        {/* Incident Switcher Dropdown */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">Switch Case:</span>
          <select
            value={activeIncident.incident_id}
            onChange={(e) => onSelectIncident(e.target.value)}
            className="px-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
          >
            {incidents.map((inc) => (
              <option key={inc.incident_id} value={inc.incident_id}>
                {inc.incident_id} ({inc.max_severity})
              </option>
            ))}
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <LoadingSkeleton count={3} type="row" />
          <LoadingSkeleton count={4} type="table" />
        </div>
      ) : error ? (
        <ErrorState
          error={error}
          onRetry={() => loadInvestigationData(activeIncident.incident_id)}
          onOpenSettings={onOpenSettings}
          title="Investigation Data Fetch Failed"
        />
      ) : (
        <>
          {/* Top Row: Correlated Entities & MITRE ATT&CK */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Correlated Entities */}
            <div className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Users className="w-4 h-4 text-cyan-400" />
                  Correlated Incident Entities
                </h3>
                <span className="text-xs font-mono text-slate-400">{entitiesList.length} Entities</span>
              </div>

              {entitiesList.length === 0 ? (
                <EmptyState
                  title="No Correlated Entities"
                  description="No user, host, IP, or process entities have been mapped to this incident."
                />
              ) : (
                <div className="flex flex-wrap gap-2">
                  {entitiesList.map((ent, idx) => {
                    const normType = (ent.entity_type || '').toUpperCase();
                    const isIp = normType.includes('IP');
                    const isProcess = normType.includes('PROCESS') || normType.includes('IMAGE');
                    const isUser = normType.includes('USER') || normType.includes('ACCOUNT');

                    return (
                      <div
                        key={idx}
                        className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-700/70 flex items-center gap-2 text-xs font-mono group hover:border-slate-500 transition"
                      >
                        <span className="text-[10px] uppercase font-bold text-cyan-400 bg-cyan-950 px-1 py-0.5 rounded border border-cyan-800/40">
                          {ent.entity_type}
                        </span>
                        <span className="text-white font-semibold">{ent.entity_value}</span>

                        {/* Inline Containment Quick Triggers */}
                        {isIp && targetAgentId && (
                          <button
                            onClick={() => handleOpenQuickAction('BLOCK_SOURCE', ent.entity_value)}
                            title={`Block IP ${ent.entity_value} on agent ${targetAgentId}`}
                            className="ml-1 px-1.5 py-0.5 rounded bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300 hover:text-white text-[10px] flex items-center gap-1 transition"
                          >
                            <ShieldAlert className="w-2.5 h-2.5 text-rose-400" />
                            <span>Block</span>
                          </button>
                        )}

                        {isProcess && targetAgentId && (
                          <button
                            onClick={() => handleOpenQuickAction('KILL_PROCESS', ent.entity_value)}
                            title={`Terminate process ${ent.entity_value} on agent ${targetAgentId}`}
                            className="ml-1 px-1.5 py-0.5 rounded bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300 hover:text-white text-[10px] flex items-center gap-1 transition"
                          >
                            <Skull className="w-2.5 h-2.5 text-rose-400" />
                            <span>Kill</span>
                          </button>
                        )}

                        {isUser && targetAgentId && (
                          <button
                            onClick={() => handleOpenQuickAction('DISABLE_ACCOUNT', ent.entity_value)}
                            title={`Disable account ${ent.entity_value} on agent ${targetAgentId}`}
                            className="ml-1 px-1.5 py-0.5 rounded bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300 hover:text-white text-[10px] flex items-center gap-1 transition"
                          >
                            <UserX className="w-2.5 h-2.5 text-rose-400" />
                            <span>Lock</span>
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* MITRE ATT&CK Mapping */}
            <div className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-rose-400" />
                  MITRE ATT&CK Threat Mapping
                </h3>
                <span className="text-xs font-mono text-slate-400">{mitreList.length} Techniques</span>
              </div>

              {mitreList.length === 0 ? (
                <EmptyState
                  title="No MITRE Techniques Mapped"
                  description="Threat context worker has not yet associated MITRE ATT&CK tactics with this evidence."
                />
              ) : (
                <div className="space-y-2">
                  {mitreList.map((m) => (
                    <div
                      key={m.context_id}
                      className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800/50">
                            {m.technique_id}
                          </span>
                          <span className="text-slate-200 font-medium">{m.technique_name}</span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
                          <span>Tactic: {m.tactic}</span>
                          <span>•</span>
                          <span>Method: {m.mapping_method}</span>
                          <span>•</span>
                          <span>v{m.mitre_version}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Evidence Timeline */}
          <div className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  Durable Evidence Timeline
                </h3>
                <p className="text-xs text-slate-400">Sequence of raw normalized detection events associated with this incident</p>
              </div>
              <span className="text-xs font-mono text-slate-400">{evidenceList.length} Events</span>
            </div>

            {evidenceList.length === 0 ? (
              <EmptyState
                title="No Evidence Events"
                description="No detection events are bound to this incident record."
              />
            ) : (
              <div className="space-y-3">
                {evidenceList.map((ev, i) => (
                  <div
                    key={ev.detection_event_id || i}
                    className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition space-y-2.5"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                          #{i + 1}
                        </span>
                        <span className="font-mono text-xs font-bold text-cyan-300">
                          {ev.detector_name || ev.detection_type}
                        </span>
                        <SeverityBadge severity={ev.severity} />
                        <OsBadge os={ev.os} />
                      </div>

                      <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                        <span>Confidence: <strong className="text-cyan-300">{(ev.confidence * 100).toFixed(0)}%</strong></span>
                        <span>•</span>
                        <span>{new Date(ev.timestamp).toLocaleString()}</span>
                        <button
                          onClick={() => setActiveJson({ title: `Evidence Event: ${ev.detection_event_id}`, data: ev })}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 flex items-center gap-1 text-[11px] transition"
                          title="View raw normalized event JSON"
                        >
                          <FileCode className="w-3.5 h-3.5" />
                          <span>JSON</span>
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono pt-2 border-t border-slate-800/60 text-slate-300">
                      <div>
                        <span className="text-slate-500 block text-[10px]">EVENT ID:</span>
                        <span className="text-slate-300 truncate block" title={ev.detection_event_id}>{ev.detection_event_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">AGENT / HOST:</span>
                        <span className="text-slate-300">{ev.agent_id} ({ev.hostname})</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">SOURCE EVENT ID:</span>
                        <span className="text-slate-300">{ev.source_event_id}</span>
                      </div>
                    </div>

                    {/* Evidence attributes preview */}
                    {ev.evidence && Object.keys(ev.evidence).length > 0 && (
                      <div className="p-2.5 rounded bg-black/40 border border-slate-800 text-[11px] font-mono text-emerald-400/90 overflow-x-auto">
                        <span className="text-slate-500 text-[10px] block mb-1">EVIDENCE PAYLOAD PREVIEW:</span>
                        <pre className="whitespace-pre-wrap break-all">{JSON.stringify(ev.evidence, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {/* JSON Viewer Modal */}
      <JsonModal
        isOpen={Boolean(activeJson)}
        onClose={() => setActiveJson(null)}
        title={activeJson?.title}
        data={activeJson?.data}
      />

      {/* Quick Containment Action Modal */}
      {quickActionModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-lg shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <h3 className="text-sm font-bold text-white">
                  Confirm Entity Containment Dispatch
                </h3>
              </div>
              <button
                onClick={() => setQuickActionModal(null)}
                className="text-slate-400 hover:text-white text-xs p-1"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleExecuteQuickAction} className="p-5 space-y-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-500">ACTION TYPE:</span>
                  <span className="text-rose-400 font-bold">{quickActionModal.type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">TARGET ENTITY:</span>
                  <span className="text-white font-bold">{quickActionModal.entityValue}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">TARGET ENDPOINT:</span>
                  <span className="text-cyan-300 truncate max-w-[200px]" title={quickActionModal.agentId}>
                    {quickActionModal.agentId}
                  </span>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1 text-[11px]">
                  Analyst Justification / Rationale
                </label>
                <input
                  type="text"
                  required
                  value={quickActionModal.reason}
                  onChange={(e) => setQuickActionModal({ ...quickActionModal, reason: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-rose-500 text-xs"
                />
              </div>

              {/* Simulation Mode Toggle */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="font-bold text-white block">Safe Simulation Mode</span>
                  <span className="text-[10px] text-slate-400">Agent logs verification command without OS mutation</span>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={quickActionModal.simulate}
                    onChange={(e) => setQuickActionModal({ ...quickActionModal, simulate: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-rose-600"></div>
                </label>
              </div>

              <div className="pt-2 flex items-center justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setQuickActionModal(null)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isDispatchingQuick}
                  className="px-4 py-1.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-bold rounded text-xs flex items-center gap-1.5 transition"
                >
                  <Send className="w-3.5 h-3.5" />
                  {isDispatchingQuick ? 'Dispatching...' : `Dispatch ${quickActionModal.type}`}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
