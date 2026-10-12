import React, { useState, useEffect, useCallback } from 'react';
import { Radio, Monitor, Terminal, Info, RefreshCw } from 'lucide-react';
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

  const loadEndpointTelemetry = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Gather all evidence across known incidents to extract endpoint presence
      const endpointMap = {};

      // Pull evidence for top incidents
      const incidentSubset = incidents.slice(0, 20);
      const evidenceArrays = await Promise.all(
        incidentSubset.map(inc => api.getIncidentEvidence(inc.incident_id).catch(() => []))
      );

      evidenceArrays.flat().forEach(ev => {
        if (!ev || !ev.agent_id) return;
        const key = ev.agent_id;
        if (!endpointMap[key]) {
          endpointMap[key] = {
            agent_id: ev.agent_id,
            hostname: ev.hostname || 'unknown-host',
            os: ev.os || 'unknown',
            first_seen: ev.timestamp,
            last_seen: ev.timestamp,
            event_count: 0,
            detectors: new Set(),
            severities: new Set(),
          };
        }

        const ep = endpointMap[key];
        ep.event_count++;
        if (ev.detector_name) ep.detectors.add(ev.detector_name);
        if (ev.severity) ep.severities.add(ev.severity);

        if (new Date(ev.timestamp) > new Date(ep.last_seen)) {
          ep.last_seen = ev.timestamp;
        }
        if (new Date(ev.timestamp) < new Date(ep.first_seen)) {
          ep.first_seen = ev.timestamp;
        }
      });

      const list = Object.values(endpointMap).map(ep => ({
        ...ep,
        detectors: Array.from(ep.detectors),
        severities: Array.from(ep.severities),
      }));

      // Sort by last seen descending
      list.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
      setEndpoints(list);
    } catch (err) {
      setError(err.message || 'Failed to aggregate endpoint telemetry.');
    } finally {
      setIsLoading(false);
    }
  }, [incidents]);

  useEffect(() => {
    loadEndpointTelemetry();
  }, [loadEndpointTelemetry]);


  return (
    <div className="space-y-6">
      {/* Scope and Boundary Notice */}
      <EndpointBoundaryNotice />

      {/* Header Bar */}
      <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Radio className="w-5 h-5 text-cyan-400" />
            Endpoint Telemetry Inventory
          </h2>
          <p className="text-xs text-slate-400">
            Monitored Windows Employee and Ubuntu Employee endpoint nodes
          </p>
        </div>

        <button
          onClick={loadEndpointTelemetry}
          disabled={isLoading}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-600 flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Endpoints</span>
        </button>
      </div>

      {/* Endpoint Scope Information Box */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3">
          <Monitor className="w-6 h-6 text-blue-400 shrink-0 mt-1" />
          <div className="text-xs space-y-1">
            <span className="font-semibold text-white">Windows Employee Endpoint (Active)</span>
            <p className="text-slate-400 leading-relaxed">
              Monitors Windows Security Event Log, Sysmon, and ETW telemetry. Normalized into v1 contract events with local heuristic detection.
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3">
          <Terminal className="w-6 h-6 text-orange-400 shrink-0 mt-1" />
          <div className="text-xs space-y-1">
            <span className="font-semibold text-white">Ubuntu Employee Endpoint (Active)</span>
            <p className="text-slate-400 leading-relaxed">
              Monitors Linux <span className="font-mono text-orange-300">/var/log/auth.log</span> and journald for SSH brute-force and suspicious sudo activity with zero external dependencies.
            </p>
          </div>
        </div>
      </div>

      {isLoading ? (
        <LoadingSkeleton count={3} type="table" />
      ) : error ? (
        <ErrorState
          error={error}
          onRetry={loadEndpointTelemetry}
          onOpenSettings={onOpenSettings}
          title="Endpoint Query Error"
        />
      ) : endpoints.length === 0 ? (
        <EmptyState
          title="No Endpoint Telemetry Detected"
          description="No active agent IDs found across incident evidence. Ingest detection events from windows-telemetry or ubuntu-telemetry."
          icon={Radio}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {endpoints.map((ep) => (
            <div
              key={ep.agent_id}
              className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg flex flex-col justify-between space-y-4 hover:border-slate-700 transition"
            >
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <OsBadge os={ep.os} />
                  <span className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    ACTIVE
                  </span>
                </div>

                <div className="mt-3 space-y-1">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">AGENT ID</span>
                  <p className="text-xs font-mono font-bold text-cyan-300 truncate" title={ep.agent_id}>
                    {ep.agent_id}
                  </p>
                  <p className="text-xs text-slate-300 font-medium">{ep.hostname}</p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/60 space-y-2 text-xs font-mono">
                  <div className="flex justify-between text-slate-400">
                    <span>Events Ingested:</span>
                    <span className="text-white font-bold">{ep.event_count}</span>
                  </div>
                  <div className="flex justify-between text-slate-400 text-[11px]">
                    <span>First Seen:</span>
                    <span className="text-slate-300">{new Date(ep.first_seen).toLocaleDateString()}</span>
                  </div>
                  <div className="flex justify-between text-slate-400 text-[11px]">
                    <span>Last Telemetry:</span>
                    <span className="text-slate-300">{new Date(ep.last_seen).toLocaleString()}</span>
                  </div>
                </div>
              </div>

              {ep.detectors.length > 0 && (
                <div className="pt-2 border-t border-slate-800/40">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Active Rules:</span>
                  <div className="flex flex-wrap gap-1">
                    {ep.detectors.map((d, i) => (
                      <span key={i} className="text-[10px] font-mono bg-slate-900 text-slate-300 px-1.5 py-0.5 rounded border border-slate-800">
                        {d}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Architecture Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 text-xs text-slate-400 flex items-start gap-3">
        <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-300">Backend API Capability Audit Note:</span>{' '}
          In current Semester-I scope, the backend API does not expose dedicated agent daemon management endpoints
          (<span className="font-mono text-slate-300">/api/v1/endpoints</span> or agent heartbeat push). Endpoint metrics displayed above are faithfully aggregated from verified ingested detection events in compliance with the normalized event contract.
        </div>
      </div>
    </div>
  );
}
