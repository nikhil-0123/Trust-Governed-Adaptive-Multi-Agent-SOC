import React from 'react';
import { ShieldAlert, Lock, Radio } from 'lucide-react';

export function GovernancePolicyNotice() {
  return (
    <div className="flex items-start gap-3 p-3.5 rounded-lg bg-amber-950/20 border border-amber-800/40 text-amber-200/90 text-xs mb-4">
      <Lock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
      <div>
        <span className="font-semibold text-amber-300">Append-Only Governance Policy:</span>{' '}
        Decisions are strictly immutable. Analyst overrides are not accepted by the current backend architecture
        (<span className="font-mono text-amber-400">HTTP 501 Not Implemented</span>). All historical decisions remain preserved in the audit log.
      </div>
    </div>
  );
}

export function ResponseSafetyNotice() {
  return (
    <div className="flex items-start gap-3 p-3.5 rounded-lg bg-blue-950/20 border border-blue-800/40 text-blue-200/90 text-xs mb-4">
      <ShieldAlert className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
      <div>
        <span className="font-semibold text-blue-300">Response Execution Safety:</span>{' '}
        Autonomous endpoint response execution is disabled in this phase. A recorded governance decision denotes an approved policy state, not an automatically dispatched remediation command.
      </div>
    </div>
  );
}

export function EndpointBoundaryNotice() {
  return (
    <div className="flex items-start gap-3 p-3.5 rounded-lg bg-slate-900/60 border border-slate-700/60 text-slate-300 text-xs mb-4">
      <Radio className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
      <div>
        <span className="font-semibold text-cyan-300">Endpoint Telemetry Scope:</span>{' '}
        Endpoint statuses and telemetry activity are derived from ingested detection evidence. Direct push-daemon telemetry querying and Ubuntu Server Telemetry are scheduled for future project phases.
      </div>
    </div>
  );
}
