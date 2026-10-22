import React from 'react';
import { AlertOctagon, ShieldCheck, AlertTriangle, Activity, ArrowRight, ExternalLink, Shield, Zap, Clock, CheckCircle2 } from 'lucide-react';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge, StatusBadge } from '../components/common/Badges';
import { SeverityPieChart } from '../components/charts/SeverityPieChart';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { ResponseSafetyNotice } from '../components/common/ArchitectureNotices';

export function OverviewPage({
  incidents,
  isLoading,
  error,
  onRetry,
  onOpenSettings,
  onSelectIncident,
  onNavigate
}) {
  if (isLoading) {
    return (
      <div className="space-y-6">
        <LoadingSkeleton count={4} type="card" />
        <LoadingSkeleton count={3} type="table" />
      </div>
    );
  }

  if (error) {
    return <ErrorState error={error} onRetry={onRetry} onOpenSettings={onOpenSettings} title="SOC Overview Unavailable" />;
  }

  // Calculate real metrics from database incidents
  const totalCount = incidents.length;
  const criticalCount = incidents.filter(i => (i.max_severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = incidents.filter(i => (i.max_severity || '').toUpperCase() === 'HIGH').length;
  const openCount = incidents.filter(i => (i.status || '').toUpperCase() === 'OPEN').length;
  const assessedCount = incidents.filter(i => Boolean(i.latest_assessment_id)).length;
  const analyzedCount = incidents.filter(i => Boolean(i.latest_analysis_id)).length;
  const autoMitigatedCount = incidents.filter(i => (i.approval_status || '').toUpperCase() === 'AUTO_APPROVED').length;
  const pendingHumanCount = incidents.filter(i => (i.approval_status || '').toUpperCase() === 'PENDING').length;

  const recentIncidents = [...incidents].slice(0, 6);

  return (
    <div className="space-y-6">
      {/* Top Banner Notice */}
      <ResponseSafetyNotice />

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard
          title="Total Incidents"
          value={totalCount}
          subtitle="Fused from endpoint events"
          icon={AlertOctagon}
          color="cyan"
        />
        <MetricCard
          title="Critical Alerts"
          value={criticalCount}
          subtitle="Immediate priority events"
          icon={AlertTriangle}
          color="rose"
        />
        <MetricCard
          title="Open / Active"
          value={openCount}
          subtitle="Incidents requiring SOC triage"
          icon={Activity}
          color="amber"
        />
        <MetricCard
          title="AI Evaluated"
          value={`${analyzedCount} / ${totalCount}`}
          subtitle={`${assessedCount} assessed with Trust/Risk`}
          icon={ShieldCheck}
          color="emerald"
        />
        <MetricCard
          title="Autonomous Mitigations"
          value={autoMitigatedCount}
          subtitle={`${pendingHumanCount} awaiting human review`}
          icon={Zap}
          color="cyan"
        />
      </div>

      {/* Two Column Grid: Charts and Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Chart */}
        <div className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Severity Distribution
            </h3>
            <span className="text-xs text-slate-400 font-mono">{totalCount} Total</span>
          </div>

          <div className="flex-1 flex items-center justify-center pt-2">
            <SeverityPieChart incidents={incidents} />
          </div>

          <div className="grid grid-cols-2 gap-2 pt-3 border-t border-slate-800 text-xs font-mono">
            <div className="flex items-center justify-between px-2.5 py-1.5 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-rose-400">Critical:</span>
              <span className="text-white font-bold">{criticalCount}</span>
            </div>
            <div className="flex items-center justify-between px-2.5 py-1.5 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-amber-400">High:</span>
              <span className="text-white font-bold">{highCount}</span>
            </div>
          </div>
        </div>

        {/* Recent Alerts Feed */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Recent Incidents Stream
              </h3>
              <p className="text-xs text-slate-400">Chronological feed of correlated detection incidents</p>
            </div>
            <button
              onClick={() => onNavigate('incidents')}
              className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium transition"
            >
              <span>View All</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="mt-4 flex-1">
            {recentIncidents.length === 0 ? (
              <EmptyState
                title="No Incidents Ingested"
                description="The central SOC backend currently contains no correlated incidents. Deploy endpoints or ingest test events."
              />
            ) : (
              <div className="divide-y divide-slate-800/80">
                {recentIncidents.map((inc) => (
                  <div
                    key={inc.incident_id}
                    onClick={() => {
                      onSelectIncident(inc.incident_id);
                      onNavigate('investigation');
                    }}
                    className="py-3 px-2 flex items-center justify-between hover:bg-slate-800/40 rounded-lg cursor-pointer transition group"
                  >
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-cyan-300 group-hover:text-cyan-200">
                          {inc.incident_id}
                        </span>
                        <SeverityBadge severity={inc.max_severity} />
                        <StatusBadge status={inc.status} />

                        {inc.approval_status === 'AUTO_APPROVED' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/50 shadow-sm shadow-cyan-500/20">
                            <Zap className="w-3 h-3 text-cyan-400" />
                            <span>⚡ AUTO-MITIGATED{inc.dispatched_command_types?.length ? `: ${inc.dispatched_command_types[0]}` : ''}</span>
                          </span>
                        ) : inc.approval_status === 'PENDING' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-500/50 shadow-sm shadow-amber-500/20 animate-pulse">
                            <Clock className="w-3 h-3 text-amber-400" />
                            <span>⏳ PENDING HUMAN REVIEW</span>
                          </span>
                        ) : inc.approval_status === 'APPROVED' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-500/50">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            <span>✓ ANALYST MITIGATED</span>
                          </span>
                        ) : null}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono flex items-center gap-3">
                        <span>First: {new Date(inc.first_seen).toLocaleString()}</span>
                        <span>•</span>
                        <span>Last: {new Date(inc.last_seen).toLocaleString()}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-right hidden sm:block">
                        <span className="text-[11px] font-mono text-slate-400 block">
                          {inc.latest_analysis_id ? 'AI Analyzed' : inc.latest_assessment_id ? 'Risk Assessed' : 'Correlated'}
                        </span>
                      </div>
                      <ExternalLink className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition" />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
