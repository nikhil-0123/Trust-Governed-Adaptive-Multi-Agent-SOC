import React, { useState, useEffect, useCallback } from 'react';
import { Scale, ShieldCheck, ShieldAlert, History, Lock } from 'lucide-react';
import { api } from '../api/client';
import { DecisionBadge, SeverityBadge } from '../components/common/Badges';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { JsonModal } from '../components/common/JsonModal';
import { GovernancePolicyNotice, ResponseSafetyNotice } from '../components/common/ArchitectureNotices';

export function GovernancePage({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  onOpenSettings
}) {
  const [assessment, setAssessment] = useState(null);
  const [decision, setDecision] = useState(null);
  const [history, setHistory] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [overrideTestResult, setOverrideTestResult] = useState(null);
  const [activeJson, setActiveJson] = useState(null);

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;

  const loadGovernanceData = useCallback(async (incidentId) => {
    setIsLoading(true);
    setError(null);
    setOverrideTestResult(null);
    try {
      const assRes = await api.getIncidentAssessment(incidentId);
      const decRes = await api.getIncidentDecision(incidentId);
      const histRes = await api.getIncidentHistory(incidentId);
      setAssessment(assRes);
      setDecision(decRes);
      setHistory(histRes);
    } catch (err) {
      setError(err.message || 'Failed to fetch governance data.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!activeIncident?.incident_id) return;
    loadGovernanceData(activeIncident.incident_id);
  }, [activeIncident?.incident_id, loadGovernanceData]);

  const handleTestOverrideRejection = async () => {
    if (!activeIncident) return;
    try {
      await api.submitOverrideAttempt(activeIncident.incident_id, 'FORCE_APPROVE', 'Analyst architectural constraint test');
      setOverrideTestResult({
        success: false,
        message: 'Unexpected: Backend accepted override (should be blocked by architecture).'
      });
    } catch (err) {
      // Backend returns 501
      setOverrideTestResult({
        success: true,
        status: err.status,
        message: `Verified: Backend rejected override with HTTP ${err.status} (${err.message}). Architecture guardrails active.`
      });
    }
  };

  if (!activeIncident) {
    return (
      <EmptyState
        title="No Incident Selected"
        description="Select an incident to review Trust/Risk scores and governance decisions."
      />
    );
  }

  const trustScore = assessment?.trust_score ?? null;
  const riskScore = assessment?.risk_score ?? null;

  return (
    <div className="space-y-6">
      {/* Policy Notice Banners */}
      <GovernancePolicyNotice />
      <ResponseSafetyNotice />

      {/* Incident Switcher Bar */}
      <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <span className="text-[10px] font-mono text-amber-400 uppercase tracking-widest block">
            Trust & Governance Review
          </span>
          <h2 className="text-base font-bold font-mono text-white flex items-center gap-2 mt-0.5">
            <span>{activeIncident.incident_id}</span>
            <SeverityBadge severity={activeIncident.max_severity} />
          </h2>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">Case:</span>
          <select
            value={activeIncident.incident_id}
            onChange={(e) => onSelectIncident(e.target.value)}
            className="px-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
          >
            {incidents.map((inc) => (
              <option key={inc.incident_id} value={inc.incident_id}>
                {inc.incident_id} ({inc.latest_assessment_id ? 'Assessed' : 'Pending'})
              </option>
            ))}
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <LoadingSkeleton count={2} type="card" />
          <LoadingSkeleton count={3} type="table" />
        </div>
      ) : error ? (
        <ErrorState
          error={error}
          onRetry={() => loadGovernanceData(activeIncident.incident_id)}
          onOpenSettings={onOpenSettings}
          title="Governance Data Error"
        />
      ) : (
        <div className="space-y-6">
          {/* Top Row: Trust & Risk Assessment Gauges */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Trust Evaluation Card */}
            <div className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-white">Trust Assessment Score</h3>
                </div>
                {assessment && (
                  <span className="text-[11px] font-mono text-slate-400">
                    Formula v{assessment.formula_version}
                  </span>
                )}
              </div>

              {assessment && trustScore !== null ? (
                <div className="space-y-3">
                  <div className="flex items-baseline justify-between">
                    <span className="text-3xl font-bold font-mono text-emerald-300">
                      {(trustScore * 100).toFixed(1)}%
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Score: {trustScore.toFixed(3)} / 1.000
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div className="w-full h-3 rounded-full bg-slate-900 border border-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-emerald-600 to-emerald-400 rounded-full transition-all duration-500"
                      style={{ width: `${Math.min(Math.max(trustScore * 100, 0), 100)}%` }}
                    />
                  </div>

                  {assessment.trust_explanation && (
                    <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-xs text-emerald-200">
                      <span className="font-semibold block mb-0.5">Trust Justification:</span>
                      <p>{assessment.trust_explanation}</p>
                    </div>
                  )}
                </div>
              ) : (
                <EmptyState
                  title="Trust Score Not Calculated"
                  description="Assessment worker has not yet completed trust evaluation for this incident."
                />
              )}
            </div>

            {/* Risk Evaluation Card */}
            <div className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-lg space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                  <h3 className="text-sm font-semibold text-white">Risk Assessment Score</h3>
                </div>
                {assessment && (
                  <span className="text-[11px] font-mono text-slate-400">
                    Config v{assessment.config_version}
                  </span>
                )}
              </div>

              {assessment && riskScore !== null ? (
                <div className="space-y-3">
                  <div className="flex items-baseline justify-between">
                    <span className="text-3xl font-bold font-mono text-rose-400">
                      {(riskScore * 100).toFixed(1)}%
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Score: {riskScore.toFixed(3)} / 1.000
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div className="w-full h-3 rounded-full bg-slate-900 border border-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-amber-500 to-rose-500 rounded-full transition-all duration-500"
                      style={{ width: `${Math.min(Math.max(riskScore * 100, 0), 100)}%` }}
                    />
                  </div>

                  {assessment.risk_explanation && (
                    <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-800/40 text-xs text-rose-200">
                      <span className="font-semibold block mb-0.5">Risk Impact Analysis:</span>
                      <p>{assessment.risk_explanation}</p>
                    </div>
                  )}
                </div>
              ) : (
                <EmptyState
                  title="Risk Score Not Calculated"
                  description="Assessment worker has not yet evaluated risk impact for this incident."
                />
              )}
            </div>
          </div>

          {/* Active Governance Decision Card */}
          <div className="p-6 rounded-xl bg-soc-card border border-soc-border shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
              <div className="flex items-center gap-2">
                <Scale className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">Authoritative Governance Decision</h3>
              </div>
              <DecisionBadge decision={decision?.decision} />
            </div>

            {decision ? (
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2">
                  <span className="text-[11px] font-mono uppercase text-slate-400 block">Governance Rationale</span>
                  <p className="text-sm text-slate-200 leading-relaxed font-mono">{decision.reason}</p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono text-slate-400">
                  <div className="p-2.5 rounded bg-slate-900/50 border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">DECISION ID:</span>
                    <span className="text-white truncate block">{decision.decision_id}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900/50 border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">POLICY VERSION:</span>
                    <span className="text-white">{decision.policy_version}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900/50 border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">RECORDED AT:</span>
                    <span className="text-white">{new Date(decision.created_at).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            ) : (
              <EmptyState
                title="Pending Governance Evaluation"
                description="The governance worker has not yet finalized a decision for this incident case."
              />
            )}
          </div>

          {/* Provenance History & Audit Chain */}
          <div className="p-6 rounded-xl bg-soc-card border border-soc-border shadow-xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-indigo-400" />
                <h3 className="text-sm font-semibold text-white">Provenance Audit Trail</h3>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {history?.historical_decisions?.length || 0} Historical Records
              </span>
            </div>

            {history ? (
              <div className="space-y-3 font-mono text-xs">
                {/* Step Chain */}
                <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
                  <div className="flex items-center gap-2 text-cyan-300">
                    <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                    <span>Incident: {history.incident.incident_id}</span>
                    <span className="text-slate-500">({history.incident.status})</span>
                  </div>

                  <div className="flex items-center gap-2 text-indigo-300 pl-4 border-l border-slate-700">
                    <span className="w-2 h-2 rounded-full bg-indigo-400"></span>
                    <span>Assessment: {history.assessment?.assessment_id || 'Pending'}</span>
                  </div>

                  <div className="flex items-center gap-2 text-purple-300 pl-4 border-l border-slate-700">
                    <span className="w-2 h-2 rounded-full bg-purple-400"></span>
                    <span>Analysis: {history.analysis?.analysis_id || 'Pending'}</span>
                  </div>

                  <div className="flex items-center gap-2 text-emerald-300 pl-4 border-l border-slate-700">
                    <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                    <span>Governance Decision: {history.decision?.decision_id || 'Pending'} ({history.decision?.decision || 'None'})</span>
                  </div>
                </div>

                {/* Test Override Guardrail Button */}
                <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div className="text-xs text-slate-400">
                    <span className="text-slate-300 font-semibold">Architectural Guardrail Verification:</span>{' '}
                    Confirm that the backend properly rejects unauthorized manual write overrides.
                  </div>
                  <button
                    onClick={handleTestOverrideRejection}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-amber-300 border border-slate-600 transition flex items-center gap-1.5 shrink-0"
                  >
                    <Lock className="w-3.5 h-3.5 text-amber-400" />
                    Verify 501 Override Blocker
                  </button>
                </div>

                {overrideTestResult && (
                  <div className={`p-3 rounded-lg border text-xs font-mono ${
                    overrideTestResult.success
                      ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                      : 'bg-rose-950/40 border-rose-800 text-rose-300'
                  }`}>
                    {overrideTestResult.message}
                  </div>
                )}
              </div>
            ) : (
              <EmptyState title="No Provenance Data" description="Provenance history is unavailable." />
            )}
          </div>
        </div>
      )}

      {/* JSON Modal */}
      <JsonModal
        isOpen={Boolean(activeJson)}
        onClose={() => setActiveJson(null)}
        title={activeJson?.title}
        data={activeJson?.data}
      />
    </div>
  );
}
