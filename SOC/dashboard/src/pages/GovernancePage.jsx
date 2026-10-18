import React, { useState, useEffect, useCallback } from 'react';
import { 
  Scale, ShieldCheck, ShieldAlert, History, Lock, 
  CheckCircle2, XCircle, RefreshCw, Terminal, AlertTriangle, 
  Zap, Check, X, Clock
} from 'lucide-react';
import { api } from '../api/client';
import { DecisionBadge, SeverityBadge, ApprovalStatusBadge, ActionBadge } from '../components/common/Badges';
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
  const [governanceStatus, setGovernanceStatus] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [overrideTestResult, setOverrideTestResult] = useState(null);
  const [activeJson, setActiveJson] = useState(null);

  // Approval / Rejection states
  const [isApproving, setIsApproving] = useState(false);
  const [isRejecting, setIsRejecting] = useState(false);
  const [approvalMessage, setApprovalMessage] = useState(null);
  const [isRejectionModalOpen, setIsRejectionModalOpen] = useState(false);
  const [rejectionReason, setRejectionReason] = useState(
    'Analyst determined recommended mitigation is not warranted for this incident.'
  );

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;

  const loadGovernanceData = useCallback(async (incidentId) => {
    setIsLoading(true);
    setError(null);
    setOverrideTestResult(null);
    setApprovalMessage(null);
    try {
      const [assRes, decRes, histRes, govRes] = await Promise.all([
        api.getIncidentAssessment(incidentId).catch(() => null),
        api.getIncidentDecision(incidentId).catch(() => null),
        api.getIncidentHistory(incidentId).catch(() => null),
        api.getIncidentGovernance(incidentId).catch(() => null),
      ]);
      setAssessment(assRes);
      setDecision(decRes);
      setHistory(histRes);
      setGovernanceStatus(govRes);
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

  // Handle mitigation approval (Human-in-the-Loop)
  const handleApproveMitigation = async (specificAction = null) => {
    if (!activeIncident) return;
    setIsApproving(true);
    setApprovalMessage(null);
    try {
      const res = await api.approveGovernanceMitigation(activeIncident.incident_id, {
        action: specificAction,
        analyst_name: 'Lead SOC Analyst',
        reason: specificAction 
          ? `Analyst approved specific action: ${specificAction}`
          : 'Analyst authorized recommended containment action via TGAM-SOC console.'
      });
      setApprovalMessage({
        type: 'success',
        text: `Mitigation approved! Dispatched ${res.dispatched_count ?? (res.dispatched_commands?.length || 0)} command(s) to endpoint agent.`
      });
      // Refresh status
      const updatedGov = await api.getIncidentGovernance(activeIncident.incident_id);
      setGovernanceStatus(updatedGov);
    } catch (err) {
      setApprovalMessage({
        type: 'error',
        text: err.message || 'Failed to approve mitigation.'
      });
    } finally {
      setIsApproving(false);
    }
  };

  // Handle mitigation rejection
  const handleRejectMitigation = async () => {
    if (!activeIncident) return;
    setIsRejecting(true);
    try {
      await api.rejectGovernanceMitigation(activeIncident.incident_id, {
        analyst_name: 'Lead SOC Analyst',
        reason: rejectionReason
      });
      setIsRejectionModalOpen(false);
      setApprovalMessage({
        type: 'info',
        text: 'Mitigation recommendation rejected and recorded in governance audit log.'
      });
      // Refresh status
      const updatedGov = await api.getIncidentGovernance(activeIncident.incident_id);
      setGovernanceStatus(updatedGov);
    } catch (err) {
      setApprovalMessage({
        type: 'error',
        text: err.message || 'Failed to reject mitigation.'
      });
    } finally {
      setIsRejecting(false);
    }
  };

  const handleTestOverrideRejection = async () => {
    if (!activeIncident) return;
    try {
      await api.submitOverrideAttempt(activeIncident.incident_id, 'FORCE_APPROVE', 'Analyst architectural constraint test');
      setOverrideTestResult({
        success: false,
        message: 'Unexpected: Backend accepted override (should be blocked by architecture).'
      });
    } catch (err) {
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
        description="Select an incident to review Trust/Risk scores, governance decisions, and mitigations."
      />
    );
  }

  const trustScore = assessment?.trust_score ?? null;
  const riskScore = assessment?.risk_score ?? null;
  const recommendations = governanceStatus?.recommendations || [];
  const dispatchedCommands = governanceStatus?.dispatched_commands || [];
  const approvalStatus = governanceStatus?.approval_status || 'NOT_REQUIRED';

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
                {inc.incident_id} ({inc.max_severity})
              </option>
            ))}
          </select>
          <button
            onClick={() => loadGovernanceData(activeIncident.incident_id)}
            title="Refresh Governance Data"
            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white rounded-lg border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <LoadingSkeleton count={3} type="card" />
        </div>
      ) : error ? (
        <ErrorState
          error={error}
          onRetry={() => loadGovernanceData(activeIncident.incident_id)}
          onOpenSettings={onOpenSettings}
        />
      ) : (
        <div className="space-y-6">
          {/* Trust Score & Risk Impact Score Overview */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Trust Evaluation Card */}
            <div className="p-6 rounded-xl bg-soc-card border border-soc-border shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-white">Trust Assessment</h3>
                </div>
                {trustScore !== null && (
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                    Formula {assessment.formula_version || 'v1.0'}
                  </span>
                )}
              </div>

              {trustScore !== null ? (
                <div className="space-y-4">
                  <div className="flex items-baseline justify-between">
                    <span className="text-xs font-mono text-slate-400">Calculated Confidence:</span>
                    <span className="text-2xl font-mono font-bold text-emerald-400">
                      {(trustScore * 100).toFixed(1)}%
                    </span>
                  </div>

                  <div className="w-full h-3 rounded-full bg-slate-900 border border-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-teal-500 to-emerald-400 rounded-full transition-all duration-500"
                      style={{ width: `${Math.min(Math.max(trustScore * 100, 0), 100)}%` }}
                    />
                  </div>

                  {assessment.trust_explanation && (
                    <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-xs text-emerald-200">
                      <span className="font-semibold block mb-0.5">Trust Evidence Basis:</span>
                      <p>{assessment.trust_explanation}</p>
                    </div>
                  )}
                </div>
              ) : (
                <EmptyState
                  title="Trust Score Not Calculated"
                  description="Assessment worker has not yet processed trust score for this incident."
                />
              )}
            </div>

            {/* Risk Impact Card */}
            <div className="p-6 rounded-xl bg-soc-card border border-soc-border shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                  <h3 className="text-sm font-semibold text-white">Risk Evaluation</h3>
                </div>
                {riskScore !== null && (
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40">
                    Formula {assessment.formula_version || 'v1.0'}
                  </span>
                )}
              </div>

              {riskScore !== null ? (
                <div className="space-y-4">
                  <div className="flex items-baseline justify-between">
                    <span className="text-xs font-mono text-slate-400">Assessed Threat Risk:</span>
                    <span className="text-2xl font-mono font-bold text-rose-400">
                      {(riskScore * 100).toFixed(1)}%
                    </span>
                  </div>

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

          {/* Authoritative Governance Decision Card */}
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

          {/* ========================================================================= */}
          {/* STEP 3: GOVERNED ENDPOINT MITIGATION & HUMAN-IN-THE-LOOP CONTROL PANEL   */}
          {/* ========================================================================= */}
          <div className="p-6 rounded-xl bg-gradient-to-b from-slate-900/90 to-soc-card border border-slate-800 shadow-2xl space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-800/40 text-cyan-400">
                  <Zap className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    Automated & Governed Mitigation
                  </h3>
                  <p className="text-xs text-slate-400">
                    Endpoint containment dispatch governed by trust policy & human authorization
                  </p>
                </div>
              </div>
              <ApprovalStatusBadge status={approvalStatus} />
            </div>

            {/* Notification alert banner */}
            {approvalMessage && (
              <div className={`p-3 rounded-lg border text-xs font-mono flex items-center gap-2 ${
                approvalMessage.type === 'success' 
                  ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300' 
                  : approvalMessage.type === 'info'
                  ? 'bg-blue-950/40 border-blue-800 text-blue-300'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}>
                {approvalMessage.type === 'success' ? <Check className="w-4 h-4 shrink-0" /> : <AlertTriangle className="w-4 h-4 shrink-0" />}
                <span>{approvalMessage.text}</span>
              </div>
            )}

            {/* Human Approval Required Action Box */}
            {approvalStatus === 'PENDING' && (
              <div className="p-5 rounded-xl bg-amber-950/20 border border-amber-600/40 space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <Clock className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-sm font-semibold text-amber-300">
                        Human-in-the-Loop Authorization Required
                      </h4>
                      <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">
                        Governance policy classified this incident as requiring mandatory human review before mitigation execution.
                        Review recommended actions below and confirm containment dispatch.
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleApproveMitigation(null)}
                      disabled={isApproving || isRejecting}
                      className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 disabled:opacity-50 text-white font-mono text-xs font-bold rounded-lg shadow-lg shadow-emerald-950/50 flex items-center gap-2 transition"
                    >
                      <Check className="w-4 h-4" />
                      {isApproving ? 'Dispatching...' : 'Approve & Execute All'}
                    </button>
                    <button
                      onClick={() => setIsRejectionModalOpen(true)}
                      disabled={isApproving || isRejecting}
                      className="px-3 py-2 bg-slate-900 hover:bg-rose-950/50 text-rose-300 border border-rose-800/60 disabled:opacity-50 font-mono text-xs font-semibold rounded-lg flex items-center gap-1.5 transition"
                    >
                      <X className="w-4 h-4" />
                      Reject
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Approved / Auto-Approved notification */}
            {approvalStatus === 'APPROVED' && (
              <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-600/30 flex items-center gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                <div className="text-xs font-mono text-emerald-200">
                  <span className="font-bold text-white block">Mitigation Approved by Analyst</span>
                  Commands have been submitted to endpoint queues and are actively executing via agent heartbeats.
                </div>
              </div>
            )}

            {approvalStatus === 'AUTO_APPROVED' && (
              <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-600/30 flex items-center gap-3">
                <Zap className="w-5 h-5 text-cyan-400 shrink-0" />
                <div className="text-xs font-mono text-cyan-200">
                  <span className="font-bold text-white block">Autonomous Execution (Zero Latency)</span>
                  High trust / low risk threshold satisfied. Commands were automatically dispatched to endpoints without delay.
                </div>
              </div>
            )}

            {approvalStatus === 'REJECTED' && (
              <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-600/30 flex items-center gap-3">
                <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
                <div className="text-xs font-mono text-rose-200">
                  <span className="font-bold text-white block">Mitigation Rejected</span>
                  The analyst rejected automated mitigation. No containment actions were dispatched to endpoints.
                </div>
              </div>
            )}

            {/* Recommended Containment Actions List */}
            <div className="space-y-3">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                Recommended Containment Strategies ({recommendations.length})
              </span>

              {recommendations.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {recommendations.map((rec, idx) => {
                    const actionType = rec.type || rec.action || 'CONTAINMENT';
                    return (
                      <div key={idx} className="p-4 rounded-lg bg-slate-900/70 border border-slate-800 space-y-2.5">
                        <div className="flex items-center justify-between">
                          <ActionBadge action={actionType} />
                          {approvalStatus === 'PENDING' && (
                            <button
                              onClick={() => handleApproveMitigation(actionType)}
                              disabled={isApproving}
                              className="px-2 py-1 text-[11px] font-mono text-emerald-300 hover:text-white bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-800/60 rounded transition flex items-center gap-1"
                            >
                              <Check className="w-3 h-3" />
                              Approve Only
                            </button>
                          )}
                        </div>
                        <p className="text-xs text-slate-300 font-mono leading-relaxed">
                          {rec.reason || 'No description provided'}
                        </p>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800 text-xs text-slate-400 font-mono">
                  No explicit mitigation strategies generated by reasoning synthesis for this case.
                </div>
              )}
            </div>

            {/* Live Endpoint Commands Execution Audit Trail */}
            <div className="space-y-3 pt-3 border-t border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  Dispatched Endpoint Commands ({dispatchedCommands.length})
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  Target Endpoint Delivery via Heartbeat
                </span>
              </div>

              {dispatchedCommands.length > 0 ? (
                <div className="overflow-x-auto rounded-lg border border-slate-800">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Command ID</th>
                        <th className="py-2.5 px-3">Type</th>
                        <th className="py-2.5 px-3">Target Agent</th>
                        <th className="py-2.5 px-3">Parameters</th>
                        <th className="py-2.5 px-3">Status</th>
                        <th className="py-2.5 px-3 text-right">Result</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
                      {dispatchedCommands.map((cmd) => {
                        const statusColor = 
                          cmd.status === 'EXECUTED' 
                            ? 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60'
                            : cmd.status === 'FAILED'
                            ? 'text-rose-400 bg-rose-950/60 border-rose-800/60'
                            : 'text-amber-400 bg-amber-950/60 border-amber-800/60 animate-pulse';

                        return (
                          <tr key={cmd.command_id} className="hover:bg-slate-800/40 transition">
                            <td className="py-2 px-3 text-slate-300 truncate max-w-[120px]" title={cmd.command_id}>
                              {cmd.command_id.slice(0, 8)}...
                            </td>
                            <td className="py-2 px-3">
                              <ActionBadge action={cmd.command_type} />
                            </td>
                            <td className="py-2 px-3 text-slate-400 truncate max-w-[120px]" title={cmd.agent_id}>
                              {cmd.agent_id.slice(0, 10)}...
                            </td>
                            <td className="py-2 px-3 text-slate-300 truncate max-w-[160px]">
                              {typeof cmd.parameters === 'object' ? JSON.stringify(cmd.parameters) : cmd.parameters}
                            </td>
                            <td className="py-2 px-3">
                              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${statusColor}`}>
                                <span className="w-1.5 h-1.5 rounded-full bg-current" />
                                {cmd.status}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-right">
                              <button
                                onClick={() => setActiveJson({
                                  title: `Command: ${cmd.command_type} (${cmd.command_id})`,
                                  data: {
                                    command_id: cmd.command_id,
                                    agent_id: cmd.agent_id,
                                    command_type: cmd.command_type,
                                    status: cmd.status,
                                    parameters: cmd.parameters,
                                    result: cmd.result,
                                    created_at: cmd.created_at,
                                    updated_at: cmd.updated_at
                                  }
                                })}
                                className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[10px] transition"
                              >
                                View
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-slate-900/30 border border-slate-800 text-xs text-slate-500 font-mono text-center">
                  No remote commands have been dispatched for this incident yet.
                </div>
              )}
            </div>
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

      {/* Rejection Prompt Modal */}
      {isRejectionModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-lg p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <XCircle className="w-4 h-4 text-rose-400" />
                Reject Mitigation Recommendation
              </h3>
              <button
                onClick={() => setIsRejectionModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed font-mono">
              Provide an official analyst rationale for rejecting the recommended mitigation.
              This decision will be immutably recorded in the governance audit trail.
            </p>

            <textarea
              value={rejectionReason}
              onChange={(e) => setRejectionReason(e.target.value)}
              rows={3}
              className="w-full p-2.5 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              placeholder="Enter rationale for rejecting mitigation..."
            />

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setIsRejectionModalOpen(false)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleRejectMitigation}
                disabled={isRejecting || !rejectionReason.trim()}
                className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-xs font-mono text-white font-bold rounded-lg transition"
              >
                {isRejecting ? 'Rejecting...' : 'Confirm Rejection'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* JSON Modal for raw data inspection */}
      <JsonModal
        isOpen={Boolean(activeJson)}
        onClose={() => setActiveJson(null)}
        title={activeJson?.title}
        data={activeJson?.data}
      />
    </div>
  );
}
