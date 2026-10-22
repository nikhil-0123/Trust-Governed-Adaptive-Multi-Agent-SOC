import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  BrainCircuit,
  Sparkles,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  FileCode,
  Search,
  ChevronDown,
  ChevronRight,
  Layers,
  HelpCircle,
  Check,
  Copy,
  Zap,
  Activity,
  Workflow
} from 'lucide-react';
import { api } from '../api/client';
import { StatusBadge, SeverityBadge } from '../components/common/Badges';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { JsonModal } from '../components/common/JsonModal';

export function AnalysisPage({
  incidents = [],
  selectedIncidentId,
  onSelectIncident,
  onOpenSettings
}) {
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isJsonOpen, setIsJsonOpen] = useState(false);
  const [claimTab, setClaimTab] = useState('all'); // 'all' | 'verified' | 'rejected'
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedClaimIds, setExpandedClaimIds] = useState(new Set());
  const [copiedId, setCopiedId] = useState(null);

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;

  const loadAnalysis = useCallback(async (incidentId) => {
    if (!incidentId) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.getIncidentAnalysis(incidentId);
      setAnalysis(res);
    } catch (err) {
      setError(err.message || 'Failed to fetch multi-agent analysis.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!activeIncident?.incident_id) return;
    loadAnalysis(activeIncident.incident_id);
  }, [activeIncident?.incident_id, loadAnalysis]);

  const toggleClaimExpand = (claimId) => {
    setExpandedClaimIds(prev => {
      const next = new Set(prev);
      if (next.has(claimId)) next.delete(claimId);
      else next.add(claimId);
      return next;
    });
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Parse structured analysis output if formatted as JSON
  const parsedOutput = useMemo(() => {
    if (!analysis?.analysis_output) return null;
    try {
      return typeof analysis.analysis_output === 'string'
        ? JSON.parse(analysis.analysis_output)
        : analysis.analysis_output;
    } catch {
      return null;
    }
  }, [analysis?.analysis_output]);

  // Derived collections
  const verifiedClaims = parsedOutput?.verified_claims || [];
  const rejectedClaims = parsedOutput?.rejected_claims || [];
  const unsupportedClaims = parsedOutput?.unsupported_claims || [];
  const allCandidateClaims = useMemo(() => [
    ...verifiedClaims.map(c => ({ ...c, _status: 'VERIFIED' })),
    ...rejectedClaims.map(c => ({ ...c, _status: 'REJECTED' })),
    ...unsupportedClaims.map(c => ({ ...c, _status: 'UNSUPPORTED' }))
  ], [verifiedClaims, rejectedClaims, unsupportedClaims]);

  const verificationResults = parsedOutput?.verification_results || [];
  const recommendations = parsedOutput?.recommendations || [];
  const uncertainty = parsedOutput?.uncertainty || null;
  const assessmentSnapshot = parsedOutput?.assessment_snapshot || null;

  // Filtered claims based on tab and search
  const filteredClaims = useMemo(() => {
    let list = allCandidateClaims;
    if (claimTab === 'verified') list = list.filter(c => c._status === 'VERIFIED');
    else if (claimTab === 'rejected') list = list.filter(c => c._status !== 'VERIFIED');

    if (!searchQuery.trim()) return list;
    const q = searchQuery.toLowerCase();
    return list.filter(c =>
      (c.statement && c.statement.toLowerCase().includes(q)) ||
      (c.claim_type && c.claim_type.toLowerCase().includes(q)) ||
      (c.claim_id && c.claim_id.toLowerCase().includes(q)) ||
      (c.mitre_techniques && c.mitre_techniques.some(t => t.toLowerCase().includes(q)))
    );
  }, [allCandidateClaims, claimTab, searchQuery]);

  // Map claim ID to verification result for quick lookup
  const verResultMap = useMemo(() => {
    const map = new Map();
    verificationResults.forEach(r => map.set(r.claim_id, r));
    return map;
  }, [verificationResults]);

  if (!activeIncident) {
    return (
      <EmptyState
        title="No Incident Selected"
        description="Select an incident to inspect multi-agent reasoning, evidence corroboration, and governance-driven containment."
      />
    );
  }

  const claimTypeColor = (type) => {
    switch (type) {
      case 'ATTACK_TTP':
        return 'text-amber-300 bg-amber-950/60 border-amber-700/50';
      case 'EXECUTION_CHAIN':
        return 'text-purple-300 bg-purple-950/60 border-purple-700/50';
      case 'PERSISTENCE_TRANSFER':
        return 'text-rose-300 bg-rose-950/60 border-rose-700/50';
      case 'ANOMALY_DETECTION':
      default:
        return 'text-cyan-300 bg-cyan-950/60 border-cyan-700/50';
    }
  };

  const statusVerdictBadge = (status) => {
    switch (status) {
      case 'VERIFIED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-600/60 shadow-sm shadow-emerald-950/40">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            VERIFIED
          </span>
        );
      case 'PARTIALLY_VERIFIED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-600/60">
            <AlertTriangle className="w-3.5 h-3.5 text-cyan-400" />
            PARTIAL
          </span>
        );
      case 'CONTRADICTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-rose-950/80 text-rose-300 border border-rose-600/60">
            <XCircle className="w-3.5 h-3.5 text-rose-400" />
            CONTRADICTED
          </span>
        );
      case 'INSUFFICIENT_EVIDENCE':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
            UNVERIFIED
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Incident Selector */}
      <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-lg backdrop-blur-sm">
        <div>
          <div className="flex items-center gap-2">
            <Workflow className="w-4 h-4 text-cyan-400 animate-pulse" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 font-bold">
              Autonomous Multi-Agent SOC Reasoning Engine
            </span>
          </div>
          <h2 className="text-base font-bold font-mono text-white flex items-center gap-3 mt-1">
            <span>{activeIncident.incident_id}</span>
            <SeverityBadge severity={activeIncident.max_severity} />
            <StatusBadge status={activeIncident.status} />
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">Case Target:</span>
            <select
              value={activeIncident.incident_id}
              onChange={(e) => onSelectIncident(e.target.value)}
              className="px-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
            >
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.incident_id} ({inc.latest_analysis_id ? 'Analyzed' : 'Pending'})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => loadAnalysis(activeIncident.incident_id)}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 flex items-center gap-1.5 transition"
          >
            <Activity className={`w-3.5 h-3.5 text-cyan-400 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>

          {analysis && (
            <button
              onClick={() => setIsJsonOpen(true)}
              className="px-3 py-1.5 rounded-lg bg-cyan-950/40 hover:bg-cyan-900/50 text-xs font-mono text-cyan-300 border border-cyan-800/50 flex items-center gap-1.5 transition"
            >
              <FileCode className="w-3.5 h-3.5" />
              Raw Audit JSON
            </button>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <LoadingSkeleton count={3} type="card" />
          <LoadingSkeleton count={3} type="table" />
        </div>
      ) : error ? (
        <ErrorState
          error={error}
          onRetry={() => loadAnalysis(activeIncident.incident_id)}
          onOpenSettings={onOpenSettings}
          title="Analysis Pipeline Error"
        />
      ) : !analysis ? (
        <div className="p-8 rounded-xl bg-soc-card border border-dashed border-slate-700/80 text-center space-y-3">
          <div className="w-14 h-14 mx-auto rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/50">
            <BrainCircuit className="w-7 h-7" />
          </div>
          <h3 className="text-base font-semibold text-white">Multi-Agent Analysis Pending / Not Triggered</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            The multi-agent reasoning worker processes incidents automatically upon completion of Trust & Risk evaluation.
          </p>
          <div className="pt-2">
            <button
              onClick={() => loadAnalysis(activeIncident.incident_id)}
              className="px-4 py-2 text-xs font-mono rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition"
            >
              Poll Assessment State
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Multi-Agent 3-Stage Pipeline Visualization */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Stage 1: Analysis Agent */}
            <div className="p-4 rounded-xl bg-gradient-to-b from-purple-950/30 to-soc-card border border-purple-800/40 relative overflow-hidden group">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-purple-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-purple-400 animate-ping" />
                  Stage 1: Analysis Agent
                </span>
                <BrainCircuit className="w-5 h-5 text-purple-400/80 group-hover:scale-110 transition-transform" />
              </div>
              <h4 className="mt-2 text-sm font-semibold text-white">Candidate Claims Extraction</h4>
              <p className="mt-1 text-xs text-slate-400">
                Maps telemetry indicators to potential MITRE ATT&CK techniques & execution flows.
              </p>
              <div className="mt-3 flex items-center gap-2 pt-2 border-t border-purple-900/40 text-xs font-mono">
                <span className="text-purple-300 font-bold">{allCandidateClaims.length} Claims Generated</span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-400 text-[11px]">{analysis.prompt_versions?.analysis || 'v1.0'}</span>
              </div>
            </div>

            {/* Stage 2: Verification Agent */}
            <div className="p-4 rounded-xl bg-gradient-to-b from-cyan-950/30 to-soc-card border border-cyan-800/40 relative overflow-hidden group">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  Stage 2: Verification Agent
                </span>
                <ShieldCheck className="w-5 h-5 text-cyan-400/80 group-hover:scale-110 transition-transform" />
              </div>
              <h4 className="mt-2 text-sm font-semibold text-white">Evidence Cross-Examination</h4>
              <p className="mt-1 text-xs text-slate-400">
                Strictly verifies claims against ground-truth endpoint detection events.
              </p>
              <div className="mt-3 flex items-center gap-2 pt-2 border-t border-cyan-900/40 text-xs font-mono">
                <span className="text-emerald-400 font-bold">{verifiedClaims.length} Ground-Truth Verified</span>
                <span className="text-slate-500">•</span>
                <span className="text-rose-400">{rejectedClaims.length} Refuted</span>
              </div>
            </div>

            {/* Stage 3: Synthesis Agent */}
            <div className="p-4 rounded-xl bg-gradient-to-b from-emerald-950/30 to-soc-card border border-emerald-800/40 relative overflow-hidden group">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  Stage 3: Synthesis Agent
                </span>
                <Sparkles className="w-5 h-5 text-emerald-400/80 group-hover:scale-110 transition-transform" />
              </div>
              <h4 className="mt-2 text-sm font-semibold text-white">Threat Fusion & Response</h4>
              <p className="mt-1 text-xs text-slate-400">
                Synthesizes narrative, models uncertainty, and formulates containment strategy.
              </p>
              <div className="mt-3 flex items-center gap-2 pt-2 border-t border-emerald-900/40 text-xs font-mono">
                <span className="text-emerald-300 font-bold">{recommendations.length} Action(s) Proposed</span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-400 text-[11px]">{analysis.model_provenance || 'MockLLM'}</span>
              </div>
            </div>
          </div>

          {/* Incident Threat Narrative & Trust Context */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Executive Threat Narrative */}
            <div className="lg:col-span-2 p-6 rounded-xl bg-soc-card border border-soc-border space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <BrainCircuit className="w-4 h-4 text-purple-400" />
                  <h3 className="text-sm font-semibold text-white">Multi-Agent Incident Narrative</h3>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  Analysis ID: <span className="text-slate-300">{analysis.analysis_id.slice(0, 8)}...</span>
                </span>
              </div>

              {parsedOutput?.incident_summary ? (
                <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400 font-bold block">
                    Synthesized Executive Summary
                  </span>
                  <p className="text-xs md:text-sm text-slate-200 leading-relaxed font-sans">
                    {parsedOutput.incident_summary}
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400 italic">
                  Raw narrative: {analysis.analysis_output}
                </div>
              )}

              {parsedOutput?.evidence_summary && (
                <div className="p-3.5 rounded-lg bg-cyan-950/20 border border-cyan-800/30 text-xs text-cyan-200 flex items-start gap-2.5">
                  <Layers className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-cyan-300 block mb-0.5">Evidence Scope:</span>
                    <span className="text-slate-300">{parsedOutput.evidence_summary}</span>
                  </div>
                </div>
              )}

              {/* Uncertainty Callout */}
              {uncertainty && (
                <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-800/30 text-xs text-amber-200 space-y-2">
                  <div className="flex items-center gap-2 text-amber-300 font-semibold">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Uncertainty & Ambiguity Factors</span>
                  </div>
                  {uncertainty.description && (
                    <p className="text-slate-300 text-xs">{uncertainty.description}</p>
                  )}
                  {Array.isArray(uncertainty.factors) && uncertainty.factors.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {uncertainty.factors.map((f, i) => (
                        <span key={i} className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-950/60 border border-amber-700/40 text-amber-300">
                          {typeof f === 'string' ? f : JSON.stringify(f)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Right 1 Col: Trust & Risk Assessment Context */}
            <div className="p-6 rounded-xl bg-soc-card border border-soc-border space-y-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                    <span>Trust & Risk Context</span>
                  </h3>
                  <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">
                    {assessmentSnapshot?.formula_version || 'v1.0'}
                  </span>
                </div>

                <div className="mt-4 space-y-4">
                  {/* Trust Score Gauge */}
                  <div>
                    <div className="flex justify-between text-xs font-mono mb-1">
                      <span className="text-slate-400">Evidence Trust Score:</span>
                      <span className="text-emerald-400 font-bold">
                        {assessmentSnapshot?.trust_score !== undefined
                          ? `${(assessmentSnapshot.trust_score * 100).toFixed(1)}%`
                          : 'N/A'}
                      </span>
                    </div>
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-emerald-600 to-emerald-400 transition-all duration-500"
                        style={{ width: `${(assessmentSnapshot?.trust_score || 0) * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Risk Score Gauge */}
                  <div>
                    <div className="flex justify-between text-xs font-mono mb-1">
                      <span className="text-slate-400">Incident Severity Risk:</span>
                      <span className="text-rose-400 font-bold">
                        {assessmentSnapshot?.risk_score !== undefined
                          ? `${(assessmentSnapshot.risk_score * 100).toFixed(1)}%`
                          : 'N/A'}
                      </span>
                    </div>
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-amber-500 to-rose-500 transition-all duration-500"
                        style={{ width: `${(assessmentSnapshot?.risk_score || 0) * 100}%` }}
                      />
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800 space-y-2 text-xs font-mono">
                    <div className="flex justify-between text-slate-400">
                      <span>Correlated Events:</span>
                      <span className="text-white">{assessmentSnapshot?.input_snapshot?.detection_event_count ?? 'N/A'}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Max Severity:</span>
                      <span className="text-white">{assessmentSnapshot?.input_snapshot?.max_severity ?? activeIncident.max_severity}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Provenance:</span>
                      <span className="text-purple-300 truncate max-w-[120px]" title={analysis.model_provenance}>
                        {analysis.model_provenance || 'Deterministic'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-[11px] text-slate-400">
                <span className="text-slate-300 font-semibold block mb-0.5">Verification Integrity:</span>
                Multi-agent claims are mathematically corroborated against the ingested telemetry event store before governance dispatch.
              </div>
            </div>
          </div>

          {/* Interactive Claims & Verification Graph / Matrix */}
          <div className="p-6 rounded-xl bg-soc-card border border-soc-border shadow-xl space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <h3 className="text-base font-semibold text-white flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <span>Claim Verification Matrix</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Trace each analytic claim from hypothesis generation through adversarial cross-examination.
                </p>
              </div>

              {/* Tab Filters */}
              <div className="flex items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono">
                <button
                  onClick={() => setClaimTab('all')}
                  className={`px-3 py-1 rounded-md transition ${claimTab === 'all' ? 'bg-cyan-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  All Claims ({allCandidateClaims.length})
                </button>
                <button
                  onClick={() => setClaimTab('verified')}
                  className={`px-3 py-1 rounded-md transition ${claimTab === 'verified' ? 'bg-emerald-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  Verified ({verifiedClaims.length})
                </button>
                {rejectedClaims.length > 0 && (
                  <button
                    onClick={() => setClaimTab('rejected')}
                    className={`px-3 py-1 rounded-md transition ${claimTab === 'rejected' ? 'bg-rose-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
                  >
                    Refuted ({rejectedClaims.length})
                  </button>
                )}
              </div>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
              <input
                type="text"
                placeholder="Search claims by type, statement, MITRE technique (e.g. T1059)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 text-xs bg-slate-900/80 border border-slate-800 rounded-lg text-white font-mono placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 transition"
              />
            </div>

            {/* Claims Cards List */}
            {filteredClaims.length === 0 ? (
              <div className="p-8 text-center border border-dashed border-slate-800 rounded-xl space-y-2">
                <ShieldAlert className="w-8 h-8 text-slate-500 mx-auto" />
                <p className="text-sm font-medium text-slate-300">No claims match the active filter</p>
                <p className="text-xs text-slate-500">Try switching tabs or resetting the search query.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {filteredClaims.map((claim, idx) => {
                  const isExpanded = expandedClaimIds.has(claim.claim_id);
                  const verResult = verResultMap.get(claim.claim_id);

                  return (
                    <div
                      key={claim.claim_id || idx}
                      className="rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition overflow-hidden"
                    >
                      {/* Claim Header Row */}
                      <div
                        onClick={() => toggleClaimExpand(claim.claim_id)}
                        className="p-4 cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-800/20"
                      >
                        <div className="flex items-start md:items-center gap-3">
                          <button className="text-slate-400 hover:text-white mt-0.5 md:mt-0">
                            {isExpanded ? <ChevronDown className="w-4 h-4 text-cyan-400" /> : <ChevronRight className="w-4 h-4" />}
                          </button>

                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-xs font-bold text-white">
                              {claim.claim_id}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-[11px] font-mono border ${claimTypeColor(claim.claim_type)}`}>
                              {claim.claim_type}
                            </span>
                            {claim.mitre_techniques?.map((tech) => (
                              <span
                                key={tech}
                                className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-950/70 border border-purple-800/50 text-purple-300 font-semibold"
                              >
                                {tech}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div className="flex items-center gap-3 pl-7 md:pl-0">
                          <div className="text-right">
                            <span className="text-[10px] font-mono text-slate-500 block">CONFIDENCE</span>
                            <span className="text-xs font-mono font-bold text-cyan-300">
                              {claim.confidence !== undefined ? `${(claim.confidence * 100).toFixed(0)}%` : 'N/A'}
                            </span>
                          </div>

                          {statusVerdictBadge(verResult?.verification_status || claim._status || 'VERIFIED')}
                        </div>
                      </div>

                      {/* Claim Statement Bar */}
                      <div className="px-4 pb-3 pl-11 text-xs text-slate-200 font-sans leading-relaxed">
                        {claim.statement}
                      </div>

                      {/* Expandable Deep Trace Details */}
                      {isExpanded && (
                        <div className="px-4 py-4 ml-11 mr-4 mb-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-4 text-xs font-mono animate-fadeIn">
                          {/* Analytic Reasoning Summary */}
                          <div>
                            <span className="text-[10px] uppercase tracking-wider text-slate-400 block mb-1">
                              Analysis Agent Reasoning:
                            </span>
                            <p className="text-slate-300 font-sans bg-slate-900/60 p-2.5 rounded border border-slate-800/60 leading-relaxed">
                              {claim.reasoning_summary || 'No analytic summary specified.'}
                            </p>
                          </div>

                          {/* Verification Cross-Examination Verdict */}
                          {verResult && (
                            <div className="p-3 rounded bg-emerald-950/10 border border-emerald-800/30 space-y-1.5">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-1.5">
                                  <ShieldCheck className="w-3.5 h-3.5" />
                                  Verification Agent Rationale ({verResult.verifier_agent_id})
                                </span>
                                <span className="text-[11px] text-emerald-300 font-bold">
                                  Confidence: {(verResult.confidence * 100).toFixed(0)}%
                                </span>
                              </div>
                              <p className="text-slate-300 font-sans text-xs">
                                {verResult.verification_reason}
                              </p>
                            </div>
                          )}

                          {/* Supporting Evidence IDs */}
                          {claim.supporting_evidence && claim.supporting_evidence.length > 0 && (
                            <div>
                              <span className="text-[10px] uppercase tracking-wider text-slate-400 block mb-1.5">
                                Corroborated Ground-Truth Detection Event IDs:
                              </span>
                              <div className="flex flex-wrap gap-2">
                                {claim.supporting_evidence.map((evId) => (
                                  <div
                                    key={evId}
                                    onClick={() => copyToClipboard(evId, evId)}
                                    className="px-2.5 py-1 rounded bg-slate-900 border border-cyan-900/50 hover:border-cyan-500/70 text-cyan-300 text-[11px] font-mono cursor-pointer flex items-center gap-1.5 transition"
                                    title="Click to copy event ID"
                                  >
                                    <Zap className="w-3 h-3 text-cyan-400" />
                                    <span>{evId}</span>
                                    {copiedId === evId ? (
                                      <Check className="w-3 h-3 text-emerald-400" />
                                    ) : (
                                      <Copy className="w-3 h-3 text-slate-500" />
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Contradictory Evidence if any */}
                          {verResult?.contradictory_evidence && verResult.contradictory_evidence.length > 0 && (
                            <div>
                              <span className="text-[10px] uppercase tracking-wider text-rose-400 block mb-1">
                                Contradictory Evidence Signals:
                              </span>
                              <div className="flex flex-wrap gap-2">
                                {verResult.contradictory_evidence.map((evId) => (
                                  <span key={evId} className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-[11px] font-mono">
                                    {evId}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Containment & Remediation Recommendations */}
          <div className="p-6 rounded-xl bg-soc-card border border-soc-border shadow-xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-semibold text-white">Synthesized Containment Recommendations</h3>
              </div>
              <span className="text-xs font-mono text-emerald-300 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                Synthesis Agent
              </span>
            </div>

            {recommendations.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {recommendations.map((rec, i) => (
                  <div
                    key={i}
                    className="p-4 rounded-xl bg-slate-900/70 border border-indigo-800/40 space-y-2 hover:border-indigo-600/60 transition"
                  >
                    <div className="flex items-center justify-between">
                      <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-indigo-950/80 text-indigo-300 border border-indigo-700/60">
                        {rec.type}
                      </span>
                      <span className="text-[11px] font-mono text-emerald-400 font-semibold">
                        {rec.status}
                      </span>
                    </div>

                    <p className="text-xs text-slate-200 leading-relaxed font-sans pt-1">
                      {rec.reason}
                    </p>

                    {rec.supporting_claims && rec.supporting_claims.length > 0 && (
                      <div className="pt-2 border-t border-slate-800 flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                        <span>Supporting Claims:</span>
                        {rec.supporting_claims.map((clmId) => (
                          <span key={clmId} className="px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                            {clmId}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>No automated active disruption recommended. Endpoint monitoring and event correlation active.</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Raw JSON modal for deep technical audit */}
      <JsonModal
        isOpen={isJsonOpen}
        onClose={() => setIsJsonOpen(false)}
        title={`Multi-Agent Analysis Audit Payload: ${analysis?.analysis_id}`}
        data={analysis}
      />
    </div>
  );
}

