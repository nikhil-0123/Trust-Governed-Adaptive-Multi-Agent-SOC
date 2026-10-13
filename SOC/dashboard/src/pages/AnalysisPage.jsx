import React, { useState, useEffect, useCallback } from 'react';
import { BrainCircuit, Sparkles, CheckCircle2, FileCode } from 'lucide-react';
import { api } from '../api/client';
import { StatusBadge, SeverityBadge } from '../components/common/Badges';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { JsonModal } from '../components/common/JsonModal';

export function AnalysisPage({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  onOpenSettings
}) {
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isJsonOpen, setIsJsonOpen] = useState(false);

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;

  const loadAnalysis = useCallback(async (incidentId) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.getIncidentAnalysis(incidentId);
      setAnalysis(res);
    } catch (err) {
      setError(err.message || 'Failed to fetch AI analysis.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!activeIncident?.incident_id) return;
    loadAnalysis(activeIncident.incident_id);
  }, [activeIncident?.incident_id, loadAnalysis]);


  if (!activeIncident) {
    return (
      <EmptyState
        title="No Incident Selected"
        description="Select an incident to view AI multi-agent reasoning and verification analysis."
      />
    );
  }

  // Parse structured analysis output if formatted as JSON or structured markdown
  let parsedOutput = null;
  if (analysis?.analysis_output) {
    try {
      parsedOutput = JSON.parse(analysis.analysis_output);
    } catch {
      // plain text or markdown string
      parsedOutput = null;
    }
  }

  return (
    <div className="space-y-6">
      {/* Incident Switcher Bar */}
      <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <span className="text-[10px] font-mono text-purple-400 uppercase tracking-widest block">
            Multi-Agent Reasoning Engine
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
                {inc.incident_id} ({inc.latest_analysis_id ? 'Analyzed' : 'Pending'})
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
          onRetry={() => loadAnalysis(activeIncident.incident_id)}
          onOpenSettings={onOpenSettings}
          title="Analysis Fetch Error"
        />
      ) : !analysis ? (
        <div className="p-8 rounded-xl bg-soc-card border border-dashed border-slate-700/80 text-center space-y-3">
          <div className="w-12 h-12 mx-auto rounded-full bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
            <BrainCircuit className="w-6 h-6" />
          </div>
          <h3 className="text-base font-semibold text-white">AI Analysis In Progress / Pending</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            The multi-agent reasoning worker has not yet completed evaluation for this incident.
            Analysis executes automatically after trust/risk assessment.
          </p>
          <div className="pt-2">
            <button
              onClick={() => loadAnalysis(activeIncident.incident_id)}
              className="px-4 py-2 text-xs font-mono rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-600 transition"
            >
              Check Again
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Metadata Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-soc-card border border-soc-border">
              <span className="text-[10px] font-mono text-slate-500 uppercase block">ANALYSIS RECORD ID</span>
              <p className="mt-1 text-xs font-mono font-bold text-white truncate" title={analysis.analysis_id}>
                {analysis.analysis_id}
              </p>
              <div className="mt-2 flex items-center gap-2">
                <StatusBadge status={analysis.status} />
              </div>
            </div>

            <div className="p-4 rounded-xl bg-soc-card border border-soc-border">
              <span className="text-[10px] font-mono text-slate-500 uppercase block">MODEL PROVENANCE</span>
              <p className="mt-1 text-xs font-mono font-bold text-purple-300 truncate" title={analysis.model_provenance}>
                {analysis.model_provenance || 'Deterministic Reasoning Pipeline'}
              </p>
              <span className="mt-1 text-[11px] text-slate-400 block font-mono">
                Assessed: {new Date(analysis.created_at).toLocaleString()}
              </span>
            </div>

            <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase block">ASSESSMENT LINK</span>
                <p className="mt-1 text-xs font-mono font-bold text-indigo-300 truncate max-w-[150px]" title={analysis.assessment_id}>
                  {analysis.assessment_id}
                </p>
              </div>
              <button
                onClick={() => setIsJsonOpen(true)}
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition"
              >
                <FileCode className="w-4 h-4" />
                Raw JSON
              </button>
            </div>
          </div>

          {/* Analysis Content Body */}
          <div className="p-6 rounded-xl bg-soc-card border border-soc-border shadow-xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-semibold text-white">Multi-Agent Synthesis & Verification Output</h3>
              </div>
              <span className="text-xs font-mono text-purple-300 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800/40">
                Verified
              </span>
            </div>

            {/* Display formatted JSON structure if present, or formatted markdown block */}
            {parsedOutput ? (
              <div className="space-y-4">
                {parsedOutput.summary && (
                  <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
                    <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Executive Summary</span>
                    <p className="text-sm text-slate-200 leading-relaxed">{parsedOutput.summary}</p>
                  </div>
                )}

                {parsedOutput.findings && Array.isArray(parsedOutput.findings) && (
                  <div className="space-y-2">
                    <span className="text-[11px] font-mono uppercase text-slate-400 block">Identified Threat Findings</span>
                    <div className="space-y-2">
                      {parsedOutput.findings.map((finding, idx) => (
                        <div key={idx} className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-start gap-3">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                          <p className="text-xs text-slate-300">{typeof finding === 'string' ? finding : JSON.stringify(finding)}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {parsedOutput.recommendation && (
                  <div className="p-4 rounded-lg bg-indigo-950/20 border border-indigo-800/40 text-xs text-indigo-200">
                    <span className="font-semibold text-indigo-300 block mb-1">Recommended Response Strategy:</span>
                    <p>{parsedOutput.recommendation}</p>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800/80 font-mono text-xs text-slate-300 leading-relaxed whitespace-pre-wrap break-all">
                {analysis.analysis_output}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Raw JSON modal */}
      <JsonModal
        isOpen={isJsonOpen}
        onClose={() => setIsJsonOpen(false)}
        title={`Analysis Payload: ${analysis?.analysis_id}`}
        data={analysis}
      />
    </div>
  );
}
