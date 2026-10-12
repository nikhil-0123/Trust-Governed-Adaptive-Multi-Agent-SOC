import React from 'react';
import { AlertTriangle, CheckCircle, Clock, Ban, Terminal, Monitor } from 'lucide-react';

export function SeverityBadge({ severity, size = 'sm' }) {
  const sev = (severity || 'UNKNOWN').toUpperCase();
  const styles = {
    CRITICAL: 'bg-rose-950/70 text-rose-300 border-rose-700/60 shadow-rose-950/50',
    HIGH: 'bg-amber-950/70 text-amber-300 border-amber-700/60 shadow-amber-950/50',
    MEDIUM: 'bg-yellow-950/60 text-yellow-300 border-yellow-700/50',
    LOW: 'bg-blue-950/60 text-blue-300 border-blue-700/50',
    UNKNOWN: 'bg-slate-800 text-slate-300 border-slate-700'
  };

  const currentStyle = styles[sev] || styles.UNKNOWN;
  const padding = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm font-semibold';

  return (
    <span className={`inline-flex items-center gap-1 font-mono uppercase tracking-wider rounded border ${currentStyle} ${padding}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${sev === 'CRITICAL' ? 'bg-rose-400 animate-pulse' : sev === 'HIGH' ? 'bg-amber-400' : 'bg-blue-400'}`} />
      {sev}
    </span>
  );
}

export function StatusBadge({ status }) {
  const st = (status || 'UNKNOWN').toUpperCase();
  const styles = {
    OPEN: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    TRIAGED: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
    DECIDED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    PENDING: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    COMPLETED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    FAILED: 'bg-rose-500/10 text-rose-400 border-rose-500/30'
  };

  const style = styles[st] || 'bg-slate-800 text-slate-300 border-slate-700';

  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border ${style}`}>
      {st}
    </span>
  );
}

export function DecisionBadge({ decision }) {
  const dec = (decision || 'PENDING').toUpperCase();
  const config = {
    AUTO_APPROVE: {
      bg: 'bg-emerald-950/70 text-emerald-300 border-emerald-600/60',
      icon: CheckCircle,
      label: 'AUTO APPROVE'
    },
    HUMAN_APPROVAL: {
      bg: 'bg-amber-950/70 text-amber-300 border-amber-600/60',
      icon: Clock,
      label: 'HUMAN APPROVAL REQUIRED'
    },
    HOLD: {
      bg: 'bg-rose-950/70 text-rose-300 border-rose-600/60',
      icon: Ban,
      label: 'HOLD / REJECTED'
    },
    ESCALATE: {
      bg: 'bg-purple-950/70 text-purple-300 border-purple-600/60',
      icon: AlertTriangle,
      label: 'ESCALATE TO SOC LEAD'
    },
    PENDING: {
      bg: 'bg-slate-800 text-slate-400 border-slate-700',
      icon: Clock,
      label: 'PENDING GOVERNANCE'
    }
  };

  const current = config[dec] || config.PENDING;
  const Icon = current.icon;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md border ${current.bg}`}>
      <Icon className="w-3.5 h-3.5" />
      {current.label}
    </span>
  );
}

export function OsBadge({ os }) {
  const osLower = (os || '').toLowerCase();
  const isWindows = osLower.includes('win');
  const isUbuntu = osLower.includes('ubuntu') || osLower.includes('linux');

  if (isWindows) {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 font-mono">
        <Monitor className="w-3 h-3 text-blue-400" />
        Windows
      </span>
    );
  }

  if (isUbuntu) {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-300 border border-orange-500/20 font-mono">
        <Terminal className="w-3 h-3 text-orange-400" />
        Ubuntu Linux
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
      {os || 'Unknown OS'}
    </span>
  );
}

export function MitreBadge({ techniqueId, tactic, techniqueName }) {
  return (
    <div className="inline-flex flex-col gap-0.5 p-2 rounded bg-slate-900/90 border border-cyan-800/40 text-left">
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs font-semibold text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800/40">
          {techniqueId}
        </span>
        <span className="text-xs text-slate-400 font-medium">
          {tactic}
        </span>
      </div>
      {techniqueName && (
        <span className="text-xs text-slate-200 truncate max-w-xs font-medium mt-0.5">
          {techniqueName}
        </span>
      )}
    </div>
  );
}
