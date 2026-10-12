import React from 'react';
import { AlertCircle, RefreshCw, KeyRound, WifiOff } from 'lucide-react';

export function ErrorState({ error, onRetry, onOpenSettings, title = "Data Acquisition Error" }) {
  const isUnauthorized = error?.toLowerCase().includes('unauthorized') || error?.includes('401');
  const isNetwork = error?.toLowerCase().includes('cannot connect') || error?.includes('network');

  return (
    <div className="rounded-xl border border-rose-800/50 bg-rose-950/20 p-6 text-center my-4">
      <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
        {isNetwork ? <WifiOff className="w-6 h-6" /> : isUnauthorized ? <KeyRound className="w-6 h-6" /> : <AlertCircle className="w-6 h-6" />}
      </div>
      <h3 className="text-base font-semibold text-rose-200">{title}</h3>
      <p className="mt-1 text-sm text-slate-300 max-w-lg mx-auto font-mono text-xs bg-slate-950/60 p-3 rounded border border-rose-900/40 mt-3 text-left">
        {error || 'An unexpected error occurred while communicating with the central SOC backend.'}
      </p>

      <div className="mt-5 flex items-center justify-center gap-3">
        {onRetry && (
          <button
            onClick={onRetry}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-soc-panel hover:bg-slate-700 text-sm font-medium text-white border border-slate-600 transition"
          >
            <RefreshCw className="w-4 h-4" />
            Retry Query
          </button>
        )}
        {isUnauthorized && onOpenSettings && (
          <button
            onClick={onOpenSettings}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-sm font-medium text-white transition shadow-lg shadow-cyan-900/30"
          >
            <KeyRound className="w-4 h-4" />
            Configure API Bearer Token
          </button>
        )}
      </div>
    </div>
  );
}
