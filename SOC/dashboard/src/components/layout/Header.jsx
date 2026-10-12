import React, { useState, useEffect } from 'react';
import { Shield, Settings, RefreshCw, Clock } from 'lucide-react';
import { getApiConfig } from '../../api/client';

export function Header({ backendConnected, onRefresh, isRefreshing, onOpenSettings }) {
  const [currentTime, setCurrentTime] = useState(() => new Date().toUTCString());
  const config = getApiConfig();

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toUTCString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="border-b border-soc-border bg-soc-surface/90 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and title */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center shadow-lg shadow-cyan-950/50">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-bold tracking-wider text-white">TGAM-SOC</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
                  Console v1.0
                </span>
              </div>
              <p className="text-xs text-soc-textMuted hidden sm:block">
                Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense
              </p>
            </div>
          </div>

          {/* Right Status Actions */}
          <div className="flex items-center gap-3">
            {/* Live Clock */}
            <div className="hidden lg:flex items-center gap-1.5 text-xs text-slate-400 font-mono bg-slate-900/60 px-2.5 py-1 rounded-md border border-slate-800">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span>{currentTime}</span>
            </div>

            {/* Backend Link Indicator */}
            <button
              onClick={onOpenSettings}
              className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono border transition ${
                backendConnected === true
                  ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60 hover:bg-emerald-900/30'
                  : backendConnected === false
                  ? 'bg-rose-950/40 text-rose-300 border-rose-800/60 hover:bg-rose-900/30'
                  : 'bg-slate-900 text-slate-400 border-slate-700'
              }`}
              title={`SOC Backend: ${config.baseUrl}`}
            >
              <span className={`w-2 h-2 rounded-full ${
                backendConnected === true ? 'bg-emerald-400 animate-pulse' :
                backendConnected === false ? 'bg-rose-500' : 'bg-slate-500'
              }`} />
              <span className="hidden md:inline">Backend:</span>
              <span>{backendConnected === true ? 'ONLINE' : backendConnected === false ? 'OFFLINE' : 'CHECKING'}</span>
            </button>

            {/* Manual Refresh */}
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className="p-2 rounded-lg bg-soc-panel hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition"
              title="Refresh SOC data"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>

            {/* Config modal button */}
            <button
              onClick={onOpenSettings}
              className="p-2 rounded-lg bg-soc-panel hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition"
              title="API & Auth Settings"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
