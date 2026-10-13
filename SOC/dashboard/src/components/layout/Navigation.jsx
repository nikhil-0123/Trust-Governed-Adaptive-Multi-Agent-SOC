import React from 'react';
import { LayoutDashboard, AlertOctagon, Search, BrainCircuit, Scale, Radio, ShieldAlert } from 'lucide-react';

export function Navigation({ activeTab, setActiveTab, incidentCount, selectedIncidentId }) {
  const tabs = [
    { id: 'overview', label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'incidents', label: 'Incidents', icon: AlertOctagon, badge: incidentCount },
    { id: 'investigation', label: 'Investigation', icon: Search, subLabel: selectedIncidentId ? selectedIncidentId.slice(0, 12) + '...' : null },
    { id: 'analysis', label: 'AI Analysis', icon: BrainCircuit },
    { id: 'governance', label: 'Trust & Governance', icon: Scale },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: ShieldAlert },
    { id: 'endpoints', label: 'Endpoints', icon: Radio },
  ];


  return (
    <nav className="border-b border-soc-border bg-soc-surface/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex space-x-1 sm:space-x-4 overflow-x-auto py-2.5 scrollbar-none">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-2 text-xs sm:text-sm font-medium rounded-lg transition-all whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-lg shadow-cyan-950/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                {tab.badge !== undefined && (
                  <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                    isActive ? 'bg-cyan-500/20 text-cyan-200' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {tab.badge}
                  </span>
                )}
                {tab.subLabel && (
                  <span className="hidden md:inline px-1.5 py-0.2 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-800/50 text-[10px] font-mono">
                    {tab.subLabel}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>
    </nav>
  );
}
