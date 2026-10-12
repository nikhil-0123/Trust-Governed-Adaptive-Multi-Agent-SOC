import React, { useState, useMemo } from 'react';
import { Search, ArrowUpDown, ChevronRight, ShieldAlert, Cpu, Scale } from 'lucide-react';
import { SeverityBadge, StatusBadge } from '../components/common/Badges';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';

export function IncidentsPage({
  incidents,
  isLoading,
  error,
  onRetry,
  onOpenSettings,
  selectedIncidentId,
  onSelectIncident,
  onNavigate
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sortField, setSortField] = useState('updated_at');
  const [sortAsc, setSortAsc] = useState(false);

  // Filter and sort incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchSearch =
        inc.incident_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (inc.max_severity || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (inc.status || '').toLowerCase().includes(searchTerm.toLowerCase());

      const matchSeverity =
        severityFilter === 'ALL' || (inc.max_severity || '').toUpperCase() === severityFilter;

      const matchStatus =
        statusFilter === 'ALL' || (inc.status || '').toUpperCase() === statusFilter;

      return matchSearch && matchSeverity && matchStatus;
    }).sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [incidents, searchTerm, severityFilter, statusFilter, sortField, sortAsc]);

  const selectedIncident = useMemo(() => {
    return incidents.find(i => i.incident_id === selectedIncidentId) || null;
  }, [incidents, selectedIncidentId]);

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-12 bg-slate-800/40 rounded-xl animate-pulse"></div>
        <LoadingSkeleton count={6} type="table" />
      </div>
    );
  }

  if (error) {
    return <ErrorState error={error} onRetry={onRetry} onOpenSettings={onOpenSettings} title="Unable to Load Incidents" />;
  }

  return (
    <div className="space-y-6">
      {/* Search and Filters Bar */}
      <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search incident ID, severity, status..."
            className="w-full pl-9 pr-4 py-2 text-xs bg-slate-900 border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Filter Dropdowns */}
        <div className="flex items-center gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 text-xs bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="TRIAGED">Triaged</option>
            <option value="DECIDED">Decided</option>
          </select>

          <span className="text-xs font-mono text-slate-400 px-2">
            {filteredIncidents.length} / {incidents.length}
          </span>
        </div>
      </div>

      {/* Main Grid: Table and Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Table column */}
        <div className={`rounded-xl bg-soc-card border border-soc-border overflow-hidden ${selectedIncident ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/70 text-[11px] font-mono uppercase text-slate-400">
                  <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => toggleSort('incident_id')}>
                    <div className="flex items-center gap-1">
                      Incident ID
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => toggleSort('max_severity')}>
                    <div className="flex items-center gap-1">
                      Severity
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => toggleSort('status')}>
                    <div className="flex items-center gap-1">
                      Status
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="py-3 px-4 cursor-pointer hover:text-white hidden sm:table-cell" onClick={() => toggleSort('last_seen')}>
                    <div className="flex items-center gap-1">
                      Last Seen
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs">
                {filteredIncidents.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-400">
                      <EmptyState
                        title="No Matching Incidents"
                        description="Try modifying search criteria or severity filters."
                      />
                    </td>
                  </tr>
                ) : (
                  filteredIncidents.map((inc) => {
                    const isSelected = selectedIncidentId === inc.incident_id;
                    return (
                      <tr
                        key={inc.incident_id}
                        onClick={() => onSelectIncident(inc.incident_id)}
                        className={`cursor-pointer transition ${
                          isSelected
                            ? 'bg-cyan-950/40 border-l-2 border-cyan-400'
                            : 'hover:bg-slate-800/40'
                        }`}
                      >
                        <td className="py-3 px-4 font-mono font-medium text-cyan-300">
                          {inc.incident_id}
                        </td>
                        <td className="py-3 px-4">
                          <SeverityBadge severity={inc.max_severity} />
                        </td>
                        <td className="py-3 px-4">
                          <StatusBadge status={inc.status} />
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400 text-[11px] hidden sm:table-cell">
                          {new Date(inc.last_seen).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectIncident(inc.incident_id);
                            }}
                            className="p-1 rounded text-slate-400 hover:text-cyan-300 transition"
                          >
                            <ChevronRight className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Incident Drawer */}
        {selectedIncident && (
          <div className="p-5 rounded-xl bg-soc-card border border-soc-border shadow-xl flex flex-col space-y-4 animate-fade-in">
            <div className="flex items-start justify-between pb-3 border-b border-slate-800">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest block">
                  Incident Triage Card
                </span>
                <h3 className="text-sm font-bold font-mono text-white mt-1">
                  {selectedIncident.incident_id}
                </h3>
              </div>
              <SeverityBadge severity={selectedIncident.max_severity} />
            </div>

            <div className="space-y-2.5 text-xs">
              <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Current Status:</span>
                <StatusBadge status={selectedIncident.status} />
              </div>
              <div className="flex items-center justify-between py-1 border-b border-slate-800/60 font-mono text-[11px]">
                <span className="text-slate-400">First Seen:</span>
                <span className="text-slate-200">{new Date(selectedIncident.first_seen).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-slate-800/60 font-mono text-[11px]">
                <span className="text-slate-400">Last Seen:</span>
                <span className="text-slate-200">{new Date(selectedIncident.last_seen).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-slate-800/60 font-mono text-[11px]">
                <span className="text-slate-400">Assessment ID:</span>
                <span className="text-indigo-300 truncate max-w-[140px]" title={selectedIncident.latest_assessment_id || 'Pending'}>
                  {selectedIncident.latest_assessment_id || 'None'}
                </span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-slate-800/60 font-mono text-[11px]">
                <span className="text-slate-400">Analysis ID:</span>
                <span className="text-purple-300 truncate max-w-[140px]" title={selectedIncident.latest_analysis_id || 'Pending'}>
                  {selectedIncident.latest_analysis_id || 'None'}
                </span>
              </div>
            </div>

            {/* Quick Actions to jump to deep tabs */}
            <div className="pt-2 space-y-2">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Deep Inspection Routing
              </span>

              <button
                onClick={() => onNavigate('investigation')}
                className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-cyan-950/40 hover:bg-cyan-900/50 text-cyan-200 border border-cyan-800/60 text-xs font-medium transition"
              >
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Investigate Evidence & MITRE</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={() => onNavigate('analysis')}
                className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-purple-950/40 hover:bg-purple-900/50 text-purple-200 border border-purple-800/60 text-xs font-medium transition"
              >
                <div className="flex items-center gap-2">
                  <Cpu className="w-3.5 h-3.5 text-purple-400" />
                  <span>Inspect AI Reasoning Output</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={() => onNavigate('governance')}
                className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-amber-950/40 hover:bg-amber-900/50 text-amber-200 border border-amber-800/60 text-xs font-medium transition"
              >
                <div className="flex items-center gap-2">
                  <Scale className="w-3.5 h-3.5 text-amber-400" />
                  <span>Trust Score & Governance Decision</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
