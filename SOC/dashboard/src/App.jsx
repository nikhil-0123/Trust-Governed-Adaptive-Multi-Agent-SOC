import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/layout/Header';
import { Navigation } from './components/layout/Navigation';
import { SettingsModal } from './components/layout/SettingsModal';
import { OverviewPage } from './pages/OverviewPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { AnalysisPage } from './pages/AnalysisPage';
import { GovernancePage } from './pages/GovernancePage';
import { EndpointsPage } from './pages/EndpointsPage';
import { api } from './api/client';

export function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [backendConnected, setBackendConnected] = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  const fetchIncidentsData = useCallback(async (isBackground = false) => {
    if (!isBackground) setIsLoading(true);
    else setIsRefreshing(true);
    setError(null);


    try {
      const data = await api.getIncidents();
      setIncidents(data || []);
      setBackendConnected(true);

      // Auto-select first incident if none selected or if previously selected was removed
      if (data && data.length > 0) {
        setSelectedIncidentId((prev) => {
          if (!prev || !data.some(i => i.incident_id === prev)) {
            return data[0].incident_id;
          }
          return prev;
        });
      }
    } catch (err) {
      setError(err.message || 'Error fetching incidents from backend.');
      setBackendConnected(false);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidentsData();

    // Auto-refresh every 12 seconds
    const interval = setInterval(() => {
      fetchIncidentsData(true);
    }, 12000);

    return () => clearInterval(interval);
  }, [fetchIncidentsData]);

  const handleSelectIncident = (incidentId) => {
    setSelectedIncidentId(incidentId);
  };

  const handleNavigate = (tab) => {
    setActiveTab(tab);
  };

  return (
    <div className="min-h-screen bg-soc-bg text-soc-textMain flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Header */}
      <Header
        backendConnected={backendConnected}
        onRefresh={() => fetchIncidentsData(true)}
        isRefreshing={isRefreshing}
        onOpenSettings={() => setIsSettingsOpen(true)}
      />

      {/* Navigation */}
      <Navigation
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        incidentCount={incidents.length}
        selectedIncidentId={selectedIncidentId}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && (
          <OverviewPage
            incidents={incidents}
            isLoading={isLoading}
            error={error}
            onRetry={() => fetchIncidentsData()}
            onOpenSettings={() => setIsSettingsOpen(true)}
            onSelectIncident={handleSelectIncident}
            onNavigate={handleNavigate}
          />
        )}

        {activeTab === 'incidents' && (
          <IncidentsPage
            incidents={incidents}
            isLoading={isLoading}
            error={error}
            onRetry={() => fetchIncidentsData()}
            onOpenSettings={() => setIsSettingsOpen(true)}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={handleSelectIncident}
            onNavigate={handleNavigate}
          />
        )}

        {activeTab === 'investigation' && (
          <InvestigationPage
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={handleSelectIncident}
            onOpenSettings={() => setIsSettingsOpen(true)}
          />
        )}

        {activeTab === 'analysis' && (
          <AnalysisPage
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={handleSelectIncident}
            onOpenSettings={() => setIsSettingsOpen(true)}
          />
        )}

        {activeTab === 'governance' && (
          <GovernancePage
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={handleSelectIncident}
            onOpenSettings={() => setIsSettingsOpen(true)}
          />
        )}

        {activeTab === 'endpoints' && (
          <EndpointsPage
            incidents={incidents}
            onOpenSettings={() => setIsSettingsOpen(true)}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-soc-border bg-soc-surface/40 py-4 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>TGAM-SOC — Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense</span>
          <span>Append-Only Governance • Zero Fabricated Data • Live API Synchronized</span>
        </div>
      </footer>

      {/* Settings Modal */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onConfigSaved={() => fetchIncidentsData()}
      />
    </div>
  );
}

export default App;
