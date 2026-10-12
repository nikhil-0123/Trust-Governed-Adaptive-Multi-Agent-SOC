import React, { useState } from 'react';
import { X, Server, CheckCircle, AlertTriangle, RefreshCw } from 'lucide-react';
import { getApiConfig, setApiConfig, resetApiConfig, api } from '../../api/client';

export function SettingsModal({ isOpen, onClose, onConfigSaved }) {
  const current = getApiConfig();
  const [baseUrl, setBaseUrl] = useState(current.baseUrl);
  const [token, setToken] = useState(current.token);
  const [testStatus, setTestStatus] = useState(null); // 'testing' | 'success' | 'error'
  const [testMessage, setTestMessage] = useState('');

  if (!isOpen) return null;

  const handleTest = async () => {
    setTestStatus('testing');
    setTestMessage('Pinging SOC backend...');
    setApiConfig(baseUrl, token);
    try {
      const res = await api.testConnection();
      setTestStatus('success');
      setTestMessage(`Connected successfully! Found ${Array.isArray(res) ? res.length : 0} incidents in database.`);
    } catch (err) {
      setTestStatus('error');
      setTestMessage(err.message || 'Connection failed.');
    }
  };

  const handleSave = () => {
    setApiConfig(baseUrl, token);
    if (onConfigSaved) onConfigSaved();
    onClose();
  };

  const handleReset = () => {
    resetApiConfig();
    const defaults = getApiConfig();
    setBaseUrl(defaults.baseUrl);
    setToken(defaults.token);
    setTestStatus(null);
    setTestMessage('');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-md rounded-xl bg-soc-surface border border-slate-700 shadow-2xl p-6">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-semibold text-white">SOC Backend Configuration</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="mt-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              API Base URL
            </label>
            <div className="relative">
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://localhost:8000"
                className="w-full px-3 py-2 text-sm bg-slate-900 border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
            <p className="mt-1 text-xs text-slate-400">Address of the FastAPI central SOC server.</p>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Bearer Authentication Token
            </label>
            <div className="relative">
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="dev-token-123"
                className="w-full px-3 py-2 text-sm bg-slate-900 border border-slate-700 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
            <p className="mt-1 text-xs text-slate-400">Backend API secret token for Authorization header.</p>
          </div>

          {/* Test connection output */}
          {testStatus && (
            <div className={`p-3 rounded-lg border text-xs font-mono flex items-start gap-2 ${
              testStatus === 'success'
                ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                : testStatus === 'error'
                ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                : 'bg-cyan-950/40 border-cyan-800 text-cyan-300'
            }`}>
              {testStatus === 'success' ? <CheckCircle className="w-4 h-4 shrink-0 text-emerald-400 mt-0.5" /> :
               testStatus === 'error' ? <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" /> :
               <RefreshCw className="w-4 h-4 shrink-0 animate-spin text-cyan-400 mt-0.5" />}
              <span className="break-all">{testMessage}</span>
            </div>
          )}
        </div>

        <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
          <button
            type="button"
            onClick={handleReset}
            className="text-xs text-slate-400 hover:text-slate-200 transition underline underline-offset-2"
          >
            Reset Defaults
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleTest}
              disabled={testStatus === 'testing'}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-600 transition"
            >
              Test Link
            </button>
            <button
              type="button"
              onClick={handleSave}
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-medium text-white transition shadow-lg shadow-cyan-900/30"
            >
              Save & Apply
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
