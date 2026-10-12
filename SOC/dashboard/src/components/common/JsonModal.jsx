import React, { useState } from 'react';
import { X, Copy, Check } from 'lucide-react';

export function JsonModal({ isOpen, onClose, title = "JSON Data Viewer", data }) {
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  let formatted = '';
  try {
    if (typeof data === 'string') {
      const parsed = JSON.parse(data);
      formatted = JSON.stringify(parsed, null, 2);
    } else {
      formatted = JSON.stringify(data, null, 2);
    }
  } catch {
    formatted = String(data);
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(formatted);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-3xl rounded-xl bg-soc-surface border border-slate-700 shadow-2xl flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700 bg-slate-900/60 rounded-t-xl">
          <h3 className="text-sm font-semibold text-cyan-300 font-mono flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            {title}
          </h3>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="p-1.5 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-600 flex items-center gap-1 transition"
              title="Copy JSON"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-4 overflow-auto flex-1 font-mono text-xs bg-black/60 text-emerald-300">
          <pre className="whitespace-pre-wrap break-all leading-relaxed">{formatted}</pre>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-800 bg-slate-900/40 text-right rounded-b-xl">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 border border-slate-600 transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
