import React from 'react';

export function LoadingSkeleton({ count = 3, type = 'card' }) {
  if (type === 'table') {
    return (
      <div className="space-y-3 animate-pulse">
        <div className="h-10 bg-slate-800/60 rounded border border-slate-700/40"></div>
        {Array.from({ length: count }).map((_, i) => (
          <div key={i} className="h-14 bg-slate-800/30 rounded border border-slate-700/20"></div>
        ))}
      </div>
    );
  }

  if (type === 'row') {
    return (
      <div className="space-y-2 animate-pulse">
        {Array.from({ length: count }).map((_, i) => (
          <div key={i} className="h-12 bg-slate-800/40 rounded border border-slate-700/30"></div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 animate-pulse">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="h-28 rounded-xl bg-slate-800/40 border border-slate-700/40 p-4">
          <div className="h-4 w-24 bg-slate-700/60 rounded mb-3"></div>
          <div className="h-8 w-16 bg-slate-700/80 rounded mb-2"></div>
          <div className="h-3 w-32 bg-slate-700/40 rounded"></div>
        </div>
      ))}
    </div>
  );
}
