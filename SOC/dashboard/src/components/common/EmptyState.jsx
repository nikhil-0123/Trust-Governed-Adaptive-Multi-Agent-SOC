import React from 'react';
import { Inbox } from 'lucide-react';

export function EmptyState({ title = "No Records Found", description = "No items available to display.", icon: Icon = Inbox }) {
  return (
    <div className="rounded-xl border border-dashed border-slate-700/60 bg-soc-card/40 p-8 text-center my-4">
      <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-slate-800/60 border border-slate-700 flex items-center justify-center text-slate-400">
        <Icon className="w-6 h-6" />
      </div>
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      <p className="mt-1 text-xs text-slate-400 max-w-sm mx-auto">{description}</p>
    </div>
  );
}
