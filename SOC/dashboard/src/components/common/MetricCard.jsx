import React from 'react';

export function MetricCard({ title, value, subtitle, icon: Icon, trend, color = 'cyan' }) {
  const colorMap = {
    cyan: {
      border: 'hover:border-cyan-500/50',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      glow: 'shadow-cyan-500/5',
      accent: 'text-cyan-400'
    },
    rose: {
      border: 'hover:border-rose-500/50',
      iconBg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      glow: 'shadow-rose-500/5',
      accent: 'text-rose-400'
    },
    amber: {
      border: 'hover:border-amber-500/50',
      iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      glow: 'shadow-amber-500/5',
      accent: 'text-amber-400'
    },
    emerald: {
      border: 'hover:border-emerald-500/50',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      glow: 'shadow-emerald-500/5',
      accent: 'text-emerald-400'
    },
    purple: {
      border: 'hover:border-purple-500/50',
      iconBg: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      glow: 'shadow-purple-500/5',
      accent: 'text-purple-400'
    }
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div className={`p-4 rounded-xl bg-soc-card border border-soc-border ${scheme.border} transition-all duration-200 shadow-lg ${scheme.glow}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-soc-textMuted">{title}</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-white font-mono">{value}</span>
            {trend && (
              <span className={`text-xs font-medium ${trend.type === 'positive' ? 'text-emerald-400' : 'text-amber-400'}`}>
                {trend.text}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="mt-1 text-xs text-soc-textMuted">{subtitle}</p>
          )}
        </div>
        {Icon && (
          <div className={`p-2.5 rounded-lg border ${scheme.iconBg}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
    </div>
  );
}
