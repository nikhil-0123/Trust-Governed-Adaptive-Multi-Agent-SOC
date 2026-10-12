import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const d = payload[0];
    return (
      <div className="bg-slate-900 border border-slate-700 px-3 py-1.5 rounded shadow-xl text-xs font-mono">
        <span style={{ color: d.payload.color }} className="font-semibold">{d.name}: </span>
        <span className="text-white font-bold">{d.value}</span>
      </div>
    );
  }
  return null;
};

export function SeverityPieChart({ incidents = [] }) {
  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  incidents.forEach((inc) => {
    const sev = (inc.max_severity || 'LOW').toUpperCase();
    if (counts[sev] !== undefined) counts[sev]++;
    else counts.LOW++;
  });

  const data = [
    { name: 'Critical', value: counts.CRITICAL, color: '#f43f5e' },
    { name: 'High', value: counts.HIGH, color: '#f59e0b' },
    { name: 'Medium', value: counts.MEDIUM, color: '#eab308' },
    { name: 'Low', value: counts.LOW, color: '#3b82f6' }
  ].filter(d => d.value > 0);

  if (data.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-xs text-slate-500 font-mono">
        No active incident severity data
      </div>
    );
  }

  return (
    <div className="w-full h-52">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={75}
            paddingAngle={4}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value) => <span className="text-xs text-slate-300 font-medium">{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
