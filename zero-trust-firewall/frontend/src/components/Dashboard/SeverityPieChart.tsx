import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

interface SeverityPieChartProps {
  data: Record<string, number>;
}

const COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#22c55e',
  info: '#0284c7',
};

const SeverityPieChart: React.FC<SeverityPieChartProps> = ({ data }) => {
  const chartData = Object.entries(data)
    .filter(([_, value]) => value > 0)
    .map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
      color: COLORS[name] || '#64748b',
    }));

  const total = chartData.reduce((sum, item) => sum + item.value, 0);

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0];
      const percentage = ((data.value / total) * 100).toFixed(1);
      return (
        <div className="bg-dark-800 border border-dark-600 rounded-lg p-3 shadow-xl">
          <div className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: data.payload.color }}
            />
            <span className="text-white font-medium">{data.name}</span>
          </div>
          <p className="text-dark-300 text-sm mt-1">
            {data.value} threats ({percentage}%)
          </p>
        </div>
      );
    }
    return null;
  };

  const renderCustomLabel = ({ cx, cy }: any) => {
    return (
      <text
        x={cx}
        y={cy}
        fill="#fff"
        textAnchor="middle"
        dominantBaseline="central"
      >
        <tspan x={cx} y={cy - 10} className="text-2xl font-bold">
          {total}
        </tspan>
        <tspan x={cx} y={cy + 15} className="text-sm fill-gray-400">
          Threats
        </tspan>
      </text>
    );
  };

  return (
    <div className="card">
      <h3 className="text-lg font-semibold text-white mb-4">Severity Distribution</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={80}
              paddingAngle={2}
              dataKey="value"
              labelLine={false}
              label={renderCustomLabel}
            >
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend
              formatter={(value) => (
                <span className="text-dark-300 text-sm">{value}</span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default SeverityPieChart;
