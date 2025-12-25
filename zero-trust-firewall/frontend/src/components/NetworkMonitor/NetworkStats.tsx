import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
} from 'recharts';
import { formatBytes } from '../../utils/helpers';

interface NetworkStatsProps {
  protocols: Array<{
    protocol: string;
    count: number;
    bytes_sent: number;
    bytes_received: number;
  }>;
  bandwidth: Array<{
    timestamp: string;
    bytes_sent: number;
    bytes_received: number;
    connections: number;
  }>;
}

const NetworkStats: React.FC<NetworkStatsProps> = ({ protocols, bandwidth }) => {
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-dark-800 border border-dark-600 rounded-lg p-3 shadow-xl">
          <p className="text-dark-300 text-sm mb-2">{label}</p>
          {payload.map((entry: any, index: number) => (
            <div key={index} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: entry.color }}
              />
              <span className="text-dark-400 text-sm">{entry.name}:</span>
              <span className="text-white text-sm font-medium">
                {entry.name.includes('bytes') ? formatBytes(entry.value) : entry.value}
              </span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Protocol Distribution */}
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Protocol Distribution</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={protocols} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis type="number" stroke="#64748b" />
              <YAxis
                type="category"
                dataKey="protocol"
                stroke="#64748b"
                tick={{ fill: '#94a3b8', fontSize: 12 }}
                width={80}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Connections" fill="#3b82f6" radius={4} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Bandwidth Over Time */}
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Bandwidth Usage</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={bandwidth.slice(-24)}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="timestamp"
                stroke="#64748b"
                tick={{ fill: '#94a3b8', fontSize: 10 }}
                tickFormatter={(value) => new Date(value).getHours() + ':00'}
              />
              <YAxis
                stroke="#64748b"
                tick={{ fill: '#94a3b8', fontSize: 12 }}
                tickFormatter={(value) => formatBytes(value)}
              />
              <Tooltip content={<CustomTooltip />} />
              <Line
                type="monotone"
                dataKey="bytes_sent"
                name="Sent"
                stroke="#22c55e"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="bytes_received"
                name="Received"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default NetworkStats;
