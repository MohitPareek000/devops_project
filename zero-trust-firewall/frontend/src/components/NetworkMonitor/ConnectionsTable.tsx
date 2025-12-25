import React from 'react';
import { Ban, Unlock } from 'lucide-react';
import { formatDate, formatBytes } from '../../utils/helpers';

interface Connection {
  id: number;
  source_ip: string;
  destination_ip: string;
  destination_domain: string;
  destination_port: number;
  protocol: string;
  bytes_sent: number;
  bytes_received: number;
  connection_status: string;
  is_blocked: boolean;
  threat_score: number;
  timestamp: string;
}

interface ConnectionsTableProps {
  connections: Connection[];
  onBlock?: (ip: string) => void;
  onUnblock?: (ip: string) => void;
}

const ConnectionsTable: React.FC<ConnectionsTableProps> = ({
  connections,
  onBlock,
  onUnblock,
}) => {
  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      established: 'text-green-400',
      closed: 'text-gray-400',
      blocked: 'text-red-400',
      syn_sent: 'text-yellow-400',
    };
    return colors[status] || 'text-gray-400';
  };

  const getThreatScoreColor = (score: number) => {
    if (score >= 0.7) return 'text-red-400 bg-red-900/30';
    if (score >= 0.4) return 'text-yellow-400 bg-yellow-900/30';
    return 'text-green-400 bg-green-900/30';
  };

  return (
    <div className="table-container">
      <table className="table">
        <thead>
          <tr>
            <th>Source IP</th>
            <th>Destination</th>
            <th>Port</th>
            <th>Protocol</th>
            <th>Traffic</th>
            <th>Status</th>
            <th>Threat</th>
            <th>Time</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-700">
          {connections.length === 0 ? (
            <tr>
              <td colSpan={9} className="text-center py-8 text-dark-400">
                No connections found
              </td>
            </tr>
          ) : (
            connections.map((conn) => (
              <tr key={conn.id} className={conn.is_blocked ? 'bg-red-900/10' : ''}>
                <td className="font-mono text-sm">{conn.source_ip}</td>
                <td>
                  <div>
                    {conn.destination_domain && (
                      <p className="text-white">{conn.destination_domain}</p>
                    )}
                    <p className="text-dark-400 text-xs font-mono">
                      {conn.destination_ip}
                    </p>
                  </div>
                </td>
                <td className="font-mono">{conn.destination_port}</td>
                <td>
                  <span className="px-2 py-1 bg-dark-700 rounded text-sm">
                    {conn.protocol}
                  </span>
                </td>
                <td>
                  <div className="text-sm">
                    <p className="text-green-400">
                      ↑ {formatBytes(conn.bytes_sent)}
                    </p>
                    <p className="text-blue-400">
                      ↓ {formatBytes(conn.bytes_received)}
                    </p>
                  </div>
                </td>
                <td>
                  <span className={getStatusColor(conn.connection_status)}>
                    {conn.connection_status}
                  </span>
                </td>
                <td>
                  <span
                    className={`px-2 py-1 rounded text-sm ${getThreatScoreColor(
                      conn.threat_score
                    )}`}
                  >
                    {(conn.threat_score * 100).toFixed(0)}%
                  </span>
                </td>
                <td className="text-dark-400 text-sm">
                  {formatDate(conn.timestamp)}
                </td>
                <td>
                  {conn.is_blocked ? (
                    onUnblock && (
                      <button
                        onClick={() => onUnblock(conn.source_ip)}
                        className="p-1.5 text-green-400 hover:bg-dark-700 rounded-lg transition-colors"
                        title="Unblock IP"
                      >
                        <Unlock className="w-4 h-4" />
                      </button>
                    )
                  ) : (
                    onBlock && (
                      <button
                        onClick={() => onBlock(conn.source_ip)}
                        className="p-1.5 text-red-400 hover:bg-dark-700 rounded-lg transition-colors"
                        title="Block IP"
                      >
                        <Ban className="w-4 h-4" />
                      </button>
                    )
                  )}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

export default ConnectionsTable;
