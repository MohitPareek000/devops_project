import React from 'react';
import { ExternalLink, Eye, Trash2 } from 'lucide-react';
import { formatDate, getSeverityBadgeClass, truncateUrl } from '../../utils/helpers';

interface Threat {
  id: number;
  url: string;
  domain: string;
  is_phishing: boolean;
  confidence_score: number;
  severity: string;
  status: string;
  scanned_at: string;
}

interface ThreatTableProps {
  threats: Threat[];
  onView: (threat: Threat) => void;
  onDelete?: (id: number) => void;
}

const ThreatTable: React.FC<ThreatTableProps> = ({ threats, onView, onDelete }) => {
  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      active: 'bg-blue-900/50 text-blue-400 border-blue-800',
      blocked: 'bg-red-900/50 text-red-400 border-red-800',
      resolved: 'bg-green-900/50 text-green-400 border-green-800',
      false_positive: 'bg-gray-900/50 text-gray-400 border-gray-700',
    };
    return styles[status] || styles.active;
  };

  return (
    <div className="table-container">
      <table className="table">
        <thead>
          <tr>
            <th>Domain / URL</th>
            <th>Verdict</th>
            <th>Confidence</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Scanned At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-700">
          {threats.length === 0 ? (
            <tr>
              <td colSpan={7} className="text-center py-8 text-dark-400">
                No threats found
              </td>
            </tr>
          ) : (
            threats.map((threat) => (
              <tr key={threat.id}>
                <td>
                  <div>
                    <p className="font-medium text-white">{threat.domain}</p>
                    <p className="text-dark-400 text-xs mt-1">
                      {truncateUrl(threat.url, 50)}
                    </p>
                  </div>
                </td>
                <td>
                  <span
                    className={`inline-flex items-center gap-1 ${
                      threat.is_phishing ? 'text-red-400' : 'text-green-400'
                    }`}
                  >
                    <div
                      className={`w-2 h-2 rounded-full ${
                        threat.is_phishing ? 'bg-red-500' : 'bg-green-500'
                      }`}
                    />
                    {threat.is_phishing ? 'Phishing' : 'Safe'}
                  </span>
                </td>
                <td>
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-dark-700 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          threat.is_phishing ? 'bg-red-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${threat.confidence_score * 100}%` }}
                      />
                    </div>
                    <span className="text-dark-300 text-sm">
                      {(threat.confidence_score * 100).toFixed(0)}%
                    </span>
                  </div>
                </td>
                <td>
                  <span className={`badge ${getSeverityBadgeClass(threat.severity)}`}>
                    {threat.severity}
                  </span>
                </td>
                <td>
                  <span
                    className={`inline-flex px-2 py-1 rounded-full text-xs font-medium border ${getStatusBadge(
                      threat.status
                    )}`}
                  >
                    {threat.status.replace('_', ' ')}
                  </span>
                </td>
                <td className="text-dark-300">{formatDate(threat.scanned_at)}</td>
                <td>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onView(threat)}
                      className="p-1.5 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                      title="View details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    <a
                      href={threat.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-1.5 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                      title="Open URL"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                    {onDelete && (
                      <button
                        onClick={() => onDelete(threat.id)}
                        className="p-1.5 text-dark-400 hover:text-red-400 hover:bg-dark-700 rounded-lg transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

export default ThreatTable;
