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
      active: 'bg-blue-100 text-blue-700 border-blue-200',
      blocked: 'bg-red-100 text-red-700 border-red-200',
      resolved: 'bg-green-100 text-green-700 border-green-200',
      false_positive: 'bg-gray-100 text-gray-700 border-gray-200',
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
        <tbody className="divide-y divide-gray-200">
          {threats.length === 0 ? (
            <tr>
              <td colSpan={7} className="text-center py-8 text-gray-500">
                No threats found
              </td>
            </tr>
          ) : (
            threats.map((threat) => (
              <tr key={threat.id}>
                <td>
                  <div>
                    <p className="font-medium text-gray-900">{threat.domain}</p>
                    <p className="text-gray-500 text-xs mt-1">
                      {truncateUrl(threat.url, 50)}
                    </p>
                  </div>
                </td>
                <td>
                  <span
                    className={`inline-flex items-center gap-1 ${
                      threat.is_phishing ? 'text-red-600' : 'text-green-600'
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
                    <div className="w-16 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          threat.is_phishing ? 'bg-red-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${threat.confidence_score * 100}%` }}
                      />
                    </div>
                    <span className="text-gray-600 text-sm">
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
                <td className="text-gray-600">{formatDate(threat.scanned_at)}</td>
                <td>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onView(threat)}
                      className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                      title="View details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    <a
                      href={threat.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                      title="Open URL"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                    {onDelete && (
                      <button
                        onClick={() => onDelete(threat.id)}
                        className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-gray-100 rounded-lg transition-colors"
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
