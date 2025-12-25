import React from 'react';
import { ExternalLink, AlertTriangle } from 'lucide-react';
import { formatRelativeTime, getSeverityBadgeClass, truncateUrl } from '../../utils/helpers';

interface Threat {
  id: number;
  url: string;
  domain: string;
  severity: string;
  confidence_score: number;
  scanned_at: string;
}

interface RecentThreatsProps {
  threats: Threat[];
}

const RecentThreats: React.FC<RecentThreatsProps> = ({ threats }) => {
  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Recent Threats</h3>
        <a
          href="/threats"
          className="text-sm text-blue-600 hover:text-blue-700 flex items-center gap-1"
        >
          View all
          <ExternalLink className="w-4 h-4" />
        </a>
      </div>

      {threats.length === 0 ? (
        <div className="text-center py-8">
          <AlertTriangle className="w-12 h-12 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500">No threats detected recently</p>
        </div>
      ) : (
        <div className="space-y-3">
          {threats.map((threat) => (
            <div
              key={threat.id}
              className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`badge ${getSeverityBadgeClass(threat.severity)}`}>
                    {threat.severity}
                  </span>
                  <span className="text-gray-900 font-medium truncate">
                    {threat.domain}
                  </span>
                </div>
                <p className="text-gray-500 text-sm mt-1 truncate">
                  {truncateUrl(threat.url, 60)}
                </p>
              </div>
              <div className="text-right ml-4">
                <p className="text-gray-600 text-sm">
                  {(threat.confidence_score * 100).toFixed(0)}% confidence
                </p>
                <p className="text-gray-400 text-xs">
                  {formatRelativeTime(threat.scanned_at)}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default RecentThreats;
