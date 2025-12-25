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
        <h3 className="text-lg font-semibold text-white">Recent Threats</h3>
        <a
          href="/threats"
          className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
        >
          View all
          <ExternalLink className="w-4 h-4" />
        </a>
      </div>

      {threats.length === 0 ? (
        <div className="text-center py-8">
          <AlertTriangle className="w-12 h-12 text-dark-500 mx-auto mb-3" />
          <p className="text-dark-400">No threats detected recently</p>
        </div>
      ) : (
        <div className="space-y-3">
          {threats.map((threat) => (
            <div
              key={threat.id}
              className="flex items-center justify-between p-3 bg-dark-900 rounded-lg hover:bg-dark-800 transition-colors"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`badge ${getSeverityBadgeClass(threat.severity)}`}>
                    {threat.severity}
                  </span>
                  <span className="text-white font-medium truncate">
                    {threat.domain}
                  </span>
                </div>
                <p className="text-dark-400 text-sm mt-1 truncate">
                  {truncateUrl(threat.url, 60)}
                </p>
              </div>
              <div className="text-right ml-4">
                <p className="text-dark-300 text-sm">
                  {(threat.confidence_score * 100).toFixed(0)}% confidence
                </p>
                <p className="text-dark-500 text-xs">
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
