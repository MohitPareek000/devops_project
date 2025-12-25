import React from 'react';
import { Ban } from 'lucide-react';
import { getSeverityBadgeClass } from '../../utils/helpers';

interface BlockedDomain {
  domain: string;
  count: number;
  severity?: string;
}

interface TopBlockedDomainsProps {
  domains: BlockedDomain[];
}

const TopBlockedDomains: React.FC<TopBlockedDomainsProps> = ({ domains }) => {
  const maxCount = Math.max(...domains.map((d) => d.count), 1);

  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-4">
        <Ban className="w-5 h-5 text-red-400" />
        <h3 className="text-lg font-semibold text-white">Top Blocked Domains</h3>
      </div>

      {domains.length === 0 ? (
        <div className="text-center py-8">
          <p className="text-dark-400">No blocked domains</p>
        </div>
      ) : (
        <div className="space-y-3">
          {domains.map((domain, index) => (
            <div key={domain.domain} className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-dark-500 text-sm w-5">{index + 1}.</span>
                  <span className="text-white font-medium truncate max-w-[200px]">
                    {domain.domain}
                  </span>
                  {domain.severity && (
                    <span className={`badge ${getSeverityBadgeClass(domain.severity)}`}>
                      {domain.severity}
                    </span>
                  )}
                </div>
                <span className="text-dark-300 text-sm">{domain.count} blocks</span>
              </div>
              <div className="h-1.5 bg-dark-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-red-500 rounded-full transition-all duration-500"
                  style={{ width: `${(domain.count / maxCount) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default TopBlockedDomains;
