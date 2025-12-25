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
        <Ban className="w-5 h-5 text-red-600" />
        <h3 className="text-lg font-semibold text-gray-900">Top Blocked Domains</h3>
      </div>

      {domains.length === 0 ? (
        <div className="text-center py-8">
          <p className="text-gray-500">No blocked domains</p>
        </div>
      ) : (
        <div className="space-y-3">
          {domains.map((domain, index) => (
            <div key={domain.domain} className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-gray-400 text-sm w-5">{index + 1}.</span>
                  <span className="text-gray-900 font-medium truncate max-w-[200px]">
                    {domain.domain}
                  </span>
                  {domain.severity && (
                    <span className={`badge ${getSeverityBadgeClass(domain.severity)}`}>
                      {domain.severity}
                    </span>
                  )}
                </div>
                <span className="text-gray-600 text-sm">{domain.count} blocks</span>
              </div>
              <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden">
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
