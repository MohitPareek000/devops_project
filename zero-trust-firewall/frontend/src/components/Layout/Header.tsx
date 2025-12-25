import React, { useState, useEffect } from 'react';
import { Bell, Search, Menu } from 'lucide-react';
import { alertsAPI } from '../../services/api';
import { formatRelativeTime } from '../../utils/helpers';

interface Alert {
  id: number;
  title: string;
  severity: string;
  created_at: string;
}

interface HeaderProps {
  onMenuClick?: () => void;
}

const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [showAlerts, setShowAlerts] = useState(false);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fetchAlerts = async () => {
    try {
      const response = await alertsAPI.getUnread(5);
      setAlerts(response.data.alerts);
      setUnreadCount(response.data.unread_count);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    }
  };

  const getSeverityDot = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-green-500',
      info: 'bg-blue-500',
    };
    return colors[severity] || 'bg-gray-500';
  };

  return (
    <header className="bg-dark-900 border-b border-dark-700 px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={onMenuClick}
            className="lg:hidden p-2 text-dark-400 hover:text-white hover:bg-dark-800 rounded-lg"
          >
            <Menu className="w-5 h-5" />
          </button>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-dark-400" />
            <input
              type="text"
              placeholder="Search threats, URLs, IPs..."
              className="w-80 pl-10 pr-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white placeholder-dark-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Alert button */}
          <div className="relative">
            <button
              onClick={() => setShowAlerts(!showAlerts)}
              className="relative p-2 text-dark-400 hover:text-white hover:bg-dark-800 rounded-lg transition-colors"
            >
              <Bell className="w-5 h-5" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-xs font-bold rounded-full flex items-center justify-center">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>

            {/* Alert dropdown */}
            {showAlerts && (
              <div className="absolute right-0 mt-2 w-80 bg-dark-800 border border-dark-700 rounded-xl shadow-xl z-50">
                <div className="px-4 py-3 border-b border-dark-700">
                  <h3 className="font-semibold text-white">Notifications</h3>
                  <p className="text-sm text-dark-400">{unreadCount} unread alerts</p>
                </div>
                <div className="max-h-96 overflow-y-auto">
                  {alerts.length === 0 ? (
                    <div className="px-4 py-6 text-center text-dark-400">
                      No new alerts
                    </div>
                  ) : (
                    alerts.map((alert) => (
                      <div
                        key={alert.id}
                        className="px-4 py-3 hover:bg-dark-700 transition-colors cursor-pointer"
                      >
                        <div className="flex items-start gap-3">
                          <div className={`w-2 h-2 mt-2 rounded-full ${getSeverityDot(alert.severity)}`} />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-white truncate">{alert.title}</p>
                            <p className="text-xs text-dark-400">
                              {formatRelativeTime(alert.created_at)}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
                <div className="px-4 py-3 border-t border-dark-700">
                  <a
                    href="/alerts"
                    className="text-sm text-blue-400 hover:text-blue-300"
                  >
                    View all alerts
                  </a>
                </div>
              </div>
            )}
          </div>

          {/* Status indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-green-900/30 border border-green-800 rounded-full">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            <span className="text-sm text-green-400 font-medium">Protected</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
