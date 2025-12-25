import React from 'react';
import { Bell, Check, Eye, Trash2, AlertTriangle, Info, AlertCircle } from 'lucide-react';
import { formatRelativeTime, getSeverityBadgeClass } from '../../utils/helpers';

interface Alert {
  id: number;
  title: string;
  description: string;
  severity: string;
  alert_type: string;
  source: string;
  is_read: boolean;
  is_acknowledged: boolean;
  created_at: string;
}

interface AlertsListProps {
  alerts: Alert[];
  onMarkRead: (id: number) => void;
  onAcknowledge: (id: number) => void;
  onDelete: (id: number) => void;
  onView: (alert: Alert) => void;
}

const AlertsList: React.FC<AlertsListProps> = ({
  alerts,
  onMarkRead,
  onAcknowledge,
  onDelete,
  onView,
}) => {
  const getAlertIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <AlertCircle className="w-5 h-5 text-red-600" />;
      case 'high':
        return <AlertTriangle className="w-5 h-5 text-orange-600" />;
      case 'medium':
        return <AlertTriangle className="w-5 h-5 text-yellow-600" />;
      default:
        return <Info className="w-5 h-5 text-blue-600" />;
    }
  };

  return (
    <div className="space-y-3">
      {alerts.length === 0 ? (
        <div className="card text-center py-12">
          <Bell className="w-12 h-12 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500">No alerts to display</p>
        </div>
      ) : (
        alerts.map((alert) => (
          <div
            key={alert.id}
            className={`card transition-all hover:border-gray-300 ${
              !alert.is_read ? 'border-l-4 border-l-blue-500' : ''
            } ${alert.is_acknowledged ? 'opacity-60' : ''}`}
          >
            <div className="flex items-start gap-4">
              <div className="pt-1">{getAlertIcon(alert.severity)}</div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="font-medium text-gray-900">{alert.title}</h3>
                  <span className={`badge ${getSeverityBadgeClass(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  <span className="px-2 py-0.5 bg-gray-100 rounded text-xs text-gray-600">
                    {alert.alert_type}
                  </span>
                </div>
                <p className="text-gray-500 text-sm mt-1 line-clamp-2">
                  {alert.description}
                </p>
                <div className="flex items-center gap-4 mt-2 text-xs text-gray-400">
                  <span>Source: {alert.source}</span>
                  <span>{formatRelativeTime(alert.created_at)}</span>
                  {alert.is_acknowledged && (
                    <span className="text-green-600 flex items-center gap-1">
                      <Check className="w-3 h-3" />
                      Acknowledged
                    </span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => onView(alert)}
                  className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                  title="View details"
                >
                  <Eye className="w-4 h-4" />
                </button>
                {!alert.is_read && (
                  <button
                    onClick={() => onMarkRead(alert.id)}
                    className="p-2 text-gray-400 hover:text-blue-600 hover:bg-gray-100 rounded-lg transition-colors"
                    title="Mark as read"
                  >
                    <Bell className="w-4 h-4" />
                  </button>
                )}
                {!alert.is_acknowledged && (
                  <button
                    onClick={() => onAcknowledge(alert.id)}
                    className="p-2 text-gray-400 hover:text-green-600 hover:bg-gray-100 rounded-lg transition-colors"
                    title="Acknowledge"
                  >
                    <Check className="w-4 h-4" />
                  </button>
                )}
                <button
                  onClick={() => onDelete(alert.id)}
                  className="p-2 text-gray-400 hover:text-red-600 hover:bg-gray-100 rounded-lg transition-colors"
                  title="Delete"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
};

export default AlertsList;
