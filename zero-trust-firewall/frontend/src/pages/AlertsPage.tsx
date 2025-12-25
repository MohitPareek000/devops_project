import React, { useState, useEffect } from 'react';
import { Bell, Check, Loader2, Filter } from 'lucide-react';
import { alertsAPI } from '../services/api';
import { AlertsList } from '../components/Alerts';
import toast from 'react-hot-toast';

interface AlertCounts {
  total: number;
  unread: number;
  unacknowledged: number;
  by_severity: Record<string, number>;
}

const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [counts, setCounts] = useState<AlertCounts | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [filters, setFilters] = useState({
    severity: '',
    is_read: undefined as boolean | undefined,
    is_acknowledged: undefined as boolean | undefined,
  });

  useEffect(() => {
    fetchAlerts();
    fetchCounts();
  }, [page, filters]);

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const response = await alertsAPI.getAlerts({
        page,
        page_size: 20,
        severity: filters.severity || undefined,
        is_read: filters.is_read,
        is_acknowledged: filters.is_acknowledged,
      });
      setAlerts(response.data.items);
      setTotalPages(response.data.pages);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchCounts = async () => {
    try {
      const response = await alertsAPI.getCount();
      setCounts(response.data);
    } catch (error) {
      console.error('Failed to fetch counts:', error);
    }
  };

  const handleMarkRead = async (id: number) => {
    try {
      await alertsAPI.updateAlert(id, { is_read: true });
      fetchAlerts();
      fetchCounts();
    } catch {
      toast.error('Failed to mark as read');
    }
  };

  const handleAcknowledge = async (id: number) => {
    try {
      await alertsAPI.updateAlert(id, { is_acknowledged: true });
      toast.success('Alert acknowledged');
      fetchAlerts();
      fetchCounts();
    } catch {
      toast.error('Failed to acknowledge');
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await alertsAPI.deleteAlert(id);
      toast.success('Alert deleted');
      fetchAlerts();
      fetchCounts();
    } catch {
      toast.error('Failed to delete');
    }
  };

  const handleView = (alert: any) => {
    console.log('View alert:', alert);
  };

  const handleMarkAllRead = async () => {
    try {
      await alertsAPI.markAllRead();
      toast.success('All alerts marked as read');
      fetchAlerts();
      fetchCounts();
    } catch {
      toast.error('Failed to mark all as read');
    }
  };

  const handleAcknowledgeAll = async () => {
    try {
      await alertsAPI.acknowledgeAll();
      toast.success('All alerts acknowledged');
      fetchAlerts();
      fetchCounts();
    } catch {
      toast.error('Failed to acknowledge all');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Alerts</h1>
          <p className="text-dark-400 mt-1">Security alerts and notifications</p>
        </div>
        <div className="flex gap-2">
          <button onClick={handleMarkAllRead} className="btn btn-secondary flex items-center gap-2">
            <Bell className="w-4 h-4" />
            Mark All Read
          </button>
          <button onClick={handleAcknowledgeAll} className="btn btn-primary flex items-center gap-2">
            <Check className="w-4 h-4" />
            Acknowledge All
          </button>
        </div>
      </div>

      {/* Stats */}
      {counts && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card text-center">
            <p className="text-3xl font-bold text-white">{counts.total}</p>
            <p className="text-dark-400 text-sm">Total Alerts</p>
          </div>
          <div className="card text-center">
            <p className="text-3xl font-bold text-blue-400">{counts.unread}</p>
            <p className="text-dark-400 text-sm">Unread</p>
          </div>
          <div className="card text-center">
            <p className="text-3xl font-bold text-yellow-400">{counts.unacknowledged}</p>
            <p className="text-dark-400 text-sm">Pending</p>
          </div>
          <div className="card text-center">
            <p className="text-3xl font-bold text-red-400">
              {counts.by_severity?.critical || 0}
            </p>
            <p className="text-dark-400 text-sm">Critical</p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="w-5 h-5 text-dark-400" />
          <h3 className="font-medium text-white">Filters</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="label">Severity</label>
            <select
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
              className="input"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
          <div>
            <label className="label">Status</label>
            <select
              value={
                filters.is_read === undefined
                  ? ''
                  : filters.is_read
                  ? 'read'
                  : 'unread'
              }
              onChange={(e) =>
                setFilters({
                  ...filters,
                  is_read:
                    e.target.value === '' ? undefined : e.target.value === 'read',
                })
              }
              className="input"
            >
              <option value="">All</option>
              <option value="unread">Unread</option>
              <option value="read">Read</option>
            </select>
          </div>
          <div>
            <label className="label">Acknowledged</label>
            <select
              value={
                filters.is_acknowledged === undefined
                  ? ''
                  : filters.is_acknowledged
                  ? 'yes'
                  : 'no'
              }
              onChange={(e) =>
                setFilters({
                  ...filters,
                  is_acknowledged:
                    e.target.value === '' ? undefined : e.target.value === 'yes',
                })
              }
              className="input"
            >
              <option value="">All</option>
              <option value="no">Pending</option>
              <option value="yes">Acknowledged</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
        </div>
      ) : (
        <>
          <AlertsList
            alerts={alerts}
            onMarkRead={handleMarkRead}
            onAcknowledge={handleAcknowledge}
            onDelete={handleDelete}
            onView={handleView}
          />

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-dark-400 text-sm">
                Page {page} of {totalPages}
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(page - 1)}
                  disabled={page <= 1}
                  className="btn btn-secondary"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage(page + 1)}
                  disabled={page >= totalPages}
                  className="btn btn-secondary"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default AlertsPage;
