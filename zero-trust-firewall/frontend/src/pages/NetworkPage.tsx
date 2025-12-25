import React, { useState, useEffect } from 'react';
import { Activity, Loader2, RefreshCw, Wifi, WifiOff } from 'lucide-react';
import { networkAPI } from '../services/api';
import { NetworkStats, ConnectionsTable } from '../components/NetworkMonitor';
import { formatBytes } from '../utils/helpers';
import toast from 'react-hot-toast';

const NetworkPage: React.FC = () => {
  const [connections, setConnections] = useState<any[]>([]);
  const [protocols, setProtocols] = useState<any[]>([]);
  const [bandwidth, setBandwidth] = useState<any[]>([]);
  const [realTimeStats, setRealTimeStats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchRealTimeStats, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchConnections();
  }, [page]);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      await Promise.all([
        fetchConnections(),
        fetchProtocols(),
        fetchBandwidth(),
        fetchRealTimeStats(),
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchConnections = async () => {
    try {
      const response = await networkAPI.getConnections({ page, page_size: 20 });
      setConnections(response.data.items);
      setTotalPages(response.data.pages);
    } catch (error) {
      console.error('Failed to fetch connections:', error);
    }
  };

  const fetchProtocols = async () => {
    try {
      const response = await networkAPI.getProtocols(24);
      setProtocols(response.data);
    } catch (error) {
      console.error('Failed to fetch protocols:', error);
    }
  };

  const fetchBandwidth = async () => {
    try {
      const response = await networkAPI.getBandwidth(24);
      setBandwidth(response.data);
    } catch (error) {
      console.error('Failed to fetch bandwidth:', error);
    }
  };

  const fetchRealTimeStats = async () => {
    try {
      const response = await networkAPI.getRealTime();
      setRealTimeStats(response.data);
    } catch (error) {
      console.error('Failed to fetch real-time stats:', error);
    }
  };

  const handleBlockIP = async (ip: string) => {
    try {
      await networkAPI.blockIP(ip, 'Manually blocked');
      toast.success(`IP ${ip} blocked`);
      fetchConnections();
    } catch {
      toast.error('Failed to block IP');
    }
  };

  const handleUnblockIP = async (ip: string) => {
    try {
      await networkAPI.unblockIP(ip);
      toast.success(`IP ${ip} unblocked`);
      fetchConnections();
    } catch {
      toast.error('Failed to unblock IP');
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Network Monitor</h1>
          <p className="text-dark-400 mt-1">Real-time network traffic analysis</p>
        </div>
        <button onClick={fetchData} className="btn btn-secondary flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Real-time Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-green-500/20 rounded-xl">
              <Wifi className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Active Connections</p>
              <p className="text-2xl font-bold text-white">
                {realTimeStats?.active_connections || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-red-500/20 rounded-xl">
              <WifiOff className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Blocked IPs</p>
              <p className="text-2xl font-bold text-white">
                {realTimeStats?.blocked_ips_count || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-blue-500/20 rounded-xl">
              <Activity className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Outbound Traffic</p>
              <p className="text-2xl font-bold text-white">
                {formatBytes(realTimeStats?.bytes_per_second_sent || 0)}/s
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-purple-500/20 rounded-xl">
              <Activity className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Inbound Traffic</p>
              <p className="text-2xl font-bold text-white">
                {formatBytes(realTimeStats?.bytes_per_second_received || 0)}/s
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <NetworkStats protocols={protocols} bandwidth={bandwidth} />

      {/* Connections Table */}
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Recent Connections</h3>
        <ConnectionsTable
          connections={connections}
          onBlock={handleBlockIP}
          onUnblock={handleUnblockIP}
        />

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-dark-700">
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
      </div>
    </div>
  );
};

export default NetworkPage;
