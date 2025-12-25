import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Ban, Bell, Loader2 } from 'lucide-react';
import { dashboardAPI } from '../services/api';
import {
  StatsCard,
  ThreatChart,
  SeverityPieChart,
  RecentThreats,
  TopBlockedDomains,
} from '../components/Dashboard';
import { formatNumber } from '../utils/helpers';

interface DashboardStats {
  total_scans: number;
  phishing_detected: number;
  blocked_threats: number;
  active_alerts: number;
  scan_rate: number;
  detection_rate: number;
}

const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [severityDist, setSeverityDist] = useState<Record<string, number>>({});
  const [trends, setTrends] = useState<any[]>([]);
  const [recentThreats, setRecentThreats] = useState<any[]>([]);
  const [topBlocked, setTopBlocked] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    setIsLoading(true);
    try {
      const [statsRes, severityRes, trendsRes, threatsRes, blockedRes] = await Promise.all([
        dashboardAPI.getStats(7),
        dashboardAPI.getSeverityDistribution(7),
        dashboardAPI.getTrends(7),
        dashboardAPI.getRecentThreats(5),
        dashboardAPI.getTopBlocked(5, 7),
      ]);

      setStats(statsRes.data);
      setSeverityDist(severityRes.data);
      setTrends(trendsRes.data);
      setRecentThreats(threatsRes.data);
      setTopBlocked(blockedRes.data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setIsLoading(false);
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
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-500 mt-1">Security overview and threat monitoring</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatsCard
          title="Total Scans"
          value={formatNumber(stats?.total_scans || 0)}
          change={stats?.scan_rate}
          icon={Shield}
          iconColor="text-blue-400"
          iconBgColor="bg-blue-500/20"
        />
        <StatsCard
          title="Phishing Detected"
          value={formatNumber(stats?.phishing_detected || 0)}
          icon={AlertTriangle}
          iconColor="text-red-400"
          iconBgColor="bg-red-500/20"
        />
        <StatsCard
          title="Blocked Threats"
          value={formatNumber(stats?.blocked_threats || 0)}
          icon={Ban}
          iconColor="text-orange-400"
          iconBgColor="bg-orange-500/20"
        />
        <StatsCard
          title="Active Alerts"
          value={formatNumber(stats?.active_alerts || 0)}
          icon={Bell}
          iconColor="text-yellow-400"
          iconBgColor="bg-yellow-500/20"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ThreatChart data={trends} />
        </div>
        <SeverityPieChart data={severityDist} />
      </div>

      {/* Recent Activity Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RecentThreats threats={recentThreats} />
        <TopBlockedDomains domains={topBlocked} />
      </div>

      {/* Detection Rate Card */}
      <div className="card">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Detection Rate</h3>
            <p className="text-gray-500 text-sm mt-1">
              Percentage of scanned URLs identified as phishing
            </p>
          </div>
          <div className="text-right">
            <p className="text-4xl font-bold text-gray-900">
              {stats?.detection_rate?.toFixed(1) || 0}%
            </p>
            <p className="text-gray-500 text-sm">Last 7 days</p>
          </div>
        </div>
        <div className="h-3 bg-gray-200 rounded-full mt-4 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500 rounded-full transition-all duration-1000"
            style={{ width: `${Math.min(stats?.detection_rate || 0, 100)}%` }}
          />
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
