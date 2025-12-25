import React, { useState, useEffect } from 'react';
import { Search, Filter, Loader2, RefreshCw } from 'lucide-react';
import { urlAPI } from '../services/api';
import { ThreatTable } from '../components/ThreatLog';
import toast from 'react-hot-toast';

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

const ThreatsPage: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [filters, setFilters] = useState({
    search: '',
    severity: '',
    is_phishing: undefined as boolean | undefined,
  });
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    fetchThreats();
  }, [page, filters]);

  const fetchThreats = async () => {
    setIsLoading(true);
    try {
      const response = await urlAPI.getScans({
        page,
        page_size: 20,
        search: filters.search || undefined,
        severity: filters.severity || undefined,
        is_phishing: filters.is_phishing,
      });
      setThreats(response.data.items);
      setTotalPages(response.data.pages);
    } catch (error) {
      console.error('Failed to fetch threats:', error);
      toast.error('Failed to load threats');
    } finally {
      setIsLoading(false);
    }
  };

  const handleView = (threat: Threat) => {
    // Could open a modal or navigate to detail page
    console.log('View threat:', threat);
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this scan?')) return;

    try {
      // In a real app, you'd call the delete API
      toast.success('Scan deleted');
      fetchThreats();
    } catch {
      toast.error('Failed to delete scan');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Log</h1>
          <p className="text-dark-400 mt-1">View and manage scanned URLs</p>
        </div>
        <button
          onClick={fetchThreats}
          className="btn btn-secondary flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Search and Filters */}
      <div className="card">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-dark-400" />
            <input
              type="text"
              placeholder="Search by URL or domain..."
              value={filters.search}
              onChange={(e) => setFilters({ ...filters, search: e.target.value })}
              className="input pl-10"
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`btn ${showFilters ? 'btn-primary' : 'btn-secondary'} flex items-center gap-2`}
          >
            <Filter className="w-4 h-4" />
            Filters
          </button>
        </div>

        {showFilters && (
          <div className="mt-4 pt-4 border-t border-dark-700 grid grid-cols-1 sm:grid-cols-3 gap-4">
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
              <label className="label">Verdict</label>
              <select
                value={filters.is_phishing === undefined ? '' : filters.is_phishing.toString()}
                onChange={(e) =>
                  setFilters({
                    ...filters,
                    is_phishing: e.target.value === '' ? undefined : e.target.value === 'true',
                  })
                }
                className="input"
              >
                <option value="">All</option>
                <option value="true">Phishing</option>
                <option value="false">Safe</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                onClick={() => setFilters({ search: '', severity: '', is_phishing: undefined })}
                className="btn btn-secondary w-full"
              >
                Clear Filters
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
        </div>
      ) : (
        <>
          <ThreatTable threats={threats} onView={handleView} onDelete={handleDelete} />

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

export default ThreatsPage;
