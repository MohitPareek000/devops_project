import React, { useState } from 'react';
import { Search, AlertTriangle, CheckCircle, Loader2, Info, Shield } from 'lucide-react';
import { urlAPI } from '../../services/api';
import toast from 'react-hot-toast';
import { getSeverityBadgeClass, getSeverityColor } from '../../utils/helpers';

interface ScanResult {
  url: string;
  domain: string;
  is_phishing: boolean;
  confidence_score: number;
  ml_score: number;
  bert_score: number;
  severity: string;
  verdict: string;
  reason: string;
  features: Record<string, any>;
  detection_weights?: {
    bert: number;
    ml: number;
  };
}

const URLScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      toast.error('Please enter a URL to scan');
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await urlAPI.scan(url);
      setResult(response.data);
      if (response.data.is_phishing) {
        toast.error('Phishing URL detected!');
      } else {
        toast.success('URL appears safe');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to scan URL');
      toast.error('Scan failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Scanner Form */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 bg-blue-500/20 rounded-xl">
            <Search className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">URL Scanner</h2>
            <p className="text-dark-400 text-sm">
              Scan any URL for phishing indicators using ML and rule-based detection
            </p>
          </div>
        </div>

        <form onSubmit={handleScan} className="flex gap-4">
          <div className="flex-1">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan (e.g., https://example.com)"
              className="input"
              disabled={isLoading}
            />
          </div>
          <button
            type="submit"
            disabled={isLoading || !url.trim()}
            className="btn btn-primary flex items-center gap-2"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                Scan URL
              </>
            )}
          </button>
        </form>
      </div>

      {/* Error */}
      {error && (
        <div className="card bg-red-900/20 border-red-800">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-red-400" />
            <div>
              <h3 className="font-medium text-red-400">Scan Error</h3>
              <p className="text-dark-300 text-sm">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="space-y-6 animate-fade-in">
          {/* Verdict Card */}
          <div
            className={`card ${
              result.is_phishing
                ? 'bg-red-900/20 border-red-800'
                : 'bg-green-900/20 border-green-800'
            }`}
          >
            <div className="flex items-start gap-4">
              {result.is_phishing ? (
                <div className="p-4 bg-red-500/20 rounded-xl">
                  <AlertTriangle className="w-8 h-8 text-red-400" />
                </div>
              ) : (
                <div className="p-4 bg-green-500/20 rounded-xl">
                  <CheckCircle className="w-8 h-8 text-green-400" />
                </div>
              )}
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <h3
                    className={`text-2xl font-bold ${
                      result.is_phishing ? 'text-red-400' : 'text-green-400'
                    }`}
                  >
                    {result.is_phishing ? 'Phishing Detected' : 'URL Appears Safe'}
                  </h3>
                  <span className={`badge ${getSeverityBadgeClass(result.severity)}`}>
                    {result.severity}
                  </span>
                </div>
                <p className="text-dark-300 mt-2">{result.reason}</p>
                <p className="text-dark-400 text-sm mt-2 break-all">{result.url}</p>
              </div>
            </div>
          </div>

          {/* Scores */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="card">
              <h4 className="text-dark-400 text-sm font-medium mb-2">
                Hybrid Score
              </h4>
              <div className="flex items-end gap-2">
                <span className={`text-3xl font-bold ${getSeverityColor(result.severity)}`}>
                  {(result.confidence_score * 100).toFixed(1)}%
                </span>
              </div>
              <div className="h-2 bg-dark-700 rounded-full mt-3 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    result.is_phishing ? 'bg-red-500' : 'bg-green-500'
                  }`}
                  style={{ width: `${result.confidence_score * 100}%` }}
                />
              </div>
              <p className="text-dark-500 text-xs mt-2">BERT (50%) + ML (50%)</p>
            </div>

            <div className="card">
              <h4 className="text-dark-400 text-sm font-medium mb-2">BERT/Deep Learning</h4>
              <div className="flex items-end gap-2">
                <span className="text-3xl font-bold text-emerald-400">
                  {((result.bert_score || 0) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="h-2 bg-dark-700 rounded-full mt-3 overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                  style={{ width: `${(result.bert_score || 0) * 100}%` }}
                />
              </div>
              <p className="text-dark-500 text-xs mt-2">Semantic analysis (50%)</p>
            </div>

            <div className="card">
              <h4 className="text-dark-400 text-sm font-medium mb-2">ML Detection</h4>
              <div className="flex items-end gap-2">
                <span className="text-3xl font-bold text-blue-400">
                  {(result.ml_score * 100).toFixed(1)}%
                </span>
              </div>
              <div className="h-2 bg-dark-700 rounded-full mt-3 overflow-hidden">
                <div
                  className="h-full bg-blue-500 rounded-full transition-all duration-500"
                  style={{ width: `${result.ml_score * 100}%` }}
                />
              </div>
              <p className="text-dark-500 text-xs mt-2">RandomForest (50%)</p>
            </div>
          </div>

          {/* Features */}
          {result.features && (
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <Info className="w-5 h-5 text-dark-400" />
                <h4 className="text-lg font-semibold text-white">URL Features</h4>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {Object.entries(result.features)
                  .filter(([key]) => !['suspicious_keywords', 'domain', 'subdomain', 'path', 'query', 'tld'].includes(key))
                  .slice(0, 12)
                  .map(([key, value]) => (
                    <div key={key} className="bg-dark-900 rounded-lg p-3">
                      <p className="text-dark-400 text-xs uppercase tracking-wider">
                        {key.replace(/_/g, ' ')}
                      </p>
                      <p className="text-white font-medium mt-1">
                        {typeof value === 'boolean'
                          ? value
                            ? 'Yes'
                            : 'No'
                          : typeof value === 'number'
                          ? value.toFixed(2)
                          : String(value)}
                      </p>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default URLScanner;
