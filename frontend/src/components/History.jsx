import React, { useState, useEffect } from 'react';
import { 
  History as HistoryIcon, 
  Trash2, 
  RotateCcw, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  ExternalLink,
  Search
} from 'lucide-react';

export default function History({ onReanalyze }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [error, setError] = useState(null);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/history');
      if (response.ok) {
        const data = await response.json();
        setHistory(data || []);
      }
    } catch (err) {
      setError('Failed to load history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleClear = async () => {
    if (!window.confirm('Are you sure you want to delete all URL analysis history records?')) return;
    try {
      await fetch('/api/history', { method: 'DELETE' });
      setHistory([]);
    } catch (err) {
      alert('Failed to clear history');
    }
  };

  const filtered = history.filter((item) =>
    item.url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <HistoryIcon className="w-5 h-5 text-blue-400" />
          <h3 className="font-bold text-slate-100 text-sm">Analysis History ({filtered.length})</h3>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search history..."
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500 w-48"
            />
          </div>

          <button
            onClick={fetchHistory}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-colors"
            title="Refresh history"
          >
            <RotateCcw className="w-4 h-4" />
          </button>

          {history.length > 0 && (
            <button
              onClick={handleClear}
              className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900/60 border border-rose-800/60 text-rose-300 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear History
            </button>
          )}
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12 text-slate-500 text-xs font-mono">Loading history records...</div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12 text-slate-500 text-xs">
          No analysis history found. Run URL scans from the Analyzer tab to populate records.
        </div>
      ) : (
        <div className="overflow-x-auto border border-slate-800 rounded-xl">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase font-mono text-[11px]">
              <tr>
                <th className="py-3 px-4">Date / Time</th>
                <th className="py-3 px-4">Target URL</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Mode</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono text-xs">
              {filtered.map((item) => (
                <tr key={item.id} className="hover:bg-slate-850/50 transition-colors">
                  <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                    {new Date(item.created_at).toLocaleString()}
                  </td>
                  <td className="py-3 px-4 max-w-sm truncate text-slate-200 font-sans" title={item.url}>
                    {item.url}
                  </td>
                  <td className="py-3 px-4">
                    {item.verdict === 'Phishing' && (
                      <span className="px-2 py-0.5 rounded text-[11px] bg-rose-950/80 text-rose-400 border border-rose-800/60 font-semibold">
                        Phishing
                      </span>
                    )}
                    {item.verdict === 'Suspicious' && (
                      <span className="px-2 py-0.5 rounded text-[11px] bg-amber-950/80 text-amber-400 border border-amber-800/60 font-semibold">
                        Suspicious
                      </span>
                    )}
                    {item.verdict === 'Legitimate' && (
                      <span className="px-2 py-0.5 rounded text-[11px] bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 font-semibold">
                        Legitimate
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 font-bold text-white">
                    {item.risk_score} / 100
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-[11px]">
                    {item.offline_mode ? 'Offline' : 'Online'}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => onReanalyze(item.url)}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-blue-600 text-slate-300 hover:text-white rounded text-xs transition-colors"
                      title="Re-analyze this URL in Analyzer"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
