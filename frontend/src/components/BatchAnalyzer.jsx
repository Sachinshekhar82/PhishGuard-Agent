import React, { useState } from 'react';
import { 
  Layers, 
  Download, 
  Search, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  FileSpreadsheet,
  Trash2
} from 'lucide-react';

export default function BatchAnalyzer({ llmEnabled }) {
  const [inputText, setInputText] = useState('');
  const [offlineMode, setOfflineMode] = useState(true);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterVerdict, setFilterVerdict] = useState('ALL');
  const [error, setError] = useState(null);

  const handleBatchAnalyze = async () => {
    const lines = inputText
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    if (lines.length === 0) return;
    if (lines.length > 50) {
      setError('Please limit batch submissions to a maximum of 50 URLs.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/analyze/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          urls: lines,
          offline_mode: offlineMode
        })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Batch analysis failed');
      }

      const data = await response.json();
      setResults(data.results || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const exportToCSV = () => {
    if (results.length === 0) return;

    const headers = ['URL', 'Verdict', 'Risk Score', 'Confidence', 'Summary'];
    const rows = results.map((r) => [
      `"${r.url.replace(/"/g, '""')}"`,
      r.verdict,
      r.risk_score,
      `${(r.confidence * 100).toFixed(0)}%`,
      `"${r.summary.replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard_batch_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredResults = results.filter((item) => {
    const matchesSearch = item.url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterVerdict === 'ALL' || item.verdict.toUpperCase() === filterVerdict;
    return matchesSearch && matchesFilter;
  });

  return (
    <div className="space-y-6">
      {/* Batch Input Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-blue-400" />
            <h3 className="font-bold text-slate-100 text-sm">Batch URL Submission (Max 50 URLs)</h3>
          </div>
          <span className="text-xs text-slate-400">One URL per line</span>
        </div>

        <textarea
          rows={5}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="https://example.com&#10;http://paypal-verification-account.xyz/login&#10;http://192.168.1.50/bank/auth"
          className="w-full p-4 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
        />

        <div className="flex flex-wrap items-center justify-between gap-4 mt-4 pt-2">
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={offlineMode}
              onChange={(e) => setOfflineMode(e.target.checked)}
              className="rounded border-slate-700 text-blue-600 bg-slate-950 w-4 h-4 focus:ring-0"
            />
            <span>Offline Mode (Strictly local inference)</span>
          </label>

          <div className="flex items-center gap-3">
            {inputText && (
              <button
                type="button"
                onClick={() => setInputText('')}
                className="px-3 py-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                Clear
              </button>
            )}
            <button
              onClick={handleBatchAnalyze}
              disabled={loading || !inputText.trim()}
              className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 text-white font-medium text-xs rounded-xl shadow-md transition-all flex items-center gap-2"
            >
              {loading ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  Processing Batch...
                </>
              ) : (
                'Run Batch Analysis'
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-rose-950/60 border border-rose-800 text-rose-300 rounded-xl text-xs">
            {error}
          </div>
        )}
      </div>

      {/* Results Section */}
      {results.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <h3 className="font-bold text-slate-100 text-sm">Batch Results ({filteredResults.length} of {results.length})</h3>
              
              {/* Filter Pills */}
              <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-[11px]">
                {['ALL', 'PHISHING', 'SUSPICIOUS', 'LEGITIMATE'].map((f) => (
                  <button
                    key={f}
                    onClick={() => setFilterVerdict(f)}
                    className={`px-2.5 py-1 rounded-md transition-all ${filterVerdict === f ? 'bg-blue-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filter URL..."
                  className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500 w-44"
                />
              </div>

              <button
                onClick={exportToCSV}
                className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium flex items-center gap-1.5 border border-slate-700 transition-colors"
              >
                <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                Export CSV
              </button>
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto border border-slate-800 rounded-xl">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase font-mono text-[11px]">
                <tr>
                  <th className="py-3 px-4">URL</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Top Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono text-xs">
                {filteredResults.map((r, i) => (
                  <tr key={i} className="hover:bg-slate-850/50 transition-colors">
                    <td className="py-3 px-4 max-w-xs truncate text-slate-300 font-sans" title={r.url}>
                      {r.url}
                    </td>
                    <td className="py-3 px-4">
                      {r.verdict === 'Phishing' && (
                        <span className="px-2 py-0.5 rounded text-[11px] bg-rose-950/80 text-rose-400 border border-rose-800/60 font-semibold">
                          Phishing
                        </span>
                      )}
                      {r.verdict === 'Suspicious' && (
                        <span className="px-2 py-0.5 rounded text-[11px] bg-amber-950/80 text-amber-400 border border-amber-800/60 font-semibold">
                          Suspicious
                        </span>
                      )}
                      {r.verdict === 'Legitimate' && (
                        <span className="px-2 py-0.5 rounded text-[11px] bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 font-semibold">
                          Legitimate
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-bold text-white">
                      {r.risk_score} / 100
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {(r.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-sans max-w-sm truncate" title={r.reasons?.[0]?.reason || ''}>
                      {r.reasons?.[0]?.reason || 'None detected'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
