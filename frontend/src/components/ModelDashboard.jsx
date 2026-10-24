import React, { useState, useEffect } from 'react';
import { 
  BarChart3, 
  Database, 
  Target, 
  Award, 
  TrendingUp, 
  CheckCircle, 
  Layers, 
  RotateCcw,
  ShieldCheck,
  Split
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  Tooltip, 
  CartesianGrid, 
  BarChart, 
  Bar 
} from 'recharts';

export default function ModelDashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchMetrics = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/metrics');
      if (res.ok) {
        const json = await res.json();
        setData(json);
      } else {
        throw new Error('Failed to load model metrics');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  if (loading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 font-mono text-xs">
        Loading model telemetry and real-world evaluation metrics...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-rose-950/60 border border-rose-800 text-rose-300 p-6 rounded-2xl text-xs">
        {error || 'Unable to load model metrics.'}
      </div>
    );
  }

  const modelMetrics = data.model_metrics || {};
  const datasetInfo = data.dataset_info || {};
  const testMetrics = modelMetrics.test_metrics || {};
  const sliceMetrics = modelMetrics.slice_metrics || {};
  const cm = testMetrics.confusion_matrix || [[0, 0], [0, 0]];
  const rocCurve = modelMetrics.roc_curve || [];
  const featureImportances = modelMetrics.feature_importances || [];

  return (
    <div className="space-y-6">
      {/* Header Info */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <span className="text-xs font-mono text-blue-400 font-semibold uppercase tracking-wider">
            Evaluation Telemetry
          </span>
          <h2 className="text-xl font-bold text-white flex items-center gap-2 mt-0.5">
            <Target className="w-5 h-5 text-blue-400" />
            {modelMetrics.model_name || 'Random Forest'} Model Performance
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Evaluated on held-out test split (15%) with strict domain grouping to prevent leakage.
          </p>
        </div>

        <button
          onClick={fetchMetrics}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors border border-slate-700"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Refresh Metrics
        </button>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-lg">
          <span className="text-[11px] text-slate-400 uppercase font-mono">Accuracy</span>
          <div className="text-2xl font-black text-white mt-1">
            {(testMetrics.accuracy * 100).toFixed(2)}%
          </div>
          <span className="text-[10px] text-emerald-400 flex items-center gap-1 mt-1 font-mono">
            <CheckCircle className="w-3 h-3" /> Overall Correct
          </span>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-lg">
          <span className="text-[11px] text-slate-400 uppercase font-mono">Precision</span>
          <div className="text-2xl font-black text-blue-400 mt-1">
            {(testMetrics.precision * 100).toFixed(2)}%
          </div>
          <span className="text-[10px] text-slate-400 mt-1 font-mono">
            Low False Positives
          </span>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-lg">
          <span className="text-[11px] text-slate-400 uppercase font-mono">Recall</span>
          <div className="text-2xl font-black text-purple-400 mt-1">
            {(testMetrics.recall * 100).toFixed(2)}%
          </div>
          <span className="text-[10px] text-slate-400 mt-1 font-mono">
            Phish Catch Rate
          </span>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-lg">
          <span className="text-[11px] text-slate-400 uppercase font-mono">F1 Score</span>
          <div className="text-2xl font-black text-emerald-400 mt-1">
            {testMetrics.f1?.toFixed(4)}
          </div>
          <span className="text-[10px] text-slate-400 mt-1 font-mono">
            Harmonic Balance
          </span>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-lg">
          <span className="text-[11px] text-slate-400 uppercase font-mono">ROC-AUC</span>
          <div className="text-2xl font-black text-amber-400 mt-1">
            {testMetrics.roc_auc?.toFixed(4)}
          </div>
          <span className="text-[10px] text-slate-400 mt-1 font-mono">
            Discrimination Index
          </span>
        </div>
      </div>

      {/* Dataset Provenance & Bias Mitigation Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Dataset Provenance Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-emerald-400" />
            <h3 className="font-bold text-slate-100 text-sm">Real Dataset Sources & Balance</h3>
          </div>

          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-mono">Total Dataset</span>
              <div className="text-lg font-bold text-white mt-0.5">{datasetInfo.total_urls?.toLocaleString() || '50,000'}</div>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-[10px] text-emerald-500 uppercase font-mono">Legitimate</span>
              <div className="text-lg font-bold text-emerald-400 mt-0.5">{datasetInfo.legitimate_count?.toLocaleString() || '25,000'}</div>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-[10px] text-rose-500 uppercase font-mono">Phishing</span>
              <div className="text-lg font-bold text-rose-400 mt-0.5">{datasetInfo.phishing_count?.toLocaleString() || '25,000'}</div>
            </div>
          </div>

          {/* Sources Breakdown */}
          <div className="space-y-2 pt-2 border-t border-slate-800/80 font-mono text-xs">
            <span className="text-slate-400 font-sans font-semibold text-[11px] block mb-1">Downloaded Feeds:</span>
            {datasetInfo.sources_count && Object.entries(datasetInfo.sources_count).map(([src, cnt]) => (
              cnt > 0 && (
                <div key={src} className="flex justify-between items-center py-1 border-b border-slate-850">
                  <span className="text-slate-300">{src}</span>
                  <span className="text-blue-400 font-bold">{cnt.toLocaleString()} URLs</span>
                </div>
              )
            ))}
          </div>

          <p className="text-[11px] text-slate-500 italic">
            {datasetInfo.notes || 'Prepared locally from public open datasets. No VirusTotal used.'}
          </p>
        </div>

        {/* Dataset Bias Mitigation & Slices Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2">
            <Split className="w-5 h-5 text-blue-400" />
            <h3 className="font-bold text-slate-100 text-sm">Dataset Bias Mitigation (Slice Testing)</h3>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Bare domains (e.g. Tranco) vs full paths (phishing feeds) cause naive models to falsely learn "has path = phishing". 
            PhishGuard mitigated this by enriching domains with realistic paths and validating slices separately:
          </p>

          <div className="space-y-3">
            {sliceMetrics.domain_only_slice && (
              <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800">
                <div className="flex justify-between items-center mb-1 text-xs">
                  <span className="font-bold text-slate-200">Domain-Only Test Slice</span>
                  <span className="font-mono text-slate-400 text-[11px]">N = {sliceMetrics.domain_only_slice.count} URLs</span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono mt-2">
                  <div className="p-2 bg-slate-900 rounded">
                    <span className="text-[10px] text-slate-400 block">Accuracy</span>
                    <strong className="text-white">{(sliceMetrics.domain_only_slice.accuracy * 100).toFixed(1)}%</strong>
                  </div>
                  <div className="p-2 bg-slate-900 rounded">
                    <span className="text-[10px] text-slate-400 block">Precision</span>
                    <strong className="text-blue-400">{(sliceMetrics.domain_only_slice.precision * 100).toFixed(1)}%</strong>
                  </div>
                  <div className="p-2 bg-slate-900 rounded">
                    <span className="text-[10px] text-slate-400 block">F1 Score</span>
                    <strong className="text-emerald-400">{sliceMetrics.domain_only_slice.f1?.toFixed(4)}</strong>
                  </div>
                </div>
              </div>
            )}

            {sliceMetrics.full_url_slice && (
              <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800">
                <div className="flex justify-between items-center mb-1 text-xs">
                  <span className="font-bold text-slate-200">Full-URL (Path) Test Slice</span>
                  <span className="font-mono text-slate-400 text-[11px]">N = {sliceMetrics.full_url_slice.count} URLs</span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono mt-2">
                  <div className="p-2 bg-slate-900 rounded">
                    <span className="text-[10px] text-slate-400 block">Accuracy</span>
                    <strong className="text-white">{(sliceMetrics.full_url_slice.accuracy * 100).toFixed(1)}%</strong>
                  </div>
                  <div className="p-2 bg-slate-900 rounded">
                    <span className="text-[10px] text-slate-400 block">Precision</span>
                    <strong className="text-blue-400">{(sliceMetrics.full_url_slice.precision * 100).toFixed(1)}%</strong>
                  </div>
                  <div className="p-2 bg-slate-900 rounded">
                    <span className="text-[10px] text-slate-400 block">F1 Score</span>
                    <strong className="text-emerald-400">{sliceMetrics.full_url_slice.f1?.toFixed(4)}</strong>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Visual Charts: Confusion Matrix & ROC Curve */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Confusion Matrix */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <h3 className="font-bold text-slate-100 text-sm flex items-center gap-2">
            <Layers className="w-4 h-4 text-purple-400" />
            Confusion Matrix (Held-out Test Split)
          </h3>

          <div className="grid grid-cols-2 gap-3 text-center font-mono">
            <div className="p-4 bg-emerald-950/40 border border-emerald-500/30 rounded-xl">
              <span className="text-[10px] text-emerald-400 uppercase block font-semibold">True Negatives (Legit)</span>
              <div className="text-2xl font-black text-white mt-1">{cm[0][0]}</div>
              <span className="text-[10px] text-slate-400 block mt-0.5">Correctly classified benign</span>
            </div>

            <div className="p-4 bg-rose-950/40 border border-rose-500/30 rounded-xl">
              <span className="text-[10px] text-rose-400 uppercase block font-semibold">False Positives</span>
              <div className="text-2xl font-black text-rose-300 mt-1">{cm[0][1]}</div>
              <span className="text-[10px] text-slate-400 block mt-0.5">Benign marked as phish</span>
            </div>

            <div className="p-4 bg-amber-950/40 border border-amber-500/30 rounded-xl">
              <span className="text-[10px] text-amber-400 uppercase block font-semibold">False Negatives</span>
              <div className="text-2xl font-black text-amber-300 mt-1">{cm[1][0]}</div>
              <span className="text-[10px] text-slate-400 block mt-0.5">Missed phishing attacks</span>
            </div>

            <div className="p-4 bg-blue-950/40 border border-blue-500/30 rounded-xl">
              <span className="text-[10px] text-blue-400 uppercase block font-semibold">True Positives (Phish)</span>
              <div className="text-2xl font-black text-white mt-1">{cm[1][1]}</div>
              <span className="text-[10px] text-slate-400 block mt-0.5">Correctly caught phishing</span>
            </div>
          </div>
        </div>

        {/* ROC Curve Chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <h3 className="font-bold text-slate-100 text-sm flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-amber-400" />
            Receiver Operating Characteristic (ROC Curve)
          </h3>

          <div className="h-56 w-full text-xs font-mono">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={rocCurve} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="fpr" type="number" domain={[0, 1]} tick={{ fill: '#64748b', fontSize: 10 }} />
                <YAxis dataKey="tpr" type="number" domain={[0, 1]} tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                  formatter={(val) => [val, 'True Positive Rate']}
                  labelFormatter={(val) => `False Pos Rate: ${val}`}
                />
                <Line type="monotone" dataKey="tpr" stroke="#3b82f6" strokeWidth={2.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Feature Importances Bar Chart */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <h3 className="font-bold text-slate-100 text-sm flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-emerald-400" />
          Top Predictive Features (Gini Importance)
        </h3>

        <div className="h-64 w-full text-xs font-mono">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={featureImportances.slice(0, 10)}
              layout="vertical"
              margin={{ top: 5, right: 20, left: 100, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis type="number" domain={[0, 'dataMax + 0.02']} tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis dataKey="feature" type="category" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                formatter={(val) => [val, 'Importance Weight']}
              />
              <Bar dataKey="importance" fill="#10b981" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
