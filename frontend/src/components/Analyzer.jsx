import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Search, 
  Activity, 
  Cpu, 
  Sparkles, 
  Wifi, 
  WifiOff, 
  ChevronDown, 
  ChevronRight, 
  Clock, 
  Layers, 
  CheckCircle2, 
  Info,
  ExternalLink,
  RotateCcw
} from 'lucide-react';

const EXAMPLES = [
  { label: 'Google Search', url: 'https://www.google.com/search?q=cybersecurity' },
  { label: 'GitHub Repository', url: 'https://github.com/torvalds/linux' },
  { label: 'PayPal Brand Phish', url: 'http://paypal-security-update.account-verify.xyz/login.php' },
  { label: 'Raw IP Bank Lure', url: 'http://192.168.1.100/chase-online/auth' },
  { label: 'Homoglyph Phish', url: 'http://micros0ft-support.buzz/verify' },
  { label: 'URL Shortener', url: 'http://bit.ly/3xyzMasked' },
];

export default function Analyzer({ onAnalyzeSuccess, llmEnabled }) {
  const [url, setUrl] = useState('');
  const [offlineMode, setOfflineMode] = useState(true);
  const [aiExplanation, setAiExplanation] = useState(false);
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [traceOpen, setTraceOpen] = useState(true);
  const [featuresOpen, setFeaturesOpen] = useState(false);

  const steps = [
    'Perceiving URL structure & encoding',
    'Planning diagnostic tool suite',
    'Executing ML and heuristic analyses',
    'Reflecting on score convergence',
    'Deciding final risk & verdict',
    'Synthesizing plain-English explanation'
  ];

  const handleAnalyze = async (e, overrideUrl = null) => {
    if (e) e.preventDefault();
    const targetUrl = overrideUrl || url;
    if (!targetUrl.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setActiveStep(0);

    // Simulated progress steps for the agentic loop
    const stepInterval = setInterval(() => {
      setActiveStep((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 180);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: targetUrl.trim(),
          offline_mode: offlineMode,
          ai_explanation: aiExplanation && llmEnabled
        })
      });

      clearInterval(stepInterval);

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ detail: 'Failed to analyze URL' }));
        throw new Error(errData.detail || 'Analysis request failed');
      }

      const data = await response.json();
      setResult(data);
      if (onAnalyzeSuccess) onAnalyzeSuccess(data);
    } catch (err) {
      clearInterval(stepInterval);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getVerdictBadge = (verdict) => {
    switch (verdict) {
      case 'Legitimate':
        return {
          bg: 'bg-emerald-950/80 border-emerald-500/40 text-emerald-400',
          gaugeColor: '#10b981',
          icon: <ShieldCheck className="w-6 h-6 text-emerald-400" />,
          label: 'LEGITIMATE'
        };
      case 'Suspicious':
        return {
          bg: 'bg-amber-950/80 border-amber-500/40 text-amber-400',
          gaugeColor: '#f59e0b',
          icon: <AlertTriangle className="w-6 h-6 text-amber-400" />,
          label: 'SUSPICIOUS'
        };
      case 'Phishing':
      default:
        return {
          bg: 'bg-rose-950/80 border-rose-500/40 text-rose-400',
          gaugeColor: '#ef4444',
          icon: <ShieldAlert className="w-6 h-6 text-rose-400" />,
          label: 'PHISHING DETECTED'
        };
    }
  };

  const getSeverityBadge = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-900/60 text-rose-300 border border-rose-700/50">Critical</span>;
      case 'high':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-orange-900/60 text-orange-300 border border-orange-700/50">High</span>;
      case 'medium':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-900/60 text-amber-300 border border-amber-700/50">Medium</span>;
      case 'low':
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-900/60 text-blue-300 border border-blue-700/50">Low</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Search & Control Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur-sm">
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div className="relative flex items-center">
            <div className="absolute left-4 pointer-events-none text-slate-400">
              <Search className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to inspect (e.g. http://paypal-security-update.xyz/login)..."
              className="w-full pl-12 pr-28 py-3.5 bg-slate-950/80 border border-slate-700 rounded-xl text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono transition-all"
            />
            {url && (
              <button
                type="button"
                onClick={() => setUrl('')}
                className="absolute right-28 text-xs text-slate-500 hover:text-slate-300 px-2 py-1"
              >
                Clear
              </button>
            )}
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="absolute right-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 text-white font-medium text-sm rounded-lg shadow-md transition-all flex items-center gap-2"
            >
              {loading ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  Analyzing
                </>
              ) : (
                'Analyze URL'
              )}
            </button>
          </div>

          {/* Quick Examples */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
            <span className="text-slate-400 font-medium mr-1">Quick Presets:</span>
            {EXAMPLES.map((ex, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setUrl(ex.url);
                  handleAnalyze(null, ex.url);
                }}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-md border border-slate-700/60 transition-colors"
              >
                {ex.label}
              </button>
            ))}
          </div>

          {/* Analysis Settings Toggles */}
          <div className="flex flex-wrap items-center justify-between gap-4 pt-3 border-t border-slate-800/80 text-xs text-slate-300">
            <div className="flex items-center gap-6">
              {/* Offline Mode Toggle */}
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={offlineMode}
                  onChange={(e) => setOfflineMode(e.target.checked)}
                  className="rounded border-slate-700 text-blue-600 focus:ring-0 bg-slate-950 w-4 h-4"
                />
                <span className="flex items-center gap-1.5 font-medium">
                  {offlineMode ? <WifiOff className="w-3.5 h-3.5 text-blue-400" /> : <Wifi className="w-3.5 h-3.5 text-emerald-400" />}
                  Offline Mode (Zero network egress)
                </span>
              </label>

              {/* AI Explanation Toggle */}
              <label 
                className={`flex items-center gap-2 select-none ${llmEnabled ? 'cursor-pointer' : 'cursor-not-allowed opacity-50'}`}
                title={llmEnabled ? "Enhance explanations with Gemini" : "Set GEMINI_API_KEY in .env to enable"}
              >
                <input
                  type="checkbox"
                  disabled={!llmEnabled}
                  checked={aiExplanation && llmEnabled}
                  onChange={(e) => setAiExplanation(e.target.checked)}
                  className="rounded border-slate-700 text-purple-600 focus:ring-0 bg-slate-950 w-4 h-4"
                />
                <span className="flex items-center gap-1.5 font-medium">
                  <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                  AI Explanation (Gemini)
                  {!llmEnabled && <span className="text-[10px] text-slate-500">(Disabled)</span>}
                </span>
              </label>
            </div>

            <span className="text-slate-500 italic">
              ⚡ Local ML + Heuristic analysis runs strictly on your machine
            </span>
          </div>
        </form>
      </div>

      {/* Loading Progress State */}
      {loading && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl animate-pulse">
          <div className="flex items-center gap-3 mb-4">
            <Cpu className="w-5 h-5 text-blue-400 animate-spin" />
            <h3 className="font-semibold text-slate-200 text-sm">Agentic AI Analysis in Progress...</h3>
          </div>
          <div className="space-y-3">
            {steps.map((st, i) => (
              <div key={i} className="flex items-center gap-3 text-xs">
                <div className={`w-2.5 h-2.5 rounded-full ${i <= activeStep ? 'bg-blue-500 animate-ping' : 'bg-slate-700'}`} />
                <span className={i === activeStep ? 'text-blue-400 font-semibold' : i < activeStep ? 'text-slate-400 line-through' : 'text-slate-600'}>
                  {st}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="bg-rose-950/80 border border-rose-800 text-rose-300 p-4 rounded-xl text-sm flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Analysis Result Card */}
      {result && !loading && (
        <div className="space-y-6">
          {/* Top Verdict & Score Hero */}
          <div className={`border rounded-2xl p-6 shadow-2xl backdrop-blur-sm ${getVerdictBadge(result.verdict).bg}`}>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
              {/* Left Column: Verdict Badge & URL */}
              <div className="md:col-span-2 space-y-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-slate-900/60 rounded-xl border border-white/10 shadow-inner">
                    {getVerdictBadge(result.verdict).icon}
                  </div>
                  <div>
                    <span className="text-xs font-bold tracking-wider uppercase opacity-80">Security Assessment</span>
                    <h2 className="text-2xl font-extrabold tracking-tight">{getVerdictBadge(result.verdict).label}</h2>
                  </div>
                </div>

                <div className="p-3 bg-slate-950/60 rounded-xl border border-white/10 break-all font-mono text-xs text-slate-300">
                  <span className="text-slate-500 select-none">Analyzed Target: </span>
                  {result.url}
                </div>

                {/* Plain-English Summary */}
                <p className="text-sm text-slate-200 leading-relaxed font-medium">
                  {result.summary}
                </p>

                {/* Optional AI Paragraph */}
                {result.ai_explanation && (
                  <div className="p-3.5 bg-purple-950/40 border border-purple-500/30 rounded-xl text-xs text-purple-200 flex items-start gap-2.5">
                    <Sparkles className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                    <div>
                      <span className="font-semibold text-purple-300 block mb-0.5">Gemini AI Synthesis:</span>
                      {result.ai_explanation}
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: Risk Gauge & Confidence */}
              <div className="flex flex-col items-center justify-center p-4 bg-slate-950/60 rounded-xl border border-white/10 text-center">
                <span className="text-xs text-slate-400 font-medium mb-1">Phishing Risk Score</span>
                
                {/* Visual Radial Meter */}
                <div className="relative w-32 h-32 flex items-center justify-center">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      stroke="#1e293b"
                      strokeWidth="10"
                      fill="transparent"
                    />
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      stroke={getVerdictBadge(result.verdict).gaugeColor}
                      strokeWidth="10"
                      strokeDasharray={`${2 * Math.PI * 40}`}
                      strokeDashoffset={`${2 * Math.PI * 40 * (1 - result.risk_score / 100)}`}
                      strokeLinecap="round"
                      fill="transparent"
                      className="transition-all duration-1000 ease-out"
                    />
                  </svg>
                  <div className="absolute flex flex-col items-center justify-center">
                    <span className="text-3xl font-black">{result.risk_score}</span>
                    <span className="text-[10px] text-slate-400 font-semibold uppercase">out of 100</span>
                  </div>
                </div>

                <div className="mt-3 flex items-center gap-2 text-xs text-slate-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                  <span>Detection Confidence: <strong className="text-white font-mono">{(result.confidence * 100).toFixed(0)}%</strong></span>
                </div>
              </div>
            </div>
          </div>

          {/* Key Contributing Reasons Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-400" />
              Primary Decision Factors ({result.reasons?.length || 0})
            </h3>

            {result.reasons && result.reasons.length > 0 ? (
              <div className="space-y-2.5">
                {result.reasons.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl flex items-center justify-between gap-4 text-xs transition-all hover:border-slate-700"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-slate-500 font-mono font-semibold">#{idx + 1}</span>
                      <span className="text-slate-200 font-medium leading-relaxed">{item.reason}</span>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      {getSeverityBadge(item.severity)}
                      {item.impact > 0 && (
                        <span className="text-slate-400 font-mono text-[11px]">+{item.impact.toFixed(0)} pts</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400 italic">No threat signals or anomalies identified.</p>
            )}
          </div>

          {/* Agent Trace Accordion */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
            <button
              onClick={() => setTraceOpen(!traceOpen)}
              className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-slate-800/40 transition-colors"
            >
              <div className="flex items-center gap-2.5">
                <Cpu className="w-4 h-4 text-blue-400" />
                <span className="text-sm font-bold text-slate-200 uppercase tracking-wider">Agentic Execution Trace</span>
                <span className="text-xs text-slate-500 font-mono">(Perceive → Plan → Act → Reflect → Decide)</span>
              </div>
              {traceOpen ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
            </button>

            {traceOpen && result.agent_trace && (
              <div className="px-6 pb-6 pt-2 space-y-4 border-t border-slate-800/80 text-xs">
                {/* Step 1 & 2: Perceive and Plan */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3.5 bg-slate-950/70 rounded-xl border border-slate-800 space-y-2">
                    <span className="font-semibold text-blue-400 flex items-center gap-1.5">
                      <Search className="w-3.5 h-3.5" /> 1. PERCEIVE Output
                    </span>
                    <div className="font-mono text-slate-300 space-y-1">
                      <div>Registered Domain: <span className="text-white">{result.agent_trace.perceive?.registered_domain || 'N/A'}</span></div>
                      <div>Host Type: <span className="text-white">{result.agent_trace.perceive?.is_ip_host ? 'Raw IP Address' : 'Named Host'}</span></div>
                      <div>URL Length: <span className="text-white">{result.agent_trace.perceive?.url_length} chars</span></div>
                    </div>
                  </div>

                  <div className="p-3.5 bg-slate-950/70 rounded-xl border border-slate-800 space-y-2">
                    <span className="font-semibold text-blue-400 flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5" /> 2. PLAN (Selected Tools)
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {result.agent_trace.plan?.map((t, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded border border-slate-700 font-mono text-[11px]">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Step 3: Act (Tools Execution Table) */}
                <div className="p-3.5 bg-slate-950/70 rounded-xl border border-slate-800 space-y-2.5">
                  <span className="font-semibold text-blue-400 flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5" /> 3. ACT (Tool Evidence Results)
                  </span>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left font-mono text-[11px]">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-500">
                          <th className="py-1.5">Tool</th>
                          <th className="py-1.5">Status</th>
                          <th className="py-1.5">Risk Score Contribution</th>
                          <th className="py-1.5">Execution Time</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-850">
                        {result.agent_trace.act?.map((ev, i) => (
                          <tr key={i} className="text-slate-300">
                            <td className="py-2 font-semibold text-white">{ev.tool}</td>
                            <td className="py-2">
                              <span className={`px-1.5 py-0.5 rounded text-[10px] ${ev.status === 'ok' ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
                                {ev.status}
                              </span>
                            </td>
                            <td className="py-2 text-white">{ev.score_contribution.toFixed(1)} / 100</td>
                            <td className="py-2 text-slate-400">{ev.time_ms.toFixed(1)} ms</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Step 4: Reflect */}
                {result.agent_trace.reflection && (
                  <div className={`p-3.5 rounded-xl border text-xs ${result.agent_trace.reflection.triggered ? 'bg-amber-950/30 border-amber-500/30 text-amber-200' : 'bg-slate-950/70 border-slate-800 text-slate-300'}`}>
                    <span className="font-semibold flex items-center gap-1.5 mb-1 text-amber-400">
                      <Sparkles className="w-3.5 h-3.5" /> 4. REFLECT Step
                    </span>
                    {result.agent_trace.reflection.triggered ? (
                      <div className="space-y-1">
                        <p className="font-medium">Reflection Triggered: {result.agent_trace.reflection.trigger_reasons?.join('; ')}</p>
                        {result.agent_trace.reflection.reflection_reasons?.map((rr, idx) => (
                          <p key={idx} className="text-slate-300 font-mono text-[11px]">• {rr}</p>
                        ))}
                      </div>
                    ) : (
                      <p className="text-slate-400 italic">No reflection required: ML probability and Heuristic rules showed strong convergence.</p>
                    )}
                  </div>
                )}

                {/* Step 5: Decide */}
                {result.agent_trace.decide && (
                  <div className="p-3.5 bg-slate-950/70 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300">
                    <span className="font-semibold text-blue-400 block mb-1">5. DECIDE (Fusion Details)</span>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                      <div>ML Weight: <span className="text-white">{result.agent_trace.decide.ml_weight}</span></div>
                      <div>Heuristic Weight: <span className="text-white">{result.agent_trace.decide.heuristic_weight}</span></div>
                      <div>ML Score: <span className="text-white">{result.agent_trace.decide.ml_score}</span></div>
                      <div>Heuristic Score: <span className="text-white">{result.agent_trace.decide.heuristic_score}</span></div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Collapsible Extracted Features Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
            <button
              onClick={() => setFeaturesOpen(!featuresOpen)}
              className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-slate-800/40 transition-colors"
            >
              <div className="flex items-center gap-2.5">
                <Info className="w-4 h-4 text-blue-400" />
                <span className="text-sm font-bold text-slate-200 uppercase tracking-wider">Extracted Feature Values</span>
                <span className="text-xs text-slate-500 font-mono">({Object.keys(result.features || {}).length} features)</span>
              </div>
              {featuresOpen ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
            </button>

            {featuresOpen && result.features && (
              <div className="px-6 pb-6 pt-2 border-t border-slate-800/80">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
                  {Object.entries(result.features).map(([key, val]) => (
                    <div key={key} className="p-2.5 bg-slate-950/70 rounded-lg border border-slate-800 flex justify-between items-center">
                      <span className="text-slate-400">{key}:</span>
                      <span className="text-white font-semibold">{String(val)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
