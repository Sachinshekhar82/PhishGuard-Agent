import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Layers, 
  History as HistoryIcon, 
  BarChart3, 
  Sparkles, 
  Wifi, 
  WifiOff, 
  AlertOctagon,
  Cpu
} from 'lucide-react';
import Analyzer from './components/Analyzer';
import BatchAnalyzer from './components/BatchAnalyzer';
import History from './components/History';
import ModelDashboard from './components/ModelDashboard';

export default function App() {
  const [activeTab, setActiveTab] = useState('analyzer');
  const [health, setHealth] = useState({ model_loaded: true, llm_enabled: false });
  const [selectedUrlForAnalysis, setSelectedUrlForAnalysis] = useState(null);

  useEffect(() => {
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => setHealth(data))
      .catch(() => {});
  }, []);

  const handleInspectFromHistory = (url) => {
    setSelectedUrlForAnalysis(url);
    setActiveTab('analyzer');
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Identity */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20 border border-blue-400/30">
              <ShieldAlert className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-extrabold tracking-tight text-white font-sans">
                  PhishGuard <span className="text-blue-400 font-mono text-sm">Agent</span>
                </h1>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-950 text-blue-400 border border-blue-800/60 font-semibold">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">Agentic AI Phishing Detection & Analysis</p>
            </div>
          </div>

          {/* Tab Navigation */}
          <nav className="flex items-center gap-1 bg-slate-950/80 p-1 rounded-xl border border-slate-800 text-xs">
            <button
              onClick={() => setActiveTab('analyzer')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-all ${
                activeTab === 'analyzer' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>Analyzer</span>
            </button>

            <button
              onClick={() => setActiveTab('batch')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-all ${
                activeTab === 'batch' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Batch</span>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-all ${
                activeTab === 'history' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <HistoryIcon className="w-3.5 h-3.5" />
              <span>History</span>
            </button>

            <button
              onClick={() => setActiveTab('telemetry')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-all ${
                activeTab === 'telemetry' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span>Model Telemetry</span>
            </button>
          </nav>

          {/* System Status Indicators */}
          <div className="hidden lg:flex items-center gap-2 text-[11px] font-mono">
            <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-950 rounded-lg border border-slate-800 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>ML Engine Active</span>
            </div>
            {health.llm_enabled && (
              <div className="flex items-center gap-1.5 px-2.5 py-1 bg-purple-950/60 rounded-lg border border-purple-800 text-purple-300">
                <Sparkles className="w-3 h-3 text-purple-400" />
                <span>Gemini Ready</span>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 w-full">
        {activeTab === 'analyzer' && (
          <Analyzer
            initialUrl={selectedUrlForAnalysis}
            llmEnabled={health.llm_enabled}
          />
        )}
        {activeTab === 'batch' && <BatchAnalyzer llmEnabled={health.llm_enabled} />}
        {activeTab === 'history' && <History onReanalyze={handleInspectFromHistory} />}
        {activeTab === 'telemetry' && <ModelDashboard />}
      </main>

      {/* Mandatory Safety Notice & Defensive Tooling Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-900/60 py-4 px-4 text-center text-xs text-slate-400">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-center gap-2 text-slate-400">
          <div className="flex items-center gap-1.5 font-medium text-amber-400 bg-amber-950/40 px-3 py-1 rounded-full border border-amber-800/50">
            <AlertOctagon className="w-3.5 h-3.5" />
            <span>This tool analyzes URL text and metadata only. Do not visit suspicious URLs.</span>
          </div>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">
          PhishGuard Agent operates strictly defensively with local machine learning and rule-based agentic reasoning.
        </p>
      </footer>
    </div>
  );
}
