import React from 'react';
import { Lock, Hash, Key, Shield, Download, RefreshCw, AlertTriangle } from 'lucide-react';
import { MLAnalysisResult, MLAnalysisState } from '../types';
import { PredictionCard } from './PredictionCard';
import { TrafficOverview } from './TrafficOverview';
import { MLSecurityAssessment } from './MLSecurityAssessment';
import { ProvenancePanel } from './ProvenancePanel';
import { AnalysisProgress } from './AnalysisProgress';

interface MLAnalysisWorkspaceProps {
  state: MLAnalysisState;
  filename: string;
  onExportJson: () => void;
  onReset: () => void;
}

const CRYPTO_CARDS: {
  label: string;
  key: 'encryption' | 'hash' | 'dh_group' | 'pfs_group';
  icon: React.ReactNode;
}[] = [
  { label: 'Encryption', key: 'encryption', icon: <Lock className="w-4 h-4 text-cyan-400" /> },
  { label: 'Hash / Integrity', key: 'hash', icon: <Hash className="w-4 h-4 text-blue-400" /> },
  { label: 'DH Group', key: 'dh_group', icon: <Key className="w-4 h-4 text-purple-400" /> },
  { label: 'PFS Group', key: 'pfs_group', icon: <Shield className="w-4 h-4 text-amber-400" /> },
];

export const MLAnalysisWorkspace: React.FC<MLAnalysisWorkspaceProps> = ({
  state,
  filename,
  onExportJson,
  onReset,
}) => {
  const { stage, result, error } = state;

  // In-progress or failed — show the progress view
  if (stage !== 'COMPLETED' || !result) {
    return (
      <div className="max-w-xl mx-auto py-8">
        <AnalysisProgress stage={stage} filename={filename} error={error} />
        {stage === 'FAILED' && (
          <div className="mt-4 text-center">
            <button
              onClick={onReset}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 text-xs font-semibold hover:bg-slate-700 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-4 h-4" />
              Try Again
            </button>
          </div>
        )}
      </div>
    );
  }

  // Completed — show full analysis
  return (
    <div className="space-y-6">
      {/* Result header banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-emerald-950/60 border-emerald-800 text-emerald-300 uppercase tracking-wider">
              ANALYSIS COMPLETE
            </span>
            <h2 className="text-base font-bold text-white">
              {result.file.name}
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Protocol: {result.observed.ike_version_detected ? `${result.observed.ike_version_detected} / IPsec` : 'IPsec'} ·
            {result.observed.packet_count.toLocaleString()} packets ·
            {(result.file.size_bytes / 1024).toFixed(1)} KB
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            id="btn-reset-ml-analysis"
            onClick={onReset}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            New Analysis
          </button>
          <button
            id="btn-export-ml-json"
            onClick={onExportJson}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Warnings */}
      {result.warnings.length > 0 && (
        <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/50 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs text-amber-200/90 space-y-0.5">
            {result.warnings.map((w, i) => <div key={i}>{w}</div>)}
          </div>
        </div>
      )}

      {/* Cryptographic Profile — 4 ML prediction cards */}
      <div>
        <div className="mb-3 flex items-center gap-2">
          <h3 className="text-sm font-bold text-white">Cryptographic Profile</h3>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-purple-950/60 border-purple-800 text-purple-300">
            ML PREDICTIONS
          </span>
          <span className="text-xs text-slate-500">
            — estimated from traffic patterns, not protocol inspection
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {CRYPTO_CARDS.map(({ label, key }) => (
            <PredictionCard
              key={key}
              label={label}
              target={key}
              result={result.ml_predictions[key]}
            />
          ))}
        </div>
      </div>

      {/* Traffic Overview (observed) */}
      <TrafficOverview observed={result.observed} />

      {/* Security Assessment */}
      <MLSecurityAssessment findings={result.security_findings} />

      {/* Provenance */}
      <ProvenancePanel result={result} />
    </div>
  );
};
