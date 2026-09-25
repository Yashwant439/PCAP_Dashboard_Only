import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Lock, ShieldCheck, ShieldAlert, Cpu } from 'lucide-react';
import { MLPredictionResult } from '../types';

interface PredictionCardProps {
  label: string;
  target: 'encryption' | 'hash' | 'dh_group' | 'pfs_group';
  result: MLPredictionResult;
}

function confidenceColor(confidence: number | null): string {
  if (confidence === null) return 'text-slate-400';
  if (confidence >= 0.80) return 'text-emerald-400';
  if (confidence >= 0.55) return 'text-amber-400';
  return 'text-rose-400';
}

function confidenceLabel(confidence: number | null): string {
  if (confidence === null) return 'N/A';
  if (confidence >= 0.80) return 'HIGH';
  if (confidence >= 0.55) return 'MEDIUM';
  return 'LOW';
}

function confidenceBadgeBg(confidence: number | null): string {
  if (confidence === null) return 'bg-slate-800 border-slate-700 text-slate-400';
  if (confidence >= 0.80) return 'bg-emerald-950/60 border-emerald-800 text-emerald-300';
  if (confidence >= 0.55) return 'bg-amber-950/60 border-amber-800 text-amber-300';
  return 'bg-rose-950/60 border-rose-800 text-rose-300';
}

function barColor(confidence: number | null): string {
  if (confidence === null) return 'bg-slate-600';
  if (confidence >= 0.80) return 'bg-emerald-500';
  if (confidence >= 0.55) return 'bg-amber-500';
  return 'bg-rose-500';
}

const TARGET_ICONS: Record<string, React.ReactNode> = {
  encryption: <Lock className="w-4 h-4 text-cyan-400" />,
  hash: <ShieldCheck className="w-4 h-4 text-blue-400" />,
  dh_group: <Cpu className="w-4 h-4 text-purple-400" />,
  pfs_group: <ShieldAlert className="w-4 h-4 text-amber-400" />,
};

const TARGET_DESCRIPTIONS: Record<string, string> = {
  encryption: 'Bulk data encryption cipher used for ESP payloads',
  hash: 'Integrity / PRF algorithm for IKE/ESP authentication',
  dh_group: 'Diffie-Hellman group for IKE key exchange (Phase 1)',
  pfs_group: 'Perfect Forward Secrecy group for Child SA rekeying',
};

export const PredictionCard: React.FC<PredictionCardProps> = ({ label, target, result }) => {
  const [expanded, setExpanded] = useState(false);
  const { prediction, probabilities, confidence } = result;
  const sortedProbs = Object.entries(probabilities).sort((a, b) => b[1] - a[1]);
  const clabel = confidenceLabel(confidence);

  return (
    <div
      id={`card-ml-${target}`}
      className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-sm transition-all hover:border-slate-700"
    >
      {/* Header */}
      <div className="p-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            {TARGET_ICONS[target]}
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
              {label}
            </span>
          </div>
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${confidenceBadgeBg(confidence)}`}>
            ML PREDICTION
          </span>
        </div>

        {/* Prediction value */}
        <div className="mt-1 text-2xl font-extrabold tracking-tight text-white font-mono">
          {prediction}
        </div>

        {/* Confidence bar */}
        <div className="mt-3 space-y-1">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Model confidence</span>
            <span className={`font-bold ${confidenceColor(confidence)}`}>
              {clabel} {confidence !== null ? `(${(confidence * 100).toFixed(1)}%)` : ''}
            </span>
          </div>
          <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${barColor(confidence)}`}
              style={{ width: `${(confidence ?? 0) * 100}%` }}
            />
          </div>
        </div>
      </div>

      {/* Probability detail toggle */}
      <button
        onClick={() => setExpanded((e) => !e)}
        className="w-full flex items-center justify-between px-4 py-2 bg-slate-800/50 border-t border-slate-800 text-[11px] text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
        aria-expanded={expanded}
        aria-controls={`probs-${target}`}
      >
        <span>Class probabilities</span>
        {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
      </button>

      {expanded && (
        <div id={`probs-${target}`} className="px-4 py-3 space-y-2.5 bg-slate-950/60 border-t border-slate-800">
          <p className="text-[10px] text-slate-500 italic">{TARGET_DESCRIPTIONS[target]}</p>
          {sortedProbs.map(([cls, prob]) => (
            <div key={cls} className="space-y-0.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className={`font-mono font-semibold ${cls === prediction ? 'text-white' : 'text-slate-400'}`}>
                  {cls === prediction && <span className="text-emerald-400 mr-1">▶</span>}
                  {cls}
                </span>
                <span className={`font-bold ${cls === prediction ? confidenceColor(prob) : 'text-slate-500'}`}>
                  {(prob * 100).toFixed(1)}%
                </span>
              </div>
              <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    cls === prediction ? barColor(prob) : 'bg-slate-700'
                  }`}
                  style={{ width: `${prob * 100}%` }}
                />
              </div>
            </div>
          ))}
          <p className="text-[10px] text-slate-600 pt-1 italic">
            "Estimated class probability" — not a confirmed hardware measurement.
          </p>
        </div>
      )}
    </div>
  );
};
