import React from 'react';
import { Loader2, CheckCircle2, XCircle, Upload, Cpu, Shield, BarChart2 } from 'lucide-react';
import { MLAnalysisStage } from '../types';

interface AnalysisProgressProps {
  stage: MLAnalysisStage;
  filename: string;
  error?: string | null;
}

const STAGES: { id: MLAnalysisStage; label: string; icon: React.ReactNode }[] = [
  { id: 'UPLOADING', label: 'Uploading PCAP', icon: <Upload className="w-4 h-4" /> },
  { id: 'EXTRACTING', label: 'Extracting packet features', icon: <BarChart2 className="w-4 h-4" /> },
  { id: 'INFERRING', label: 'Running cryptographic inference', icon: <Cpu className="w-4 h-4" /> },
  { id: 'ASSESSING', label: 'Building security assessment', icon: <Shield className="w-4 h-4" /> },
  { id: 'COMPLETED', label: 'Analysis complete', icon: <CheckCircle2 className="w-4 h-4" /> },
];

const STAGE_ORDER: MLAnalysisStage[] = ['UPLOADING', 'EXTRACTING', 'INFERRING', 'ASSESSING', 'COMPLETED'];

function stageIndex(stage: MLAnalysisStage): number {
  return STAGE_ORDER.indexOf(stage);
}

export const AnalysisProgress: React.FC<AnalysisProgressProps> = ({ stage, filename, error }) => {
  const currentIdx = stageIndex(stage);
  const isFailed = stage === 'FAILED';

  return (
    <div
      id="section-analysis-progress"
      className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-sm"
    >
      {/* File label */}
      <div className="flex items-center gap-2 mb-5">
        <div className="w-8 h-8 rounded-lg bg-blue-600/10 border border-blue-500/30 flex items-center justify-center">
          <Upload className="w-4 h-4 text-blue-400" />
        </div>
        <div>
          <div className="text-xs text-slate-400">Analyzing</div>
          <div className="text-sm font-bold text-white font-mono truncate max-w-xs">{filename}</div>
        </div>
        {isFailed && (
          <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded border bg-rose-950 border-rose-800 text-rose-300">
            FAILED
          </span>
        )}
      </div>

      {/* Stage progress */}
      <div className="relative space-y-3">
        {/* Vertical connector line */}
        <div className="absolute left-[15px] top-4 bottom-4 w-px bg-slate-800" />

        {STAGES.map((s, idx) => {
          const done = currentIdx > idx || stage === 'COMPLETED';
          const active = !isFailed && currentIdx === idx;
          const failed = isFailed && currentIdx < idx + 1;

          return (
            <div key={s.id} className="flex items-center gap-3 relative z-10">
              {/* Status icon */}
              <div
                className={`w-8 h-8 rounded-full border-2 flex items-center justify-center shrink-0 transition-all duration-300 ${
                  done
                    ? 'bg-emerald-500/20 border-emerald-500 text-emerald-400'
                    : active
                    ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                    : isFailed
                    ? 'bg-rose-950/30 border-rose-800 text-rose-600'
                    : 'bg-slate-800 border-slate-700 text-slate-600'
                }`}
              >
                {done ? (
                  <CheckCircle2 className="w-4 h-4" />
                ) : active ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : isFailed ? (
                  <XCircle className="w-4 h-4" />
                ) : (
                  s.icon
                )}
              </div>

              {/* Stage label */}
              <span
                className={`text-xs font-semibold transition-colors duration-300 ${
                  done
                    ? 'text-emerald-400'
                    : active
                    ? 'text-white'
                    : isFailed
                    ? 'text-slate-600'
                    : 'text-slate-500'
                }`}
              >
                {s.label}
                {active && <span className="ml-1 text-slate-400 font-normal">...</span>}
              </span>
            </div>
          );
        })}
      </div>

      {/* Error display */}
      {isFailed && error && (
        <div className="mt-4 p-3 rounded-lg bg-rose-950/30 border border-rose-800 flex items-start gap-2">
          <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="text-xs text-rose-200">
            <div className="font-bold text-rose-300 mb-0.5">Analysis Failed</div>
            {error}
          </div>
        </div>
      )}
    </div>
  );
};
