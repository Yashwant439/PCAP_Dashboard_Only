import React from 'react';
import { FileSearch, Clock, Database, Shield, ChevronRight } from 'lucide-react';
import { MLAnalysisResult } from '../types';

interface ProvenancePanelProps {
  result: MLAnalysisResult;
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return iso;
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

export const ProvenancePanel: React.FC<ProvenancePanelProps> = ({ result }) => {
  const prov = result.provenance;
  const models = (prov['models_used'] as string[] | undefined) || [];
  const thresholds = (prov['confidence_thresholds'] as Record<string, number> | undefined) || {};

  return (
    <div id="section-provenance" className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <FileSearch className="w-4 h-4 text-cyan-400" />
        <h3 className="text-sm font-bold text-white">Evidence & Provenance</h3>
      </div>

      {/* File info */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold flex items-center gap-1.5">
            <FileSearch className="w-3 h-3" /> Input File
          </div>
          <div className="text-sm font-mono font-bold text-white break-all">{result.file.name}</div>
          <div className="text-[11px] text-slate-500">{formatBytes(result.file.size_bytes)}</div>
        </div>

        <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold flex items-center gap-1.5">
            <Clock className="w-3 h-3" /> Analysis Timestamp
          </div>
          <div className="text-xs font-mono text-white">{formatTimestamp(result.analysis_timestamp)}</div>
          <div className="text-[11px] text-slate-500">UTC server time</div>
        </div>
      </div>

      {/* Pipeline provenance */}
      <div>
        <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2">Analysis Pipeline</div>
        <div className="space-y-1">
          {[
            { step: 'PCAP Upload', detail: result.file.name, icon: <ChevronRight className="w-3.5 h-3.5 text-blue-400" /> },
            {
              step: 'Feature Extraction',
              detail: `scapy-based extractor — schema v${prov['extractor_schema_version'] || '1.1'}`,
              icon: <ChevronRight className="w-3.5 h-3.5 text-purple-400" />,
            },
            {
              step: 'ML Inference',
              detail: `${models.length} models — ${String(prov['model_dir'] || 'feature_extractor/ml/models')}`,
              icon: <ChevronRight className="w-3.5 h-3.5 text-emerald-400" />,
            },
            { step: 'Security Assessment', detail: 'Rule-based analysis on predictions + features', icon: <ChevronRight className="w-3.5 h-3.5 text-amber-400" /> },
          ].map(({ step, detail, icon }) => (
            <div key={step} className="flex items-center gap-2 text-xs py-1.5 border-b border-slate-800/60 last:border-0">
              {icon}
              <span className="font-semibold text-slate-200 w-36 shrink-0">{step}</span>
              <span className="text-slate-500 font-mono text-[10px] truncate">{detail}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Models used */}
      {models.length > 0 && (
        <div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5" /> Models Used
          </div>
          <div className="flex flex-wrap gap-2">
            {models.map((m) => (
              <span key={m} className="text-[10px] font-mono px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300">
                {m}.joblib
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Confidence thresholds */}
      {Object.keys(thresholds).length > 0 && (
        <div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5" /> Confidence Thresholds
          </div>
          <div className="flex gap-2 text-[11px]">
            {Object.entries(thresholds).map(([k, v]) => (
              <span key={k} className="px-2 py-1 rounded border bg-slate-800 border-slate-700 text-slate-300">
                <span className="font-bold uppercase">{k}</span>: ≥{Math.round(v * 100)}%
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Warnings */}
      {result.warnings.length > 0 && (
        <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/50 space-y-1">
          <div className="text-[11px] font-bold text-amber-300">Analysis Warnings</div>
          {result.warnings.map((w, i) => (
            <div key={i} className="text-[11px] text-amber-200/80 flex items-start gap-1.5">
              <span className="shrink-0">•</span>
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      {/* Limitations */}
      <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/60 text-[11px] text-slate-400 space-y-1">
        <div className="font-bold text-slate-300">Limitations</div>
        <ul className="space-y-0.5 list-none">
          {[
            'Encryption key material is never visible in network captures.',
            'ML predictions are statistical — not cryptographic proof.',
            'Model accuracy varies with capture size and traffic diversity.',
            'Only IPsec/IKEv2 traffic is supported by the current model.',
          ].map((l) => (
            <li key={l} className="flex items-start gap-1.5">
              <span className="shrink-0 text-slate-600">•</span>
              <span>{l}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};
