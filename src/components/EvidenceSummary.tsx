import React from 'react';
import { AlertTriangle, CheckCircle2, Database, FileSearch } from 'lucide-react';
import { BackendCaptureAnalysis } from '../types';

interface EvidenceSummaryProps {
  analysis: BackendCaptureAnalysis;
}

export const EvidenceSummary: React.FC<EvidenceSummaryProps> = ({ analysis }) => {
  const security = analysis.security;
  const counts = Object.entries(analysis.protocol_summary.counts);

  return (
    <section className="bg-slate-900/90 border border-cyan-900/60 rounded-xl p-4 shadow-sm">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center">
            <FileSearch className="w-4 h-4 text-cyan-300" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">Backend Evidence Analysis</h3>
            <p className="text-[11px] text-slate-400">Normalized packet observations from the uploaded capture</p>
          </div>
        </div>
        <span className="text-[11px] font-semibold text-cyan-300 bg-cyan-950/70 border border-cyan-800 rounded px-2 py-1">
          {analysis.format} · {analysis.packet_count} packets
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mt-4">
        {counts.map(([protocol, count]) => (
          <div key={protocol} className="bg-slate-950/70 border border-slate-800 rounded-lg p-2.5">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">{protocol}</div>
            <div className="text-lg font-bold text-white mt-0.5">{count}</div>
          </div>
        ))}
        <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Evidence coverage</div>
          <div className="text-lg font-bold text-cyan-300 mt-0.5">
            {security ? `${Math.round(security.evidence_coverage * 100)}%` : 'Unknown'}
          </div>
        </div>
      </div>

      {security && (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-amber-950/60 border border-amber-800 text-amber-300">
            <Database className="w-3 h-3" /> Risk score: {security.risk_score}/100
          </span>
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300">
            Assessment confidence: {Math.round(security.confidence * 100)}%
          </span>
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-rose-950/60 border border-rose-800 text-rose-300">
            <AlertTriangle className="w-3 h-3" /> {security.findings.length} observed findings
          </span>
        </div>
      )}

      {(analysis.issues.length > 0 || analysis.limitations.length > 0) && (
        <div className="mt-3 p-2.5 rounded-lg bg-slate-950/70 border border-amber-900/60 text-[11px] text-amber-200 space-y-1">
          <div className="flex items-center gap-1.5 font-semibold text-amber-300">
            <AlertTriangle className="w-3.5 h-3.5" /> Analysis limitations
          </div>
          {[...analysis.limitations, ...analysis.issues.map((issue) => `Packet ${issue.packet ?? '?'}: ${issue.detail}`)].map((item) => (
            <div key={item} className="flex items-start gap-1.5 text-slate-300">
              <CheckCircle2 className="w-3 h-3 text-amber-400 mt-0.5 shrink-0" />
              <span>{item}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
};