import React from 'react';
import { AlertTriangle, CheckCircle2, FileSearch, ShieldAlert } from 'lucide-react';
import { BackendSecurityAssessment } from '../types';

interface EvidenceSecurityAssessmentProps {
  assessment: BackendSecurityAssessment;
  onSelectPacket?: (packetId: number) => void;
}

export const EvidenceSecurityAssessment: React.FC<EvidenceSecurityAssessmentProps> = ({ assessment, onSelectPacket }) => {
  return (
    <div className="space-y-5">
      <section className="bg-slate-900/90 border border-cyan-900/60 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-300" />
              Evidence-backed security assessment
            </h3>
            <p className="text-xs text-slate-400 mt-1">Only observed packet evidence contributes to these findings.</p>
          </div>
          <div className="text-right">
            <div className="text-2xl font-black text-white">{assessment.risk_score}<span className="text-sm font-normal text-slate-400"> / 100 risk</span></div>
            <div className="text-[11px] text-cyan-300">{Math.round(assessment.confidence * 100)}% confidence · {Math.round(assessment.evidence_coverage * 100)}% evidence coverage</div>
          </div>
        </div>

        {assessment.findings.length === 0 ? (
          <div className="mt-4 p-4 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-300">
            No supported security findings were observed. This is not a proof that the VPN is secure; unsupported or missing evidence remains listed below.
          </div>
        ) : (
          <div className="mt-4 space-y-3">
            {assessment.findings.map((finding) => (
              <article key={finding.id} className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                      <h4 className="text-sm font-bold text-white">{finding.title}</h4>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{finding.impact}</p>
                  </div>
                  <span className="text-[10px] font-bold uppercase px-2 py-1 rounded border border-rose-800 bg-rose-950 text-rose-300">
                    {finding.severity} · +{finding.penalty} risk
                  </span>
                </div>
                <div className="mt-3 text-xs text-emerald-300">
                  <strong>Recommended:</strong> {finding.recommendation}
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {finding.evidence.map((item, index) => (
                    <button
                      key={`${finding.id}-${index}`}
                      type="button"
                      onClick={() => item.packet != null && onSelectPacket?.(item.packet)}
                      disabled={item.packet == null || !onSelectPacket}
                      className="inline-flex items-center gap-1 text-[10px] text-cyan-300 bg-cyan-950/60 border border-cyan-900 rounded px-1.5 py-1 enabled:hover:bg-cyan-900 disabled:opacity-60"
                    >
                      <FileSearch className="w-3 h-3" /> Packet {item.packet ?? '?'} · {item.field ?? 'field'}
                    </button>
                  ))}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      {assessment.sequence_analysis.length > 0 && (
        <section className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <FileSearch className="w-4 h-4 text-cyan-300" />
            ESP sequence observations
          </h3>
          <div className="mt-3 space-y-2">
            {assessment.sequence_analysis.map((sequence) => (
              <div key={sequence.spi} className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                <div className="font-mono text-slate-200">{sequence.spi} · {sequence.sequences.length} packets</div>
                <div className="flex flex-wrap items-center gap-2 text-slate-400">
                  <span>Duplicates: {sequence.duplicate_sequences.length}</span>
                  <span>Gaps: {sequence.gaps.length}</span>
                  <span>Out of order: {sequence.out_of_order ? 'Yes' : 'No'}</span>
                  {sequence.duplicate_sequences.length === 0 && !sequence.out_of_order && (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {assessment.limitations.length > 0 && (
        <section className="p-4 rounded-xl bg-amber-950/30 border border-amber-900/70 text-xs text-amber-100">
          <h3 className="font-bold text-amber-300 mb-2">Assessment limitations</h3>
          <ul className="space-y-1.5 list-disc list-inside">
            {assessment.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
          </ul>
        </section>
      )}
    </div>
  );
};