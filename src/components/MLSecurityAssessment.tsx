import React from 'react';
import { AlertTriangle, CheckCircle2, Info, ShieldAlert, ShieldCheck, Cpu, Eye, Wrench } from 'lucide-react';
import { MLSecurityFinding } from '../types';

interface MLSecurityAssessmentProps {
  findings: MLSecurityFinding[];
}

const BASIS_BADGE: Record<string, { label: string; cls: string }> = {
  ml_inferred: {
    label: 'ML PREDICTION',
    cls: 'bg-purple-950/60 border-purple-800 text-purple-300',
  },
  observed: {
    label: 'OBSERVED',
    cls: 'bg-cyan-950/60 border-cyan-800 text-cyan-300',
  },
  derived: {
    label: 'DERIVED',
    cls: 'bg-slate-800 border-slate-600 text-slate-300',
  },
};

const SEVERITY_CONFIG: Record<string, { border: string; bg: string; icon: React.ReactNode; label: string }> = {
  critical: {
    border: 'border-rose-800',
    bg: 'bg-rose-950/30',
    icon: <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />,
    label: 'CRITICAL',
  },
  high: {
    border: 'border-orange-800',
    bg: 'bg-orange-950/30',
    icon: <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0" />,
    label: 'HIGH',
  },
  medium: {
    border: 'border-amber-800',
    bg: 'bg-amber-950/30',
    icon: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />,
    label: 'MEDIUM',
  },
  low: {
    border: 'border-blue-800',
    bg: 'bg-blue-950/30',
    icon: <Info className="w-4 h-4 text-blue-400 shrink-0" />,
    label: 'LOW',
  },
  info: {
    border: 'border-slate-700',
    bg: 'bg-slate-800/40',
    icon: <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />,
    label: 'INFO',
  },
};

const SEVERITY_LABEL_CLS: Record<string, string> = {
  critical: 'bg-rose-950 border-rose-800 text-rose-300',
  high: 'bg-orange-950 border-orange-800 text-orange-300',
  medium: 'bg-amber-950 border-amber-800 text-amber-300',
  low: 'bg-blue-950 border-blue-800 text-blue-300',
  info: 'bg-emerald-950/60 border-emerald-800 text-emerald-300',
};

const CONFIDENCE_CLS: Record<string, string> = {
  HIGH: 'text-emerald-400',
  MEDIUM: 'text-amber-400',
  LOW: 'text-rose-400',
};

export const MLSecurityAssessment: React.FC<MLSecurityAssessmentProps> = ({ findings }) => {
  const criticalFindings = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const otherFindings = findings.filter((f) => f.severity !== 'critical' && f.severity !== 'high');

  return (
    <div id="section-ml-security" className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-blue-400" />
          <h3 className="text-sm font-bold text-white">Security Assessment</h3>
          <span className="text-[10px] text-slate-500">{findings.length} finding{findings.length !== 1 ? 's' : ''}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-purple-950/60 border-purple-800 text-purple-300">ML PREDICTION</span>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-cyan-950/60 border-cyan-800 text-cyan-300">OBSERVED</span>
        </div>
      </div>

      {/* Legend */}
      <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/60 text-[11px] text-slate-400 flex flex-wrap gap-4">
        <div className="flex items-center gap-1.5">
          <Cpu className="w-3.5 h-3.5 text-purple-400" />
          <span><strong className="text-purple-300">ML PREDICTION</strong> — from trained model inference</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Eye className="w-3.5 h-3.5 text-cyan-400" />
          <span><strong className="text-cyan-300">OBSERVED</strong> — directly from PCAP packet analysis</span>
        </div>
      </div>

      {/* Critical / High findings */}
      {criticalFindings.length > 0 && (
        <div className="space-y-3">
          <div className="text-[11px] font-bold uppercase tracking-wider text-rose-400">Action Required</div>
          {criticalFindings.map((f) => {
            const cfg = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.info;
            const basis = BASIS_BADGE[f.basis] || BASIS_BADGE.observed;
            return (
              <FindingCard key={f.id} finding={f} cfg={cfg} basis={basis} />
            );
          })}
        </div>
      )}

      {/* Informational / Low findings */}
      {otherFindings.length > 0 && (
        <div className="space-y-3">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
            {criticalFindings.length > 0 ? 'Informational' : 'Assessment Findings'}
          </div>
          {otherFindings.map((f) => {
            const cfg = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.info;
            const basis = BASIS_BADGE[f.basis] || BASIS_BADGE.observed;
            return (
              <FindingCard key={f.id} finding={f} cfg={cfg} basis={basis} />
            );
          })}
        </div>
      )}

      {/* Empty state */}
      {findings.length === 0 && (
        <div className="py-8 text-center text-slate-500 text-sm">
          <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-slate-600" />
          No assessment findings could be generated for this capture.
        </div>
      )}

      {/* Disclaimer */}
      <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/50 text-[11px] text-amber-200/80 flex items-start gap-2">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" />
        <span>
          ML-inferred findings are based on statistical model predictions — not cryptographic protocol inspection.
          Treat them as <strong className="text-amber-300">estimated indicators</strong>, not confirmed facts.
          Confidence scores reflect the model's output probability for the predicted class.
        </span>
      </div>
    </div>
  );
};

interface FindingCardProps {
  finding: MLSecurityFinding;
  cfg: typeof SEVERITY_CONFIG[string];
  basis: { label: string; cls: string };
}

const FindingCard: React.FC<FindingCardProps> = ({ finding, cfg, basis }) => (
  <div className={`p-4 rounded-lg border ${cfg.border} ${cfg.bg}`}>
    <div className="flex items-start gap-2">
      {cfg.icon}
      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-2 flex-wrap">
          <span className="text-sm font-bold text-white">{finding.title}</span>
          <div className="flex items-center gap-1.5 shrink-0 flex-wrap">
            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${basis.cls}`}>
              {basis.label}
            </span>
            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${SEVERITY_LABEL_CLS[finding.severity] || ''}`}>
              {finding.severity.toUpperCase()}
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">{finding.message}</p>
        <p className="text-[11px] text-slate-500 mt-1 leading-relaxed">{finding.detail}</p>

        {finding.basis === 'ml_inferred' && (
          <div className="flex items-center gap-1 mt-1.5 text-[10px] text-slate-500">
            <span>Model confidence:</span>
            <span className={`font-bold ${CONFIDENCE_CLS[finding.confidence_label] || 'text-slate-400'}`}>
              {finding.confidence_label} ({(finding.confidence * 100).toFixed(1)}%)
            </span>
          </div>
        )}

        <div className="mt-2.5 pt-2 border-t border-slate-700/60 flex items-start gap-1.5 text-[11px] text-emerald-300/80">
          <Wrench className="w-3 h-3 shrink-0 mt-0.5 text-emerald-400" />
          <span>{finding.recommendation}</span>
        </div>
      </div>
    </div>
  </div>
);
