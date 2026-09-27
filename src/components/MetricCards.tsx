import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react';
import { AiPrediction, IkeSecurityAssociation, SecurityScorecard } from '../types';
import { ConfidenceIndicator, SourceBadge } from './workstation/WorkstationTools';

interface MetricCardsProps {
  sa: IkeSecurityAssociation;
  scorecard: SecurityScorecard;
  aiPrediction: AiPrediction;
  actualTrafficType: string;
}

export const MetricCards: React.FC<MetricCardsProps> = ({
  sa,
  scorecard,
  aiPrediction,
  actualTrafficType,
}) => {
  const getRatingBadge = (rating: string, score: number) => {
    if (rating === 'Not Rated') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-slate-50 text-slate-600 border border-slate-200">
          <ShieldAlert className="w-3.5 h-3.5 text-slate-500" />
          <span>NOT RATED</span>
        </span>
      );
    }
    if (score >= 80) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          <span>{rating.toUpperCase()} POSTURE</span>
        </span>
      );
    }
    if (score >= 50) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
          <ShieldAlert className="w-3.5 h-3.5 text-amber-600" />
          <span>{rating.toUpperCase()} POSTURE</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
        <ShieldX className="w-3.5 h-3.5 text-rose-600" />
        <span>{rating.toUpperCase()} POSTURE</span>
      </span>
    );
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200">
        
        {/* Metric 1: Security Score */}
        <div id="card-security-score" className="p-4 flex flex-col justify-between space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Evidence-Adjusted Score
            </span>
            {getRatingBadge(scorecard.rating, scorecard.totalScore)}
          </div>
          <div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-3xl font-bold tracking-tight text-slate-900">
                {scorecard.totalScore}
              </span>
              <span className="text-sm font-medium text-slate-400">/ 100</span>
            </div>
            <div className="mt-2 flex items-center gap-1.5 flex-wrap text-[11px]">
              <SourceBadge source="RULE_ENGINE" />
              <span className={`px-1.5 py-0.2 rounded font-mono border ${scorecard.assessmentStatus === 'COMPLETE' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-700 border-amber-200'}`}>
                Evidence: {scorecard.evidenceCoveragePercent}% ({scorecard.assessmentStatus.toLowerCase()})
              </span>
              <span
                className={`px-1.5 py-0.2 rounded font-mono ${
                  scorecard.complianceNist === true
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : scorecard.complianceNist === false
                    ? 'bg-rose-50 text-rose-700 border border-rose-200'
                    : 'bg-slate-50 text-slate-600 border border-slate-200'
                }`}
              >
                {scorecard.complianceNist === null ? 'NIST: Not verified' : scorecard.complianceNist ? 'NIST SP 800-77: Pass' : 'NIST: Non-Compliant'}
              </span>
              <span
                className={`px-1.5 py-0.2 rounded font-mono ${
                  scorecard.complianceRfc8221 === true
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : scorecard.complianceRfc8221 === false
                    ? 'bg-rose-50 text-rose-700 border border-rose-200'
                    : 'bg-slate-50 text-slate-600 border border-slate-200'
                }`}
              >
                {scorecard.complianceRfc8221 === null ? 'RFC 8221: Not verified' : scorecard.complianceRfc8221 ? 'RFC 8221: Pass' : 'RFC 8221: Deprecated'}
              </span>
            </div>
          </div>
        </div>

        {/* Metric 2: Operating Mode & Architecture */}
        <div id="card-operational-mode" className="p-4 flex flex-col justify-between space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Encapsulation Mode
            </span>
            <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {sa.ipVersion}
            </span>
          </div>
          <div>
            <div className="text-base font-bold text-slate-900">
              {sa.operationalMode}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              {sa.operationalMode === 'Tunnel Mode'
                ? 'Full IP datagram encapsulated (inner headers masked)'
                : sa.operationalMode === 'Transport Mode'
                  ? 'Host-to-host transport (outer IP visible)'
                  : 'Tunnel or transport mode cannot be established from this capture.'}
            </p>
          </div>
          <div className="text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-100 flex items-center justify-between">
            <span>Protocol: <strong>{sa.ikeVersion}</strong></span>
            <span>Lifetime: <strong>{sa.keyLifetimeSeconds === null ? 'N/A' : `${sa.keyLifetimeSeconds / 3600}h`}</strong></span>
          </div>
        </div>

        {/* Metric 3: Cryptographic Cipher Suite */}
        <div id="card-crypto-suite" className="p-4 flex flex-col justify-between space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Negotiated Suite
            </span>
            <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {sa.encryptionKeyBits}-bit
            </span>
          </div>
          <div>
            <SourceBadge source={sa.fieldEvidence?.encryptionAlgorithm?.source || 'PCAP_OBSERVED'} />
            <div className="text-sm font-bold text-slate-900 font-mono truncate" title={sa.encryptionAlgorithm}>
              {sa.encryptionAlgorithm}
            </div>
            <div className="text-xs text-slate-500 mt-1 font-mono">
              Integ: {sa.authIntegrityAlgorithm} • DH: {sa.dhGroup}
            </div>
          </div>
          <div className="text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-100 flex items-center justify-between">
            <span>PFS: <strong>{sa.pfsEnabled === null ? 'Unknown' : sa.pfsEnabled ? 'Enabled' : 'Disabled'}</strong></span>
            <span>Replay: <strong>{sa.replayProtection === null ? 'Unknown' : sa.replayProtection ? 'Enabled' : 'Disabled'}</strong></span>
          </div>
        </div>

        {/* Metric 4: AI Inferred Workload */}
        <div id="card-ai-traffic" className="p-4 flex flex-col justify-between space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Inferred Workload
            </span>
            <SourceBadge source={aiPrediction.source || 'UNKNOWN'} />
          </div>
          <div>
            <div className="text-base font-bold text-slate-900">
              {aiPrediction.predictedClass}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Classified from encrypted frame length &amp; burst cadence
            </p>
          </div>
          <div className="pt-2 border-t border-slate-100">
            <ConfidenceIndicator value={aiPrediction.status === 'NOT_DETERMINABLE' ? null : aiPrediction.confidenceScore} source="Traffic pattern match" />
          </div>
          <div className="text-[11px] font-mono text-slate-500 pt-2 flex items-center justify-between">
            <span>Payload: <strong>ESP Encrypted</strong></span>
            <span>{actualTrafficType === 'Live Real Capture' ? 'Application unverified' : <>Lab context: <strong>{actualTrafficType}</strong></>}</span>
          </div>
        </div>

      </div>
    </div>
  );
};
