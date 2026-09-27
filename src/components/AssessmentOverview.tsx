import React from 'react';
import { Activity, FileText, ShieldAlert, Sparkles } from 'lucide-react';
import type { AiPrediction, SecurityScorecard, VpnCaptureScenario } from '../types';
import { buildAssessmentSnapshot } from '../utils/assessmentReport';

interface AssessmentOverviewProps {
  scenario: VpnCaptureScenario;
  scorecard: SecurityScorecard;
  prediction: AiPrediction;
  onOpenReport: () => void;
}

export const AssessmentOverview: React.FC<AssessmentOverviewProps> = ({ scenario, scorecard, prediction, onOpenReport }) => {
  const snapshot = buildAssessmentSnapshot(scenario, scorecard, prediction);
  const observed = scenario.sa.observations;
  return (
    <section className="surface overflow-hidden" aria-label="Automated assessment overview">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 p-4">
        <div>
          <h3 className="text-sm font-bold text-slate-900">Automated assessment</h3>
          <p className="mt-0.5 text-xs text-slate-500">Executive and technical reports are ready from the capture evidence. AI prose is added when the API responds.</p>
        </div>
        <button onClick={onOpenReport} className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-700">
          <FileText className="h-4 w-4" /> Open reports
        </button>
      </div>
      <div className="grid gap-3 p-4 md:grid-cols-3">
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-600"><ShieldAlert className="h-4 w-4 text-amber-600" /> Observed risk score</div>
          <div className="mt-2 text-2xl font-bold text-slate-900">{snapshot.riskScore === null ? 'Not rated' : <>{snapshot.riskScore}<span className="text-sm font-normal text-slate-500"> / 100</span></>}</div>
          <p className="mt-1 text-[11px] text-slate-500">Known configuration penalties; {snapshot.evidenceCoverage}% evidence coverage is tracked separately.</p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-600"><Sparkles className="h-4 w-4 text-violet-700" /> AI confidence score</div>
          <div className="mt-2 text-2xl font-bold text-slate-900">{snapshot.aiConfidenceScore === null ? 'Unavailable' : `${snapshot.aiConfidenceScore}%`}</div>
          <p className="mt-1 text-[11px] text-slate-500">{snapshot.aiConfidenceModels ? `Mean predicted-class probability across ${snapshot.aiConfidenceModels} trained crypto models; not measured accuracy.` : 'Trained model predictions require the ML analysis service.'}</p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-600"><Activity className="h-4 w-4 text-blue-600" /> Traffic and metadata inference</div>
          <div className="mt-2 text-sm font-bold text-slate-900">{prediction.status === 'NOT_DETERMINABLE' ? 'Not determinable' : prediction.predictedClass}</div>
          <p className="mt-1 text-[11px] text-slate-500">{snapshot.trafficMatchScore === null ? 'Insufficient ESP evidence' : `${snapshot.trafficMatchScore}% relative pattern match`} · {observed?.espPackets ?? scenario.features.packetCount} ESP frames · {observed?.natTraversal || 'NAT status unknown'} NAT-T</p>
          <p className="mt-1 text-[11px] text-slate-500">Inferred from packet shape; encrypted application content is not visible.</p>
        </div>
      </div>
      <div className="border-t border-slate-200 px-4 py-3">
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <h4 className="text-xs font-bold uppercase tracking-wide text-slate-700">Threat matrix</h4>
          <span className="text-[11px] text-slate-500">{snapshot.threats.length} scored risks · {snapshot.evidenceGaps.length} evidence gaps</span>
        </div>
        {snapshot.threats.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs table-compact">
              <thead><tr><th>Severity</th><th>Control</th><th>Observed</th><th>Score impact</th><th>Action</th></tr></thead>
              <tbody>{snapshot.threats.map((finding) => <tr key={finding.id}>
                <td className="font-semibold text-slate-700">{finding.severity}</td>
                <td>{finding.parameter}</td>
                <td>{finding.detectedValue}</td>
                <td className="font-mono">-{finding.penalty}</td>
                <td>{finding.remediation}</td>
              </tr>)}</tbody>
            </table>
          </div>
        ) : <p className="text-xs text-slate-500">No observed configuration risk was scored. Check the evidence gaps before making a security conclusion.</p>}
      </div>
    </section>
  );
};
