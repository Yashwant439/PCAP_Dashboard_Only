import type { AiPrediction, SecurityFinding, SecurityScorecard, VpnCaptureScenario } from '../types';

export type AssessmentReportKind = 'EXECUTIVE' | 'TECHNICAL' | 'COMBINED';

export interface AssessmentSnapshot {
  securityScore: number;
  riskScore: number | null;
  evidenceCoverage: number;
  threats: SecurityFinding[];
  evidenceGaps: SecurityFinding[];
  aiConfidenceScore: number | null;
  aiConfidenceModels: number;
  trafficMatchScore: number | null;
}

export interface ReportSection {
  title: string;
  lines?: string[];
  table?: { headers: string[]; rows: string[][] };
}

export function buildAssessmentSnapshot(
  scenario: VpnCaptureScenario,
  scorecard: SecurityScorecard,
  prediction: AiPrediction,
): AssessmentSnapshot {
  const modelResults = scenario.mlPredictions
    ? Object.values(scenario.mlPredictions).filter((result) => result && typeof result.confidence === 'number' && Number.isFinite(result.confidence))
    : [];
  const aiConfidenceScore = modelResults.length
    ? Math.round(modelResults.reduce((sum, result) => sum + Math.max(0, Math.min(1, result.confidence ?? 0)), 0) / modelResults.length * 100)
    : null;

  return {
    securityScore: scorecard.totalScore,
    // This is the observed configuration penalty. Unknown controls are tracked by evidence coverage.
    riskScore: scorecard.assessmentStatus === 'INSUFFICIENT' ? null : scorecard.riskPenalty,
    evidenceCoverage: scorecard.evidenceCoveragePercent,
    threats: scorecard.findings.filter((finding) => finding.penalty > 0),
    evidenceGaps: scorecard.findings.filter((finding) => finding.severity !== 'Pass' && finding.penalty === 0),
    aiConfidenceScore,
    aiConfidenceModels: modelResults.length,
    trafficMatchScore: prediction.status === 'NOT_DETERMINABLE' ? null : prediction.confidenceScore,
  };
}

const display = (value: unknown): string => value === null || value === undefined || value === '' ? 'Not observed' : String(value);
const yesNoUnknown = (value: boolean | null): string => value === null ? 'Not observed' : value ? 'Enabled' : 'Disabled';

export function buildReportSections(
  kind: AssessmentReportKind,
  scenario: VpnCaptureScenario,
  scorecard: SecurityScorecard,
  prediction: AiPrediction,
  narrative?: { executive_summary: string; technical_interpretation: string } | null,
): ReportSection[] {
  const snapshot = buildAssessmentSnapshot(scenario, scorecard, prediction);
  const summary = snapshot.threats.length
    ? `${snapshot.threats.length} observed configuration risk${snapshot.threats.length === 1 ? '' : 's'} require review; ${snapshot.evidenceGaps.length} controls need more evidence.`
    : snapshot.evidenceGaps.length
      ? `No confirmed configuration risk was scored, but ${snapshot.evidenceGaps.length} controls need more evidence.`
      : 'No configuration risk was identified in the assessed controls.';
  const scoreLines = [
    `Evidence-adjusted security score: ${snapshot.securityScore}/100 (${scorecard.rating}).`,
    `Observed configuration risk score: ${snapshot.riskScore === null ? 'Not rated' : `${snapshot.riskScore}/100`}. This is a rule-based penalty, not the probability of an attack.`,
    `Evidence coverage: ${snapshot.evidenceCoverage}% (${scorecard.assessmentStatus}). Unknown controls receive no security credit.`,
  ];
  const trafficLines = [
    `Inferred workload: ${prediction.status === 'NOT_DETERMINABLE' ? 'Not determinable' : prediction.predictedClass}.`,
    `Traffic pattern match: ${snapshot.trafficMatchScore === null ? 'Unavailable' : `${snapshot.trafficMatchScore}%`}. This is a relative heuristic score, not calibrated model confidence.`,
    `ESP packets: ${scenario.features.packetCount}; mean length: ${scenario.features.meanPacketLength.toFixed(1)} bytes; mean inter-arrival: ${scenario.features.meanInterArrivalTimeMs.toFixed(1)} ms; entropy: ${scenario.features.calculatedEntropy.toFixed(2)} bits/byte.`,
    `Wire metadata: ${scenario.sa.observations?.ikePackets ?? 'unknown'} IKE and ${scenario.sa.observations?.espPackets ?? scenario.features.packetCount} ESP frames; NAT traversal ${scenario.sa.observations?.natTraversal ?? 'not determined'}.`,
    'Application identity and encrypted contents cannot be confirmed from packet metadata.',
  ];
  const confidenceLines = [
    `AI confidence score: ${snapshot.aiConfidenceScore === null ? 'Unavailable' : `${snapshot.aiConfidenceScore}%`}.`,
    snapshot.aiConfidenceModels
      ? `Mean predicted-class probability across ${snapshot.aiConfidenceModels} available cryptographic inference models; this is not measured accuracy.`
      : 'The trained cryptographic inference service did not return model predictions for this capture.',
  ];
  const threatRows = snapshot.threats.map((finding) => [
    finding.severity, `${finding.parameter}: ${finding.threatName}${finding.cveReference ? ` (${finding.cveReference})` : ''}`,
    finding.detectedValue, String(finding.penalty), finding.remediation,
  ]);
  const threatSection: ReportSection = {
    title: 'Threat matrix and remediation',
    lines: threatRows.length ? undefined : ['No observed configuration risks were scored. Review evidence gaps before concluding the tunnel is secure.'],
    table: threatRows.length ? { headers: ['Severity', 'Control / threat', 'Observed', 'Penalty', 'Action'], rows: threatRows } : undefined,
  };
  const gapsSection: ReportSection = {
    title: 'Evidence gaps',
    lines: snapshot.evidenceGaps.length
      ? snapshot.evidenceGaps.map((finding) => `${finding.parameter}: ${finding.detectedValue}. ${finding.remediation}`)
      : ['No unassessed controls were identified in the current rule set.'],
  };

  if (kind === 'EXECUTIVE') {
    return [
      { title: 'Executive summary', lines: [narrative?.executive_summary || summary] },
      { title: 'Security and risk', lines: scoreLines },
      { title: 'Traffic and metadata inference', lines: trafficLines.slice(0, 2).concat(trafficLines[3], trafficLines[4]) },
      { title: 'AI confidence', lines: confidenceLines },
      threatSection,
      gapsSection,
    ];
  }

  const observations = scenario.sa.observations;
  const sections: ReportSection[] = [
    { title: 'Technical interpretation', lines: [narrative?.technical_interpretation || summary] },
    { title: 'Security and risk', lines: scoreLines },
    threatSection,
    gapsSection,
    {
      title: 'Cryptographic parameters',
      table: { headers: ['Parameter', 'Observed value'], rows: [
        ['IKE version', display(scenario.sa.ikeVersion)],
        ['Operating mode', display(scenario.sa.operationalMode)],
        ['Encryption', display(scenario.sa.encryptionAlgorithm)],
        ['Integrity', display(scenario.sa.authIntegrityAlgorithm)],
        ['DH group', display(scenario.sa.dhGroup)],
        ['PFS', yesNoUnknown(scenario.sa.pfsEnabled)],
        ['Replay protection', yesNoUnknown(scenario.sa.replayProtection)],
        ['Key lifetime', scenario.sa.keyLifetimeSeconds === null ? 'Not observed' : `${scenario.sa.keyLifetimeSeconds} seconds`],
      ] },
    },
    { title: 'Traffic analysis and metadata inference', lines: trafficLines },
    { title: 'AI confidence', lines: confidenceLines },
  ];

  if (scenario.mlPredictions) {
    sections.push({
      title: 'Cryptographic model predictions',
      table: { headers: ['Target', 'Prediction', 'Predicted-class probability'], rows: Object.entries(scenario.mlPredictions).map(([target, result]) => [
        target.replaceAll('_', ' '), result.prediction, result.confidence === null ? 'Unavailable' : `${Math.round(result.confidence * 100)}%`,
      ]) },
    });
  }
  if (scenario.mlSecurityFindings?.length) {
    sections.push({
      title: 'Model-inferred security notes',
      lines: ['These are predictions, not packet-observed configuration findings. Confirm them with gateway telemetry or negotiation evidence.'],
      table: { headers: ['Severity', 'Finding', 'Basis', 'Confidence', 'Recommended check'], rows: scenario.mlSecurityFindings.map((finding) => [
        finding.severity, finding.title, finding.basis.replaceAll('_', ' '), `${Math.round(finding.confidence * 100)}%`, finding.recommendation,
      ]) },
    });
  }
  if (observations) {
    sections.push({ title: 'Wire-visible metadata', lines: [
      `Total frames: ${observations.totalPackets}; IKE: ${observations.ikePackets}; ESP: ${observations.espPackets}; AH: ${observations.ahPackets}.`,
      `NAT traversal: ${display(observations.natTraversal)}; capture duration: ${observations.captureDurationMs.toFixed(1)} ms.`,
      `IKE exchanges: ${observations.ikeExchanges.join(', ') || 'None observed'}.`,
    ] });
  }
  if (kind === 'COMBINED' && scenario.gatewayTelemetry) {
    sections.push({ title: 'Gateway correlation', lines: [
      `Gateway status: ${scenario.gatewayTelemetry.gatewayStatus}; correlation: ${scenario.gatewayTelemetry.correlationStatus}.`,
      `Matched SPIs: ${scenario.gatewayTelemetry.matchedSpis.length}; unmatched capture SPIs: ${scenario.gatewayTelemetry.unmatchedPcapSpis.length}.`,
      `Telemetry source: ${scenario.gatewayTelemetry.source || 'Not reported'}.`,
    ] });
  }
  return sections;
}

export function formatAssessmentMarkdown(
  kind: AssessmentReportKind,
  scenario: VpnCaptureScenario,
  sections: ReportSection[],
  generatedAt = new Date().toISOString(),
): string {
  const title = kind === 'EXECUTIVE' ? 'Executive security report' : kind === 'COMBINED' ? 'Combined technical and gateway report' : 'Technical security report';
  const escapeCell = (value: string) => value.replaceAll('|', '\\|').replaceAll('\n', ' ');
  const body = sections.map((section) => {
    const lines = [`## ${section.title}`, ...(section.lines || []).map((line) => `- ${line}`)];
    if (section.table) {
      lines.push('', `| ${section.table.headers.map(escapeCell).join(' | ')} |`);
      lines.push(`| ${section.table.headers.map(() => '---').join(' | ')} |`);
      lines.push(...section.table.rows.map((row) => `| ${row.map(escapeCell).join(' | ')} |`));
    }
    return lines.join('\n');
  }).join('\n\n');
  return `# ${title}\n\nCapture: ${scenario.name}\nGenerated: ${generatedAt}\n\n${body}\n`;
}
