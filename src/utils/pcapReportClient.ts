import type { AiPrediction, SecurityScorecard, VpnCaptureScenario } from '../types';
import { getApiBaseUrl } from './scapyClient';

export interface PcapAiNarrative {
  source: 'GROQ_LLM';
  model: string;
  narrative: {
    executive_summary: string;
    technical_interpretation: string;
    traffic_interpretation: string;
    finding_notes: Array<{ id: string; why_it_matters: string }>;
  };
}

export async function generatePcapReportNarrative(
  scenario: VpnCaptureScenario,
  scorecard: SecurityScorecard,
  prediction: AiPrediction,
): Promise<PcapAiNarrative> {
  const response = await fetch(`${getApiBaseUrl()}/api/reports/pcap-narrative`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scenario: {
        sa: {
          ikeVersion: scenario.sa.ikeVersion,
          operationalMode: scenario.sa.operationalMode,
          ipVersion: scenario.sa.ipVersion,
          encryptionAlgorithm: scenario.sa.encryptionAlgorithm,
          encryptionKeyBits: scenario.sa.encryptionKeyBits,
          authIntegrityAlgorithm: scenario.sa.authIntegrityAlgorithm,
          dhGroup: scenario.sa.dhGroup,
          dhBits: scenario.sa.dhBits,
          pfsEnabled: scenario.sa.pfsEnabled,
          keyLifetimeSeconds: scenario.sa.keyLifetimeSeconds,
          replayProtection: scenario.sa.replayProtection,
          replayWindowSize: scenario.sa.replayWindowSize,
        },
        features: {
          packetCount: scenario.features.packetCount,
          totalBytes: scenario.features.totalBytes,
          meanPacketLength: scenario.features.meanPacketLength,
          stdPacketLength: scenario.features.stdPacketLength,
          minPacketLength: scenario.features.minPacketLength,
          maxPacketLength: scenario.features.maxPacketLength,
          meanInterArrivalTimeMs: scenario.features.meanInterArrivalTimeMs,
          burstRatio: scenario.features.burstRatio,
          flowSymmetry: scenario.features.flowSymmetry,
          calculatedEntropy: scenario.features.calculatedEntropy,
          flowDurationMs: scenario.features.flowDurationMs,
        },
      },
      scorecard: {
        totalScore: scorecard.totalScore,
        rating: scorecard.rating,
        assessmentStatus: scorecard.assessmentStatus,
        evidenceCoveragePercent: scorecard.evidenceCoveragePercent,
        riskPenalty: scorecard.riskPenalty,
        findings: scorecard.findings.map((finding) => ({
          severity: finding.severity,
          parameter: finding.parameter,
          detectedValue: finding.detectedValue,
          recommendedValue: finding.recommendedValue,
          threatName: finding.threatName,
          description: finding.description,
          remediation: finding.remediation,
        })),
      },
      prediction: {
        predictedClass: prediction.predictedClass,
        confidenceScore: prediction.confidenceScore,
        probabilities: prediction.probabilities,
        primaryFeatures: prediction.primaryFeatures,
        source: prediction.source,
        status: prediction.status,
      },
    }),
  });

  const payload = await response.json().catch(() => ({})) as { error?: string } & Partial<PcapAiNarrative>;
  if (!response.ok) {
    const messages: Record<string, string> = {
      GROQ_API_KEY_NOT_CONFIGURED: 'Groq AI reporting is not configured on the API server.',
      GROQ_RATE_LIMITED: 'Groq rate limit reached. Try again later.',
      GROQ_UNAVAILABLE: 'Groq is unavailable. The deterministic report remains available.',
      AI_REPORT_RATE_LIMITED: 'Wait at least 15 seconds before generating another AI report.',
      REPORT_CONTEXT_TOO_LARGE: 'This report context is too large to send for AI interpretation.',
    };
    throw new Error(messages[payload.error ?? ''] ?? `AI report failed (${payload.error ?? response.status})`);
  }
  return payload as PcapAiNarrative;
}