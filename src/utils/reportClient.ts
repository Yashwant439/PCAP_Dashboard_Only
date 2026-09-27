import { AiPrediction, SecurityScorecard, VpnCaptureScenario } from '../types';
import { getApiBaseUrl } from './scapyClient';

export interface CaptureAiNarrative {
  source: 'GROQ_LLM' | 'LLM7_LLM' | 'OPENAI_LLM' | 'GEMINI_LLM';
  model: string;
  narrative: {
    executive_summary: string;
    technical_interpretation: string;
    traffic_interpretation: string;
    finding_notes: Array<{ id: string; why_it_matters: string }>;
  };
}

export function buildCaptureAiReportPayload(scenario: VpnCaptureScenario, scorecard: SecurityScorecard, prediction: AiPrediction) {
  return {
    // The server allowlists only aggregate score, finding, and flow evidence.
    // No packet bytes, addresses, SPIs, capture names, or user identifiers are sent.
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
      findings: scorecard.findings.filter(finding => finding.severity !== 'Pass'),
    },
    prediction: {
      predictedClass: prediction.predictedClass,
      confidenceScore: prediction.confidenceScore,
      source: prediction.source ?? 'UNKNOWN',
      status: prediction.status,
    },
  };
}

export async function generateCaptureAiNarrative(scenario: VpnCaptureScenario, scorecard: SecurityScorecard, prediction: AiPrediction): Promise<CaptureAiNarrative> {
  let response: Response;
  try {
    response = await fetch(`${getApiBaseUrl()}/api/reports/pcap-narrative`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildCaptureAiReportPayload(scenario, scorecard, prediction)),
    });
  } catch {
    throw new Error('AI report service is unreachable. Start or restart python server/api_server.py, then try again.');
  }
  const payload = await response.json().catch(() => ({})) as { error?: string } & Partial<CaptureAiNarrative>;
  if (!response.ok) {
    const messages: Record<string, string> = {
      GROQ_API_KEY_NOT_CONFIGURED: 'AI narrative is optional. Add GROQ_API_KEY to .env and restart server/api_server.py.',
      LLM7_API_KEY_NOT_CONFIGURED: 'AI narrative is optional. Add LLM7_API_KEY to .env, set LLM_PROVIDER=llm7, and restart server/api_server.py.',
      OPENAI_API_KEY_NOT_CONFIGURED: 'AI narrative is optional. Add OPENAI_API_KEY to .env, set LLM_PROVIDER=openai, and restart server/api_server.py.',
      GEMINI_API_KEY_NOT_CONFIGURED: 'Add GEMINI_API_KEY to .env, set LLM_PROVIDER=gemini, and restart server/api_server.py.',
      AI_REPORT_RATE_LIMITED: 'AI report rate limit reached. Try again shortly.',
      GROQ_UNAVAILABLE: 'The AI narrative service is unavailable. Deterministic PDF export remains available.',
      LLM7_UNAVAILABLE: 'LLM7 is unavailable. Deterministic PDF export remains available.',
      LLM7_HTTP_401: 'LLM7 rejected the API key. Rotate the exposed key, update LLM7_API_KEY, and restart the API server.',
      LLM7_HTTP_403: 'LLM7 denied this request. Check the replacement key, account access, and selected model.',
      LLM7_HTTP_400: 'LLM7 rejected the selected model or request. Set LLM7_MODEL=default, restart the API, and try again.',
      LLM7_HTTP_404: 'The selected LLM7 model is unavailable. Set LLM7_MODEL=default or a valid LLM7 chat model, then restart the API.',
      OPENAI_HTTP_401: 'OpenAI rejected the API key. Create a replacement key, update OPENAI_API_KEY, and restart the API server.',
      OPENAI_HTTP_403: 'OpenAI denied this request. Check project access, billing, and the selected model.',
      OPENAI_HTTP_400: 'OpenAI rejected the selected model or request. Set OPENAI_MODEL=gpt-5-mini, restart the API, and try again.',
      OPENAI_HTTP_404: 'The selected OpenAI model is unavailable to this project. Choose an available model and restart the API.',
      OPENAI_UNAVAILABLE: 'OpenAI is unavailable. Deterministic PDF export remains available.',
      GEMINI_HTTP_400: 'Gemini rejected the selected model or request. Set GEMINI_MODEL=gemini-2.0-flash, restart the API, and try again.',
      GEMINI_HTTP_401: 'Gemini rejected the API key. Replace GEMINI_API_KEY and restart the API server.',
      GEMINI_HTTP_403: 'Gemini denied this request. Check the API key restrictions and Gemini API access.',
      GEMINI_HTTP_404: 'The selected Gemini model is unavailable. Set GEMINI_MODEL=gemini-2.0-flash or a model available to your key, then restart the API.',
      GEMINI_UNAVAILABLE: 'Gemini is unavailable. Deterministic PDF export remains available.',
    };
    throw new Error(messages[payload.error ?? ''] ?? `AI narrative request failed (${payload.error ?? response.status})`);
  }
  return payload as CaptureAiNarrative;
}
