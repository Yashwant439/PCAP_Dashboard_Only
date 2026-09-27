import type { GatewayCorrelationResult, GatewayTelemetryRecord, GatewayTelemetrySummary } from '../types';
import type { ParsedPcapResult } from './pcapParser';

const SCAPY_ANALYZER_URL = 'http://127.0.0.1:8765/analyze';
const ANALYZER_API_URL = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_ANALYZER_API_URL) || 'http://127.0.0.1:8770';

export function getApiBaseUrl(): string {
  return ANALYZER_API_URL.replace(/\/$/, '');
}

export function buildGatewayTelemetrySummary(input: {
  analysisId?: string;
  pcapSpis?: string[];
  telemetry?: GatewayTelemetryRecord[];
  correlation?: GatewayCorrelationResult | null;
}): GatewayTelemetrySummary {
  const records = input.telemetry ?? [];
  const gatewayRecord = records[0];
  const correlation = input.correlation ?? {
    correlation_status: 'UNKNOWN',
    matched: [],
    unmatchedTelemetry: [],
    unmatchedPcapSpis: input.pcapSpis ?? [],
  };

  const matchedSpis = Array.from(
    new Set(
      correlation.matched.flatMap((entry) => (entry.matched_spis ?? [])),
    ),
  );

  const gatewayStatus = gatewayRecord?.status ?? 'NOT_DETERMINABLE';
  const evi = gatewayRecord?.evidence ?? [];

  return {
    analysisId: input.analysisId,
    gatewayId: gatewayRecord?.gatewayId ?? gatewayRecord?.gateway_id,
    gatewayStatus,
    correlationStatus: correlation.correlation_status ?? 'UNKNOWN',
    source: gatewayRecord?.source ?? 'GATEWAY_TELEMETRY',
    adapter: gatewayRecord?.adapter ?? 'STRONGSWAN',
    collectedAt: gatewayRecord?.collectedAt ?? gatewayRecord?.collected_at,
    matchedSpis,
    unmatchedPcapSpis: correlation.unmatchedPcapSpis ?? input.pcapSpis ?? [],
    evidence: evi.length > 0 ? evi : ['Gateway telemetry was unavailable or not yet correlated.'],
    telemetry: records,
    correlation,
  };
}

export async function parseWithScapy(file: File): Promise<ParsedPcapResult> {
  const response = await fetch(SCAPY_ANALYZER_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Filename': file.name,
    },
    body: await file.arrayBuffer(),
  });

  const payload = (await response.json()) as ParsedPcapResult | { error?: string };

  if (!response.ok) {
    throw new Error('Scapy analyzer: ' + ('error' in payload && payload.error ? payload.error : 'analysis failed'));
  }

  return payload as ParsedPcapResult;
}

export async function registerAnalysis(file: File, gatewayId?: string): Promise<{ analysisId: string; gatewayTelemetry?: GatewayTelemetrySummary }> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/octet-stream',
    'X-Filename': file.name,
  };
  if (gatewayId) {
    headers['X-Gateway-Id'] = gatewayId;
  }

  const response = await fetch(`${getApiBaseUrl()}/api/analyze/pcap`, {
    method: 'POST',
    headers,
    body: await file.arrayBuffer(),
  });

  const payload = (await response.json()) as {
    analysisId?: string;
    gatewayTelemetry?: GatewayTelemetrySummary;
    error?: string;
    detail?: string;
  };

  if (!response.ok || !payload.analysisId) {
    throw new Error(payload.error ?? payload.detail ?? 'Analysis registration failed');
  }

  return {
    analysisId: payload.analysisId,
    gatewayTelemetry: payload.gatewayTelemetry,
  };
}

export async function fetchAnalysisTelemetry(analysisId: string, gatewayId?: string): Promise<GatewayTelemetrySummary | null> {
  const url = gatewayId
    ? `${getApiBaseUrl()}/api/analysis/${encodeURIComponent(analysisId)}/telemetry?gateway_id=${encodeURIComponent(gatewayId)}`
    : `${getApiBaseUrl()}/api/analysis/${encodeURIComponent(analysisId)}/telemetry`;

  const response = await fetch(url);
  if (!response.ok) {
    return null;
  }

  const payload = (await response.json()) as {
    analysisId?: string;
    gatewayId?: string;
    telemetry?: GatewayTelemetryRecord[];
    correlation?: GatewayCorrelationResult | null;
    pcapSpis?: string[];
    gatewayStatus?: string;
    correlationStatus?: string;
    source?: string;
    adapter?: string;
    collectedAt?: string;
    matchedSpis?: string[];
    unmatchedPcapSpis?: string[];
    evidence?: string[];
  };

  return buildGatewayTelemetrySummary({
    analysisId: payload.analysisId ?? analysisId,
    pcapSpis: payload.pcapSpis ?? [],
    telemetry: payload.telemetry ?? [],
    correlation: payload.correlation ?? null,
  });
}

