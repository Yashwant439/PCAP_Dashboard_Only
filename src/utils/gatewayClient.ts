import type {
  GatewayEnrollmentResult,
  GatewaySummary,
  GatewayTelemetrySummary,
} from '../types';
import { getApiBaseUrl, buildGatewayTelemetrySummary } from './scapyClient';
import type { TestbedSettings } from './testbedConfig';

export async function fetchGateways(): Promise<GatewaySummary[]> {
  const response = await fetch(`${getApiBaseUrl()}/api/gateways`);
  if (!response.ok) {
    throw new Error(`Failed to fetch gateways (HTTP ${response.status})`);
  }
  return (await response.json()) as GatewaySummary[];
}

export async function fetchGateway(
  gatewayId: string,
): Promise<GatewaySummary | null> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}`,
  );
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Failed to fetch gateway ${gatewayId} (HTTP ${response.status})`);
  }
  return (await response.json()) as GatewaySummary;
}

export async function createGateway(
  displayName: string,
  gatewayType: string = 'STRONGSWAN',
): Promise<GatewayEnrollmentResult> {
  const response = await fetch(`${getApiBaseUrl()}/api/gateways`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({
      display_name: displayName,
      gateway_type: gatewayType,
    }),
  });

  const payload = (await response.json()) as
    | GatewayEnrollmentResult
    | { error?: string; detail?: string };

  if (!response.ok || 'error' in payload) {
    const errorMsg =
      ('error' in payload && (payload.error ?? payload.detail)) ||
      'Gateway registration failed';
    throw new Error(errorMsg);
  }

  return payload as GatewayEnrollmentResult;
}

export async function regenerateEnrollmentToken(
  gatewayId: string,
): Promise<{ enrollment_token: string; expires_at: number }> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/token`,
    {
      method: 'POST',
    },
  );

  const payload = (await response.json()) as
    | { enrollment_token: string; expires_at: number }
    | { error?: string };

  if (!response.ok || 'error' in payload) {
    throw new Error(('error' in payload && payload.error) || 'Failed to regenerate token');
  }

  return payload as { enrollment_token: string; expires_at: number };
}

export async function revokeGateway(gatewayId: string): Promise<boolean> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/revoke`,
    {
      method: 'POST',
    },
  );
  if (!response.ok) {
    throw new Error(`Failed to revoke gateway (HTTP ${response.status})`);
  }
  return true;
}

export async function removeGateway(gatewayId: string): Promise<boolean> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}`,
    {
      method: 'DELETE',
    },
  );
  if (!response.ok) {
    throw new Error(`Failed to remove gateway (HTTP ${response.status})`);
  }
  return true;
}

export async function correlateWithGateway(
  analysisId: string,
  gatewayId: string,
): Promise<GatewayTelemetrySummary | null> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/analysis/${encodeURIComponent(analysisId)}/correlate`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: jsonStringify({ gateway_id: gatewayId }),
    },
  );

  if (!response.ok) {
    return null;
  }

  const payload = (await response.json()) as any;
  return buildGatewayTelemetrySummary({
    analysisId: payload.analysisId ?? analysisId,
    pcapSpis: payload.pcapSpis ?? [],
    telemetry: payload.telemetry ?? [],
    correlation: payload.correlation ?? null,
  });
}

function jsonStringify(obj: unknown): string {
  return JSON.stringify(obj);
}

export function getInstallCommand(serverUrl: string): string {
  const target = serverUrl.replace(/\/$/, '');
  return `curl -sSL ${target}/api/agent/install.sh | bash`;
}

export function getEnrollCommand(serverUrl: string, token: string): string {
  const target = serverUrl.replace(/\/$/, '');
  return `vpn-analyzer-agent enroll --server ${target} --token ${token}`;
}

export function getStartCommand(): string {
  return `vpn-analyzer-agent run`;
}

export function getDownloadUrl(serverUrl: string): string {
  const target = serverUrl.replace(/\/$/, '');
  return `${target}/api/agent/download`;
}

export interface GatewaySecurityReport {
  reportType: 'GATEWAY_SECURITY_REPORT';
  reportGeneratedAt: string;
  gateway: {
    gateway_id: string;
    display_name: string;
    gateway_type: string;
    status: string;
    enrolled_at?: string | null;
    last_seen_at?: string | null;
    agent_version?: string | null;
    telemetry_adapter: string;
    active_ike_sa_count: number;
    active_child_sa_count: number;
  };
  telemetry: {
    status: string;
    adapter: string;
    collectedAt?: string | null;
    receivedAt?: string | null;
    ikeRecords: Record<string, unknown>[];
    childRecords: Record<string, unknown>[];
    evidence: string[];
  };
  securityAssessment: {
    findings: Array<{ category: string; severity: string; value: string; detail: string }>;
    source: string;
    score: {
      value: number;
      max: 100;
      rating: string;
      status: 'COMPLETE' | 'PARTIAL' | 'INSUFFICIENT';
      evidenceCoveragePercent: number;
      assessedWeight: number;
      totalWeight: number;
      method: string;
      factors: Array<{ category: string; weight: number; status: string; points: number }>;
    };
    configurationRecommendations: Array<{
      id: string;
      setting: string;
      current: string;
      recommended: string;
      basis: string;
    }>;
    charts: {
      securityScore: number;
      evidenceCoveragePercent: number;
      findingSeverityCounts: Record<string, number>;
    };
    childSaEvidence?: Array<{
      spi: string | null;
      observed_spis: string[];
      collected_at?: string | null;
      sa_identity_status: 'CONFIRMED' | 'NOT_DETERMINABLE';
      fields: Record<string, {
        value: unknown;
        source: string;
        status: 'CONFIRMED' | 'NOT_DETERMINABLE';
        evidence: string;
      }>;
    }>;
    limitations: string[];
  };
}

export interface GatewayAiReport {
  source: 'GROQ_LLM' | 'LLM7_LLM' | 'OPENAI_LLM' | 'GEMINI_LLM';
  model: string;
  reportGeneratedAt: string;
  score: GatewaySecurityReport['securityAssessment']['score'];
  findings: GatewaySecurityReport['securityAssessment']['findings'];
  limitations: string[];
  configurationRecommendations: GatewaySecurityReport['securityAssessment']['configurationRecommendations'];
  charts: GatewaySecurityReport['securityAssessment']['charts'];
  narrative: {
    executive_summary: string;
    technical_interpretation: string;
    finding_notes: Array<{ id: string; why_it_matters: string }>;
    recommendation_notes: Array<{ id: string; note: string }>;
  };
}

export async function fetchGatewayReport(gatewayId: string): Promise<GatewaySecurityReport> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/report`,
  );
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(payload.error ?? `Failed to generate gateway report (HTTP ${response.status})`);
  }
  return (await response.json()) as GatewaySecurityReport;
}

export async function generateGatewayAiReport(gatewayId: string): Promise<GatewayAiReport> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/ai-report`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
  );
  const payload = await response.json().catch(() => ({})) as { error?: string } & Partial<GatewayAiReport>;
  if (!response.ok) {
    const messages: Record<string, string> = {
      GROQ_API_KEY_NOT_CONFIGURED: 'Set GROQ_API_KEY in the project .env file and restart the API.',
      LLM7_API_KEY_NOT_CONFIGURED: 'Set LLM7_API_KEY and LLM_PROVIDER=llm7 in the project .env file, then restart the API.',
      OPENAI_API_KEY_NOT_CONFIGURED: 'Set OPENAI_API_KEY and LLM_PROVIDER=openai in the project .env file, then restart the API.',
      GEMINI_API_KEY_NOT_CONFIGURED: 'Set GEMINI_API_KEY and LLM_PROVIDER=gemini in the project .env file, then restart the API.',
      GROQ_RATE_LIMITED: 'Groq rate limit reached. Try again later.',
      GROQ_UNAVAILABLE: 'Groq is unavailable. PDF export still works without AI narrative.',
      LLM7_UNAVAILABLE: 'LLM7 is unavailable. PDF export still works without AI narrative.',
      LLM7_HTTP_401: 'LLM7 rejected the API key. Rotate the exposed key, update LLM7_API_KEY, and restart the API.',
      LLM7_HTTP_403: 'LLM7 denied this request. Check the replacement key, account access, and selected model.',
      LLM7_HTTP_400: 'LLM7 rejected the selected model or request. Set LLM7_MODEL=default, restart the API, and try again.',
      LLM7_HTTP_404: 'The selected LLM7 model is unavailable. Set LLM7_MODEL=default or another valid LLM7 chat model, then restart the API.',
      OPENAI_HTTP_401: 'OpenAI rejected the API key. Create a replacement key, update OPENAI_API_KEY, and restart the API.',
      OPENAI_HTTP_403: 'OpenAI denied this request. Check project access, billing, and the selected model.',
      OPENAI_HTTP_400: 'OpenAI rejected the selected model or request. Set OPENAI_MODEL=gpt-5-mini, restart the API, and try again.',
      OPENAI_HTTP_404: 'The selected OpenAI model is unavailable to this project. Choose an available model and restart the API.',
      OPENAI_UNAVAILABLE: 'OpenAI is unavailable. PDF export still works without AI narrative.',
      GEMINI_HTTP_400: 'Gemini rejected the selected model or request. Set GEMINI_MODEL=gemini-2.0-flash, restart the API, and try again.',
      GEMINI_HTTP_401: 'Gemini rejected the API key. Replace GEMINI_API_KEY and restart the API server.',
      GEMINI_HTTP_403: 'Gemini denied this request. Check the API key restrictions and Gemini API access.',
      GEMINI_HTTP_404: 'The selected Gemini model is unavailable. Set GEMINI_MODEL=gemini-2.0-flash or another model available to your key, then restart the API.',
      GEMINI_UNAVAILABLE: 'Gemini is unavailable. PDF export still works without AI narrative.',
    };
    throw new Error(messages[payload.error ?? ''] ?? `AI report failed (${payload.error ?? response.status})`);
  }
  return payload as GatewayAiReport;
}

export interface TestbedApplyJob {
  jobId: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCEEDED' | 'FAILED';
  message: string;
  connectionName?: string;
  childName?: string;
}

export async function queueTestbedApply(
  gatewayId: string,
  settings: TestbedSettings,
  controlToken: string,
): Promise<TestbedApplyJob> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/testbed`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Testbed-Token': controlToken },
      body: JSON.stringify({ confirmed: true, settings }),
    },
  );
  const payload = await response.json().catch(() => ({})) as TestbedApplyJob & { error?: string };
  if (!response.ok) {
    const messages: Record<string, string> = {
      TESTBED_CONTROL_TOKEN_NOT_CONFIGURED: 'Set VPN_ANALYZER_TESTBED_TOKEN in the API .env, then restart the API.',
      GATEWAY_NOT_CONNECTED: 'The selected gateway is not connected.',
      GATEWAY_NOT_FOUND: 'The selected gateway was not found.',
      TESTBED_JOB_ALREADY_ACTIVE: 'A testbed apply is already queued or running for this gateway.',
      EXPLICIT_CONFIRMATION_REQUIRED: 'Confirm the gateway change before applying.',
      UNAUTHORIZED: 'Testbed control token is not valid.',
    };
    throw new Error(messages[payload.error ?? ''] ?? `Could not queue testbed (${payload.error ?? response.status})`);
  }
  return payload;
}

export async function getTestbedApplyStatus(
  gatewayId: string,
  jobId: string,
  controlToken: string,
): Promise<TestbedApplyJob> {
  const response = await fetch(
    `${getApiBaseUrl()}/api/gateways/${encodeURIComponent(gatewayId)}/testbed/${encodeURIComponent(jobId)}`,
    { headers: { 'X-Testbed-Token': controlToken } },
  );
  const payload = await response.json().catch(() => ({})) as TestbedApplyJob & { error?: string };
  if (!response.ok) throw new Error(`Could not read testbed job status (${payload.error ?? response.status})`);
  return payload;
}
