export type IkeVersion = 'IKEv1' | 'IKEv2' | 'Not observed in capture';
export type OperationalMode = 'Tunnel Mode' | 'Transport Mode' | 'Not determined from capture';
export type IpVersion = 'IPv4' | 'IPv6' | 'Not observed in capture';

export type EvidenceConfidence = 'exact' | 'heuristic' | 'unavailable';

export interface EvidenceRecord {
  value: string | number | boolean | null;
  confidence: EvidenceConfidence;
  source: string;
  packetNumber?: number;
  rawBytes?: string;
  fieldPath: string;
}

export interface EvidenceValue {
  field: string;
  value: unknown;
  source: 'PCAP_OBSERVED' | 'GATEWAY_TELEMETRY' | 'ML_INFERENCE' | 'DERIVED_FROM_OBSERVED_DATA' | 'UNKNOWN';
  confidence: number;
  status: 'OBSERVED' | 'CONFIRMED' | 'INFERRED' | 'NOT_DETERMINABLE';
  evidence: string;
  packetNumbers?: number[];
}

export interface ParsedTransform {
  type: number;
  id: number;
  name: string;
  attributes: Record<number, number>;
  attributeRawBytes?: Record<number, string>;
  rawBytes: string;
  packetNumber: number;
}

export interface ParsedProposal {
  number: number;
  protocolId: number;
  spi: string;
  transforms: ParsedTransform[];
  packetNumber: number;
}

export type TrafficCategory = 
  | 'VoIP / Audio Call'
  | 'Video Streaming'
  | 'Web Browsing / HTTPS'
  | 'Bulk Data Transfer (DB/FTP)'
  | 'Telemetry / Heartbeat (ICMP)'
  | 'Live Real Capture'
  | 'INSUFFICIENT_DATA';

export interface PacketInfo {
  id: number;
  timestamp: number; // relative ms
  sourceIp: string;
  destIp: string;
  protocol: 'IKE' | 'ESP' | 'AH' | 'ICMP' | 'UDP' | 'OTHER';
  length: number;
  info: string;
  spi?: string;
  seq?: number;
  rawPreview?: string;
  sourcePort?: number;
  destPort?: number;
  ipVersion?: IpVersion;
  debug?: string;
}

export interface CaptureObservations {
  totalPackets: number;
  ikePackets: number;
  espPackets: number;
  ahPackets: number;
  udpPackets: number;
  tcpPackets: number;
  icmpPackets: number;
  ikeExchanges: string[];
  ikePayloads: string[];
  ikeMessageIds: number[];
  ikeFlags: string[];
  ikeNotifications: string[];
  ikeVendorIds: string[];
  natDetection: 'Detected' | 'Not detected' | 'Not determinable';
  fragmentation: 'Supported' | 'Observed' | 'Not observed' | 'Not determinable';
  trafficSelectors: string[];
  natTraversal: 'Detected' | 'Not detected' | 'Not determined';
  espSpis: string[];
  ahSpis: string[];
  ahSequenceRange: string;
  espFlowDirections: string[];
  captureDurationMs: number;
  espSequenceRange: string;
  espDuplicateSequences: number[];
  espOutOfOrder: 'Observed' | 'Not observed' | 'Not determinable';
  espExtendedSequenceNumbers: 'Observed' | 'Not observed' | 'Not determined';
  linkTypes: string[];
  captureNotes: string[];
}

export interface IkeSecurityAssociation {
  ikeVersion: IkeVersion;
  operationalMode: OperationalMode;
  ipVersion: IpVersion;
  encryptionAlgorithm: string;
  encryptionKeyBits: number;
  authIntegrityAlgorithm: string;
  dhGroup: string;
  dhGroupNumber: number;
  dhBits: number;
  pfsEnabled: boolean | null;
  keyLifetimeSeconds: number | null;
  replayProtection: boolean | null;
  replayWindowSize?: number | null;
  initiatorSpi: string;
  responderSpi: string;
  proposals?: ParsedProposal[];
  evidence?: EvidenceRecord[];
  observations?: CaptureObservations;
  fieldEvidence?: Record<string, EvidenceValue>;
}

export interface EspTrafficFeatures {
  packetCount: number;
  totalBytes: number;
  meanPacketLength: number;
  stdPacketLength: number;
  minPacketLength: number;
  maxPacketLength: number;
  meanInterArrivalTimeMs: number;
  burstRatio: number;
  flowSymmetry: number; // 0-1 ratio between uplink and downlink
  calculatedEntropy: number; // 0-8 bits per byte
  flowDurationMs?: number;
}

export interface AiPrediction {
  predictedClass: TrafficCategory;
  confidenceScore: number; // 0-100
  probabilities: {
    category: TrafficCategory;
    probability: number; // 0-100
  }[];
  primaryFeatures: {
    name: string;
    value: string;
    impact: 'Supporting' | 'Neutral' | 'Contradicting';
    explanation: string;
  }[];
  source?: 'ML_INFERENCE' | 'DERIVED_FROM_OBSERVED_DATA' | 'UNKNOWN';
  status?: 'INFERRED' | 'NOT_DETERMINABLE';
  evidence?: string;
}

export interface SecurityFinding {
  id: string;
  parameter: string;
  detectedValue: string;
  recommendedValue: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Pass';
  penalty: number;
  cveReference?: string;
  threatName: string;
  description: string;
  remediation: string;
}

export interface SecurityScorecard {
  totalScore: number; // 0-100
  riskPenalty: number;
  evidenceCoveragePercent: number;
  assessmentStatus: 'COMPLETE' | 'PARTIAL' | 'INSUFFICIENT';
  rating: 'Hardened' | 'Secure' | 'Moderate' | 'Weak' | 'Critical' | 'Not Rated';
  findings: SecurityFinding[];
  complianceNist: boolean | null;
  complianceRfc8221: boolean | null;
  complianceNsaCnsa: boolean | null;
  metadataLeakageRisk: 'High' | 'Medium' | 'Low' | 'Unknown';
}

export interface GatewayTelemetryRecord {
  gatewayId?: string;
  gateway_id?: string;
  adapter?: string;
  source?: string;
  status?: string;
  collectedAt?: string;
  collected_at?: string;
  records?: Record<string, unknown>[];
  evidence?: string[];
  error?: string | null;
  [key: string]: unknown;
}

export interface GatewayCorrelationResult {
  correlation_status: 'CONFIRMED' | 'UNKNOWN';
  matched: Array<{
    correlation_status: string;
    matched_spis: string[];
    telemetry: Record<string, unknown>;
  }>;
  unmatchedTelemetry: Array<{
    correlation_status: string;
    telemetry: Record<string, unknown>;
    evidence?: string;
  }>;
  unmatchedPcapSpis: string[];
}

export interface GatewayTelemetrySummary {
  analysisId?: string;
  gatewayId?: string;
  gatewayStatus: string;
  correlationStatus: string;
  source?: string;
  adapter?: string;
  collectedAt?: string;
  pcapSpis?: string[];
  matchedSpis: string[];
  unmatchedPcapSpis: string[];
  evidence: string[];
  telemetry: GatewayTelemetryRecord[];
  correlation?: GatewayCorrelationResult;
}

export interface MLPredictionResult {
  prediction: string;
  probabilities: Record<string, number>;
  confidence: number | null;
}

export interface MLPredictions {
  encryption: MLPredictionResult;
  hash: MLPredictionResult;
  dh_group: MLPredictionResult;
  pfs_group: MLPredictionResult;
}

export interface MLSecurityFinding {
  id: string;
  title: string;
  category: string;
  severity: string;
  basis: 'ml_inferred' | 'observed' | 'derived';
  confidence: number;
  confidence_label: string;
  message: string;
  detail: string;
  recommendation: string;
}

export interface VpnCaptureScenario {
  id: string;
  name: string;
  organization: string;
  badge: string;
  description: string;
  sa: IkeSecurityAssociation;
  features: EspTrafficFeatures;
  packets: PacketInfo[];
  actualTrafficType: TrafficCategory;
  gatewayTelemetry?: GatewayTelemetrySummary;
  correlation?: GatewayCorrelationResult;
  mlPredictions?: MLPredictions | null;
  mlSecurityFindings?: MLSecurityFinding[];
  mlWarning?: string | null;
}

export type GatewayStatus =
  | 'NEVER_CONNECTED'
  | 'CONNECTED'
  | 'STALE'
  | 'OFFLINE'
  | 'REVOKED';

export interface GatewayHistoryItem {
  id: number;
  collectedAt?: string;
  receivedAt?: string;
  status: string;
  error?: string | null;
  recordsCount: number;
}

export interface GatewaySummary {
  gateway_id: string;
  display_name: string;
  gateway_type: string;
  status: GatewayStatus;
  created_at: string;
  last_seen_at?: string | null;
  enrolled_at?: string | null;
  revoked_at?: string | null;
  agent_version?: string | null;
  telemetry_adapter?: string | null;
  active_ike_sa_count: number;
  active_child_sa_count: number;
  last_error?: string | null;
  latest_telemetry?: GatewayTelemetryRecord | null;
  history?: GatewayHistoryItem[];
}

export interface GatewayEnrollmentResult {
  gateway_id: string;
  display_name: string;
  gateway_type: string;
  status: string;
  created_at: string;
  enrollment_token: string;
  expires_at: number;
  server_url: string;
}
