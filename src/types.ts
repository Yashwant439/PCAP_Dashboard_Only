export type IkeVersion = 'IKEv1' | 'IKEv2';
export type OperationalMode = 'Tunnel Mode' | 'Transport Mode';
export type IpVersion = 'IPv4' | 'IPv6';

export type TrafficCategory = 
  | 'VoIP / Audio Call'
  | 'Video Streaming'
  | 'Web Browsing / HTTPS'
  | 'Bulk Data Transfer (DB/FTP)'
  | 'Telemetry / Heartbeat (ICMP)'
  | 'Live Real Capture';

export interface PacketInfo {
  id: number;
  timestamp: number; // relative ms
  sourceIp: string;
  destIp: string;
  protocol: 'IKE' | 'ESP' | 'AH' | 'ICMP' | 'OTHER';
  length: number;
  info: string;
  spi?: string;
  seq?: number;
  natT?: boolean;
  rawPreview?: string;
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
  pfsEnabled: boolean;
  keyLifetimeSeconds: number;
  replayProtection: boolean;
  replayWindowSize?: number;
  initiatorSpi: string;
  responderSpi: string;
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
  rating: 'Hardened' | 'Secure' | 'Moderate' | 'Weak' | 'Critical';
  findings: SecurityFinding[];
  complianceNist: boolean;
  complianceRfc8221: boolean;
  complianceNsaCnsa: boolean;
  metadataLeakageRisk: 'High' | 'Medium' | 'Low';
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
  backendAnalysis?: BackendCaptureAnalysis;
}

export interface BackendEvidenceItem {
  packet: number | null;
  field: string | null;
  payload: string | null;
  detail: string | null;
}

export interface BackendSecurityFinding {
  id: string;
  title: string;
  category: string;
  severity: string;
  penalty: number;
  status: string;
  confidence: number;
  evidence: BackendEvidenceItem[];
  impact: string;
  recommendation: string;
}

export interface BackendSecurityAssessment {
  risk_score: number;
  confidence: number;
  evidence_coverage: number;
  findings: BackendSecurityFinding[];
  sequence_analysis: BackendSequenceAnalysis[];
  limitations: string[];
}

export interface BackendSequenceAnalysis {
  spi: string;
  packet_numbers: number[];
  sequences: number[];
  duplicate_sequences: number[];
  gaps: number[];
  out_of_order: boolean;
  max_forward_jump: number;
  status: string;
  reason: string | null;
}

export interface BackendTransform {
  transform_type: number;
  transform_id: number;
  name: string | null;
  attributes: Record<string, number | string>;
  packet: number;
  status: string;
}

export interface BackendChildSa {
  spi: string | null;
  initiator_spi: string | null;
  responder_spi: string | null;
  protocol: string;
  proposal_packet: number;
  ike_sa_key: string;
  transforms: BackendTransform[];
  offered_transforms: BackendTransform[];
  selected_transforms: string[];
  pfs: boolean | null;
  lifetime_seconds: number | null;
  esn: boolean | null;
  proposal_role: string;
  esp_packet_numbers: number[];
  lifecycle: string;
  direction: string;
  status: string;
  reason: string | null;
}

export interface BackendIkeSa {
  key: string;
  initiator_spi: string;
  responder_spi: string;
  version: string;
  message_packets: number[];
  child_sa_indexes: number[];
  initiator_endpoint: string | null;
  responder_endpoint: string | null;
  status: string;
}

export interface BackendEspFlow {
  spi: string;
  packet_numbers: number[];
  source_ips: string[];
  destination_ips: string[];
  status: string;
  child_sa_index: number | null;
  direction: string;
  reason: string | null;
}

export interface BackendIkeEvent {
  packet: number;
  exchange_type: number;
  name: string;
  ike_sa_key: string;
  status: string;
}

export interface BackendPacket {
  number: number;
  timestamp: number;
  length: number;
  protocol: string;
  source_ip: string | null;
  destination_ip: string | null;
  ip_version: string | null;
  source_port: number | null;
  destination_port: number | null;
  spi: string | null;
  sequence: number | null;
  ike_version: string | null;
  exchange_type: number | null;
  nat_t: boolean;
  info: string;
  raw_preview: string;
}

export interface BackendCaptureAnalysis {
  format: string;
  link_type: number;
  packet_count: number;
  packets: BackendPacket[];
  protocol_summary: { counts: Record<string, number> };
  issues: { packet: number | null; detail: string }[];
  ike_sas: BackendIkeSa[];
  child_sas: BackendChildSa[];
  esp_flows: BackendEspFlow[];
  events: BackendIkeEvent[];
  security: BackendSecurityAssessment | null;
  limitations: string[];
}

// ============================================================
// ML ANALYSIS PIPELINE TYPES
// ============================================================

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

export interface MLObservedFeatures {
  packet_count: number;
  total_bytes: number;
  avg_packet_size: number;
  min_packet_size: number;
  max_packet_size: number;
  capture_duration_seconds: number;
  udp_packet_count: number;
  udp_500_count: number;
  udp_4500_count: number;
  ike_packet_count: number;
  esp_packet_count: number;
  create_child_sa_count: number;
  informational_count: number;
  ike_request_count: number;
  ike_response_count: number;
  ike_bytes: number;
  ike_avg_packet_size: number;
  esp_bytes: number;
  esp_avg_packet_size: number;
  ike_version_detected: string | null;
  ike_exchange_distribution: Record<string, number>;
}

export interface MLSecurityFinding {
  id: string;
  title: string;
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  basis: 'ml_inferred' | 'observed' | 'derived';
  confidence: number;
  confidence_label: 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  detail: string;
  recommendation: string;
}

export interface MLAnalysisResult {
  status: 'success' | 'error';
  analysis_timestamp: string;
  file: { name: string; size_bytes: number };
  observed: MLObservedFeatures;
  ml_predictions: MLPredictions;
  security_findings: MLSecurityFinding[];
  provenance: Record<string, unknown>;
  warnings: string[];
}

export type MLAnalysisStage =
  | 'IDLE'
  | 'UPLOADING'
  | 'EXTRACTING'
  | 'INFERRING'
  | 'ASSESSING'
  | 'COMPLETED'
  | 'FAILED';

export interface MLAnalysisState {
  stage: MLAnalysisStage;
  result: MLAnalysisResult | null;
  error: string | null;
}
