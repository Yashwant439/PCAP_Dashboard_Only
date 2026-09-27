import type { IkeSecurityAssociation } from '../types';

export type EvidenceSource =
  | 'PCAP_OBSERVED'
  | 'GATEWAY_TELEMETRY'
  | 'ML_INFERENCE'
  | 'DERIVED_FROM_OBSERVED_DATA'
  | 'UNKNOWN';

export type EvidenceStatus =
  | 'OBSERVED'
  | 'CONFIRMED'
  | 'INFERRED'
  | 'NOT_DETERMINABLE';

export interface EvidenceValue<T = unknown> {
  field: string;
  value: T | null;
  source: EvidenceSource;
  confidence: number;
  status: EvidenceStatus;
  evidence: string;
  packetNumbers?: number[];
}

function observed<T>(
  field: string,
  value: T,
  evidence: string,
  packetNumbers: number[] = []
): EvidenceValue<T> {
  return {
    field,
    value,
    source: 'PCAP_OBSERVED',
    confidence: 1,
    status: 'OBSERVED',
    evidence,
    ...(packetNumbers.length > 0 ? { packetNumbers } : {}),
  };
}

function unavailable<T>(field: string, evidence: string): EvidenceValue<T> {
  return {
    field,
    value: null,
    source: 'UNKNOWN',
    confidence: 0,
    status: 'NOT_DETERMINABLE',
    evidence,
  };
}

export function buildSecurityAssociationEvidence(
  sa: IkeSecurityAssociation
): Record<string, EvidenceValue> {
  const proposalPackets = (sa.proposals || []).map((proposal) => proposal.packetNumber);
  const uniqueProposalPackets = Array.from(new Set(proposalPackets));
  const evidence: Record<string, EvidenceValue> = {
    ike_version: sa.ikeVersion === 'Not observed in capture'
      ? unavailable('ike_version', 'No valid IKE header was decoded from the supplied capture.')
      : observed('ike_version', sa.ikeVersion, 'Valid IKE header decoded from captured UDP payload.', uniqueProposalPackets),
    ip_version: sa.ipVersion === 'Not observed in capture'
      ? unavailable('ip_version', 'No valid IPv4 or IPv6 header was decoded.')
      : observed('ip_version', sa.ipVersion, 'IP version decoded from captured network headers.'),
    initiator_spi: sa.initiatorSpi === 'Not observed in capture'
      ? unavailable('initiator_spi', 'No valid IKE header exposed an initiator SPI.')
      : observed('initiator_spi', sa.initiatorSpi, 'Initiator SPI decoded from the IKE header.', uniqueProposalPackets),
    responder_spi: sa.responderSpi === 'Not observed in capture'
      ? unavailable('responder_spi', 'No responder SPI was observed in a valid IKE response.')
      : observed('responder_spi', sa.responderSpi, 'Responder SPI decoded from the IKE header.', uniqueProposalPackets),
    ike_encryption: sa.encryptionAlgorithm === 'Not observed in capture'
      ? unavailable('ike_encryption', 'No decodable encryption transform was present in the supplied capture.')
      : observed('ike_encryption', sa.encryptionAlgorithm, 'Encryption transform decoded from an IKE SA proposal.', uniqueProposalPackets),
    ike_key_bits: sa.encryptionKeyBits > 0
      ? observed('ike_key_bits', sa.encryptionKeyBits, 'Key length decoded from an IKE transform ID or key-length attribute.', uniqueProposalPackets)
      : unavailable('ike_key_bits', 'No key length was explicitly available in the decoded IKE proposal.'),
    integrity: sa.authIntegrityAlgorithm === 'Not observed in capture'
      ? unavailable('integrity', 'No decodable integrity transform was present in the supplied capture.')
      : observed('integrity', sa.authIntegrityAlgorithm, 'Integrity transform decoded from an IKE SA proposal.', uniqueProposalPackets),
    dh_group: sa.dhGroup === 'Not observed in capture'
      ? unavailable('dh_group', 'No decodable DH transform was present in the supplied capture.')
      : observed('dh_group', sa.dhGroup, 'DH transform decoded from an IKE SA proposal.', uniqueProposalPackets),
    pfs: sa.pfsEnabled === null
      ? unavailable('pfs', 'PFS cannot be proven from the available PCAP evidence without a correlated Child-SA exchange or gateway telemetry.')
      : observed('pfs', sa.pfsEnabled, 'PFS state was explicitly observed in a correlated evidence source.', uniqueProposalPackets),
    operational_mode: sa.operationalMode === 'Not determined from capture'
      ? unavailable('operational_mode', 'The supplied packet evidence does not prove tunnel or transport mode.')
      : observed('operational_mode', sa.operationalMode, 'Operational mode was explicitly observed.'),
    key_lifetime_seconds: sa.keyLifetimeSeconds === null
      ? unavailable('key_lifetime_seconds', 'SA lifetime is not carried in the available packet evidence.')
      : observed('key_lifetime_seconds', sa.keyLifetimeSeconds, 'SA lifetime was explicitly observed.'),
    replay_protection: sa.replayProtection === null
      ? unavailable('replay_protection', 'ESP packets expose sequence values but not the configured replay window.')
      : observed('replay_protection', sa.replayProtection, 'Replay protection was explicitly observed.'),
  };

  return evidence;
}

export function addSecurityAssociationEvidence(
  sa: IkeSecurityAssociation
): IkeSecurityAssociation {
  return {
    ...sa,
    fieldEvidence: buildSecurityAssociationEvidence(sa),
  };
}
