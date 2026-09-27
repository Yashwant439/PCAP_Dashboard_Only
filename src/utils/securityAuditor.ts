import { IkeSecurityAssociation, SecurityFinding, SecurityScorecard } from '../types';

export function auditIpsecSecurity(sa: IkeSecurityAssociation): SecurityScorecard {
  const findings: SecurityFinding[] = [];
  let totalScore = 100;

  // 1. IKE Version Audit
  if (sa.ikeVersion === 'Not observed in capture') {
    findings.push({
      id: 'F-IKE-UNKNOWN',
      parameter: 'Key Exchange Protocol',
      detectedValue: 'Not observed in capture',
      recommendedValue: 'IKEv2',
      severity: 'Low',
      penalty: 0,
      threatName: 'Negotiation Not Captured',
      description: 'The capture does not contain a decodable IKE version. No protocol security conclusion is made.',
      remediation: 'Capture the IKE_SA_INIT exchange for exact protocol evidence.',
    });
  } else if (sa.ikeVersion === 'IKEv2' && (!sa.proposals || sa.proposals.length === 0)) {
    findings.push({
      id: 'F-IKE-PARTIAL',
      parameter: 'Key Exchange Protocol',
      detectedValue: 'IKEv2 header observed; SA proposal not decoded',
      recommendedValue: 'IKEv2 with captured SA_INIT transforms',
      severity: 'Low',
      penalty: 0,
      threatName: 'Partial IKE Evidence',
      description: 'The capture proves that an IKEv2 header was observed, but it does not provide a decoded security proposal. Cipher and DH conclusions remain unavailable.',
      remediation: 'Capture the complete IKE_SA_INIT request and response, including their SA payloads.',
    });
  } else if (sa.ikeVersion === 'IKEv1') {
    const penalty = 15;
    totalScore -= penalty;
    findings.push({
      id: 'F-IKE-01',
      parameter: 'Key Exchange Protocol',
      detectedValue: 'IKEv1 (Legacy RFC 2409)',
      recommendedValue: 'IKEv2 (RFC 7296)',
      severity: 'Medium',
      penalty,
      threatName: 'IKEv1 Deprecation & DoS Amplification',
      description: 'IKEv1 has known protocol design shortcomings, slower multi-roundtrip handshakes, lack of built-in NAT-T mobility, and susceptibility to aggressive-mode offline dictionary attacks.',
      remediation: 'Migrate configuration to IKEv2 with certificate or pre-shared key with minimum 32-character entropy.',
    });
  } else {
    findings.push({
      id: 'F-IKE-PASS',
      parameter: 'Key Exchange Protocol',
      detectedValue: 'IKEv2 (Modern)',
      recommendedValue: 'IKEv2',
      severity: 'Pass',
      penalty: 0,
      threatName: 'Modern Protocol Standard',
      description: 'IKEv2 provides streamlined 4-message exchange, built-in DoS cookie protection, and robust MOBIKE extension support.',
      remediation: 'Maintain current IKEv2 deployment.',
    });
  }

  // 2. Encryption Algorithm Audit
  const encUpper = sa.encryptionAlgorithm.toUpperCase();
  if (encUpper.includes('NOT OBSERVED')) {
    findings.push({
      id: 'F-ENC-UNKNOWN',
      parameter: 'Symmetric Encryption Cipher',
      detectedValue: sa.encryptionAlgorithm,
      recommendedValue: 'Not assessed',
      severity: 'Low',
      penalty: 0,
      threatName: 'Encryption Transform Not Captured',
      description: 'No decodable encryption transform was observed in the capture.',
      remediation: 'Capture an IKE_SA_INIT exchange containing the SA payload.',
    });
  } else if (encUpper.includes('3DES') || encUpper.includes('DES')) {
    const penalty = 35;
    totalScore -= penalty;
    findings.push({
      id: 'F-ENC-01',
      parameter: 'Symmetric Encryption Cipher',
      detectedValue: sa.encryptionAlgorithm,
      recommendedValue: 'AES-256-GCM or AES-128-GCM',
      severity: 'Critical',
      penalty,
      cveReference: 'CVE-2016-2183 (Sweet32)',
      threatName: 'Sweet32 Birthday Collision Attack',
      description: '64-bit block ciphers like 3DES suffer from practical collision attacks after approximately 32 GB of data encrypted with the same key, enabling plaintext recovery.',
      remediation: 'Immediately decommission 3DES. Upgrade Phase 1 and Phase 2 proposals to AES-256-GCM or AES-128-GCM authenticated ciphers.',
    });
  } else if (encUpper.includes('UNKNOWN')) {
    findings.push({
      id: 'F-ENC-UNKNOWN-TRANSFORM',
      parameter: 'Symmetric Encryption Cipher',
      detectedValue: sa.encryptionAlgorithm,
      recommendedValue: 'Known, standards-approved cipher',
      severity: 'Low',
      penalty: 0,
      threatName: 'Unsupported Encryption Transform',
      description: 'An encryption transform was observed, but this analyzer cannot map its identifier to a known algorithm.',
      remediation: 'Use a parser version with the relevant transform registry or confirm the negotiated cipher through authorized gateway telemetry.',
    });
  } else if (encUpper.includes('CBC')) {
    const penalty = 10;
    totalScore -= penalty;
    findings.push({
      id: 'F-ENC-02',
      parameter: 'Symmetric Encryption Cipher',
      detectedValue: sa.encryptionAlgorithm,
      recommendedValue: 'AES-256-GCM (AEAD)',
      severity: 'Low',
      penalty,
      threatName: 'Cipher Block Chaining Mode Padding Attacks',
      description: 'AES-CBC requires separate HMAC hashing and is vulnerable to padding oracle attacks if implementation timing varies.',
      remediation: 'Prefer Authenticated Encryption with Associated Data (AEAD) modes like AES-GCM or ChaCha20-Poly1305.',
    });
  } else {
    findings.push({
      id: 'F-ENC-PASS',
      parameter: 'Symmetric Encryption Cipher',
      detectedValue: sa.encryptionAlgorithm,
      recommendedValue: 'AES-GCM (AEAD)',
      severity: 'Pass',
      penalty: 0,
      threatName: 'AEAD Modern Standard Compliant',
      description: 'AES-GCM combines high-speed hardware-accelerated encryption with integrated integrity verification (GMAC).',
      remediation: 'Maintain AES-GCM.',
    });
  }

  // 3. Diffie-Hellman Group Strength
  if (sa.dhGroupNumber === 0) {
    findings.push({
      id: 'F-DH-UNKNOWN',
      parameter: 'Diffie-Hellman Key Exchange',
      detectedValue: sa.dhGroup,
      recommendedValue: 'Not assessed',
      severity: 'Low',
      penalty: 0,
      threatName: 'DH Transform Not Captured',
      description: 'No decodable Diffie-Hellman transform was observed in the capture.',
      remediation: 'Capture an IKE_SA_INIT exchange containing the SA payload.',
    });
  } else if (sa.dhBits === 0 || sa.dhGroup.toUpperCase().includes('UNKNOWN')) {
    findings.push({
      id: 'F-DH-UNKNOWN-TRANSFORM',
      parameter: 'Diffie-Hellman Key Exchange',
      detectedValue: sa.dhGroup,
      recommendedValue: 'Known DH group with documented strength',
      severity: 'Low',
      penalty: 0,
      threatName: 'Unsupported DH Transform',
      description: 'A DH transform was observed, but its group strength is not known to this analyzer.',
      remediation: 'Confirm the DH group through an updated transform registry or authorized gateway telemetry.',
    });
  } else if (sa.dhGroupNumber < 14 || (sa.dhGroupNumber < 19 && sa.dhBits < 2048)) {
    const penalty = 30;
    totalScore -= penalty;
    findings.push({
      id: 'F-DH-01',
      parameter: 'Diffie-Hellman Key Exchange',
      detectedValue: `${sa.dhGroup} (${sa.dhBits}-bit)`,
      recommendedValue: 'DH Group 14+ (2048-bit MODP) or Group 19/20 (ECDH)',
      severity: 'Critical',
      penalty,
      cveReference: 'CVE-2015-4000 (Logjam Attack)',
      threatName: 'Logjam & Nation-State Discrete Log Cracking',
      description: 'Diffie-Hellman groups with 1024-bit primes (Group 2) or smaller (Group 1: 768-bit) can be solved using Number Field Sieve precomputations within nation-state adversary budgets.',
      remediation: 'Upgrade to DH Group 14 (MODP 2048-bit), Group 19 (NIST P-256 Elliptic Curve), or Group 20 (NIST P-384).',
    });
  } else {
    findings.push({
      id: 'F-DH-PASS',
      parameter: 'Diffie-Hellman Key Exchange',
      detectedValue: `${sa.dhGroup} (${sa.dhBits}-bit)`,
      recommendedValue: 'DH Group 14+ or ECDH 19/20',
      severity: 'Pass',
      penalty: 0,
      threatName: 'Cryptographically Secure DH Exchange',
      description: 'Meets NIST SP 800-77 guidelines offering at least 112 to 128 bits of equivalent security strength against discrete logarithm attacks.',
      remediation: 'Maintain current DH group.',
    });
  }

  // 4. Perfect Forward Secrecy (PFS)
  if (sa.pfsEnabled === null) {
    findings.push({
      id: 'F-PFS-UNKNOWN',
      parameter: 'Perfect Forward Secrecy (PFS)',
      detectedValue: 'Not observed in capture',
      recommendedValue: 'Not assessed',
      severity: 'Low',
      penalty: 0,
      threatName: 'Child SA PFS Not Captured',
      description: 'PFS cannot be determined from an IKE_SA_INIT exchange alone.',
      remediation: 'Capture CREATE_CHILD_SA exchanges or provide an explicit Child SA configuration.',
    });
  } else if (!sa.pfsEnabled) {
    const penalty = 20;
    totalScore -= penalty;
    findings.push({
      id: 'F-PFS-01',
      parameter: 'Perfect Forward Secrecy (PFS)',
      detectedValue: 'DISABLED',
      recommendedValue: 'ENABLED (Phase 2 DH Rekeying)',
      severity: 'High',
      penalty,
      threatName: 'Harvest-Now-Decrypt-Later (Retroactive Decryption)',
      description: 'Without PFS, Phase 2 Child SAs reuse key material derived from the single initial IKE SA. If the root key is compromised years later, all historical traffic captures can be retroactively decrypted.',
      remediation: 'Enable PFS in ESP child SA configuration so every rekey triggers a new independent Diffie-Hellman exchange.',
    });
  } else {
    findings.push({
      id: 'F-PFS-PASS',
      parameter: 'Perfect Forward Secrecy (PFS)',
      detectedValue: 'ENABLED',
      recommendedValue: 'ENABLED',
      severity: 'Pass',
      penalty: 0,
      threatName: 'Past Communications Protected',
      description: 'A new ephemeral key exchange occurs for each Child SA rekey, isolating session compromises.',
      remediation: 'Keep PFS enabled.',
    });
  }

  // 5. Authentication / Integrity Algorithm
  const authUpper = sa.authIntegrityAlgorithm.toUpperCase();
  if (authUpper.includes('MD5') || authUpper.includes('SHA1')) {
    const penalty = 20;
    totalScore -= penalty;
    findings.push({
      id: 'F-AUTH-01',
      parameter: 'Integrity / Authentication Algorithm',
      detectedValue: sa.authIntegrityAlgorithm,
      recommendedValue: 'HMAC-SHA256, HMAC-SHA384, or AEAD',
      severity: 'High',
      penalty,
      cveReference: 'SHAttered / Flame (MD5 & SHA-1 Collisions)',
      threatName: 'Cryptographic Hash Collision Vulnerability',
      description: 'MD5 and SHA-1 have proven theoretical and practical collision attacks. They are strictly prohibited under modern cryptographic standards.',
      remediation: 'Upgrade integrity transforms to HMAC-SHA256-128 or use AEAD authenticated ciphers.',
    });
  } else if (authUpper.includes('UNKNOWN')) {
    findings.push({
      id: 'F-AUTH-UNKNOWN-TRANSFORM',
      parameter: 'Integrity / Authentication Algorithm',
      detectedValue: sa.authIntegrityAlgorithm,
      recommendedValue: 'Known HMAC-SHA256+ or AEAD',
      severity: 'Low',
      penalty: 0,
      threatName: 'Unsupported Integrity Transform',
      description: 'An integrity transform was observed, but its algorithm is not mapped by this analyzer.',
      remediation: 'Confirm the integrity algorithm through an updated transform registry or authorized gateway telemetry.',
    });
  }

  // 6. Key Lifetime
  if (sa.keyLifetimeSeconds !== null && sa.keyLifetimeSeconds > 28800) { // > 8 hours
    const penalty = 10;
    totalScore -= penalty;
    findings.push({
      id: 'F-TIME-01',
      parameter: 'Security Association Lifetime',
      detectedValue: `${sa.keyLifetimeSeconds / 3600} hours`,
      recommendedValue: '1 to 8 hours (or 10-50 GB volume)',
      severity: 'Medium',
      penalty,
      threatName: 'Extended Key Exposure Window',
      description: 'Excessively long key lifetimes allow attackers more time to gather ciphertext under a single key, increasing exposure to cryptanalysis and key compromise.',
      remediation: 'Configure Phase 1 (IKE) lifetime to max 8 hours and Phase 2 (ESP) lifetime to 1-2 hours or 10-20 GB.',
    });
  }

  // 7. Replay Protection
  if (sa.replayProtection === null) {
    findings.push({
      id: 'F-REPLAY-UNKNOWN',
      parameter: 'Anti-Replay Window Protection',
      detectedValue: 'Not observed in capture',
      recommendedValue: 'Not assessed',
      severity: 'Low',
      penalty: 0,
      threatName: 'Replay Configuration Not Captured',
      description: 'ESP sequence numbers do not reveal the configured replay window.',
      remediation: 'Provide Child SA configuration or negotiated ESN evidence.',
    });
  } else if (!sa.replayProtection) {
    const penalty = 15;
    totalScore -= penalty;
    findings.push({
      id: 'F-REPLAY-01',
      parameter: 'Anti-Replay Window Protection',
      detectedValue: 'Disabled / Window: 0',
      recommendedValue: 'Enabled (64-packet window or ESN)',
      severity: 'High',
      penalty,
      threatName: 'Packet Replay Injection Attack',
      description: 'Without replay protection, attackers intercepting valid encrypted ESP packets can duplicate and re-inject them to trigger state corruption, duplicate orders, or DoS.',
      remediation: 'Enable anti-replay window (minimum 64 packets) and Extended Sequence Numbers (ESN 64-bit) for gigabit links.',
    });
  }

  // Keep observed risk separate from evidence completeness; unknown controls earn no score credit.
  totalScore = Math.max(0, Math.min(100, totalScore));
  const riskPenalty = 100 - totalScore;
  const scoreEvidence = [
    { weight: 10, known: sa.ikeVersion !== 'Not observed in capture' },
    { weight: 20, known: !encUpper.includes('NOT OBSERVED') && !encUpper.includes('UNKNOWN') && sa.encryptionKeyBits > 0 },
    { weight: 15, known: sa.dhGroupNumber > 0 && !sa.dhGroup.toUpperCase().includes('UNKNOWN') },
    { weight: 15, known: !authUpper.includes('NOT OBSERVED') && !authUpper.includes('UNKNOWN') },
    { weight: 15, known: sa.pfsEnabled !== null },
    { weight: 10, known: sa.keyLifetimeSeconds !== null },
    { weight: 15, known: sa.replayProtection !== null },
  ];
  const evidenceCoveragePercent = scoreEvidence.reduce(
    (weight, item) => weight + (item.known ? item.weight : 0),
    0,
  );
  const assessmentStatus: SecurityScorecard['assessmentStatus'] = evidenceCoveragePercent === 100
    ? 'COMPLETE'
    : evidenceCoveragePercent === 0 ? 'INSUFFICIENT' : 'PARTIAL';
  totalScore = Math.round(totalScore * evidenceCoveragePercent / 100);

  let rating: SecurityScorecard['rating'] = evidenceCoveragePercent === 0 ? 'Not Rated' : 'Critical';
  if (evidenceCoveragePercent > 0 && totalScore >= 90) rating = 'Hardened';
  else if (evidenceCoveragePercent > 0 && totalScore >= 75) rating = 'Secure';
  else if (evidenceCoveragePercent > 0 && totalScore >= 55) rating = 'Moderate';
  else if (evidenceCoveragePercent > 0 && totalScore >= 35) rating = 'Weak';

  // Standards Compliance
  const hasCritical = findings.some((f) => f.severity === 'Critical');
  const hasHigh = findings.some((f) => f.severity === 'High');

  const cryptoEvidenceKnown =
    !sa.encryptionAlgorithm.toUpperCase().includes('NOT OBSERVED') &&
    !sa.encryptionAlgorithm.toUpperCase().includes('UNKNOWN') &&
    sa.encryptionKeyBits > 0 &&
    !authUpper.includes('NOT OBSERVED') &&
    !authUpper.includes('UNKNOWN') &&
    sa.dhGroupNumber > 0;
  const nistEvidenceComplete = cryptoEvidenceKnown && sa.ikeVersion !== 'Not observed in capture' &&
    sa.pfsEnabled !== null && sa.keyLifetimeSeconds !== null && sa.replayProtection !== null;
  const rfcEvidenceComplete = cryptoEvidenceKnown;
  const cnsaEvidenceComplete = cryptoEvidenceKnown && sa.encryptionKeyBits > 0 && sa.dhGroupNumber > 0;
  const complianceNist = !nistEvidenceComplete
    ? null
    : !hasCritical && !hasHigh && sa.ikeVersion === 'IKEv2' && sa.pfsEnabled === true && sa.replayProtection === true;
  const complianceRfc8221 = !rfcEvidenceComplete
    ? null
    : !hasCritical && !authUpper.includes('MD5') && !authUpper.includes('SHA1');
  const complianceNsaCnsa = !cnsaEvidenceComplete
    ? null
    : totalScore >= 90 && sa.encryptionKeyBits === 256 && sa.dhGroupNumber >= 19;

  return {
    totalScore,
    riskPenalty,
    evidenceCoveragePercent,
    assessmentStatus,
    rating,
    findings,
    complianceNist,
    complianceRfc8221,
    complianceNsaCnsa,
    metadataLeakageRisk: sa.operationalMode === 'Transport Mode' ? 'High' : sa.operationalMode === 'Tunnel Mode' ? 'Medium' : 'Unknown',
  };
}
