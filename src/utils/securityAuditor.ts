import { IkeSecurityAssociation, SecurityFinding, SecurityScorecard } from '../types';

export function auditIpsecSecurity(sa: IkeSecurityAssociation): SecurityScorecard {
  const findings: SecurityFinding[] = [];
  let totalScore = 100;

  // 1. IKE Version Audit
  if (sa.ikeVersion === 'IKEv1') {
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
  if (encUpper.includes('3DES') || encUpper.includes('DES')) {
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
  if (sa.dhGroupNumber < 14 || sa.dhBits < 2048) {
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
  if (!sa.pfsEnabled) {
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
  }

  // 6. Key Lifetime
  if (sa.keyLifetimeSeconds > 28800) { // > 8 hours
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
  if (!sa.replayProtection) {
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

  // Normalize Total Score
  totalScore = Math.max(0, Math.min(100, totalScore));

  let rating: SecurityScorecard['rating'] = 'Critical';
  if (totalScore >= 90) rating = 'Hardened';
  else if (totalScore >= 75) rating = 'Secure';
  else if (totalScore >= 55) rating = 'Moderate';
  else if (totalScore >= 35) rating = 'Weak';
  else rating = 'Critical';

  // Standards Compliance
  const hasCritical = findings.some((f) => f.severity === 'Critical');
  const hasHigh = findings.some((f) => f.severity === 'High');

  const complianceNist = !hasCritical && !hasHigh && sa.ikeVersion === 'IKEv2';
  const complianceRfc8221 = !hasCritical && !authUpper.includes('MD5') && !authUpper.includes('SHA1');
  const complianceNsaCnsa = totalScore >= 90 && sa.encryptionKeyBits === 256 && sa.dhGroupNumber >= 19;

  return {
    totalScore,
    rating,
    findings,
    complianceNist,
    complianceRfc8221,
    complianceNsaCnsa,
    metadataLeakageRisk: sa.operationalMode === 'Transport Mode' ? 'High' : 'Medium',
  };
}
