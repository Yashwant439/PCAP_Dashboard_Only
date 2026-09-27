import assert from 'node:assert/strict';
import test from 'node:test';
import { auditIpsecSecurity } from '../src/utils/securityAuditor';

test('unknown cryptography cannot be reported as standards compliant', () => {
  const scorecard = auditIpsecSecurity({
    ikeVersion: 'IKEv2',
    operationalMode: 'Not determined from capture',
    ipVersion: 'IPv4',
    encryptionAlgorithm: 'Not observed in capture',
    encryptionKeyBits: 0,
    authIntegrityAlgorithm: 'Not observed in capture',
    dhGroup: 'Not observed in capture',
    dhGroupNumber: 0,
    dhBits: 0,
    pfsEnabled: null,
    keyLifetimeSeconds: null,
    replayProtection: null,
    initiatorSpi: '0x1',
    responderSpi: 'Not observed in capture',
    proposals: [],
  });

  assert.equal(scorecard.complianceNist, null);
  assert.equal(scorecard.complianceRfc8221, null);
  assert.equal(scorecard.complianceNsaCnsa, null);
});

test('unknown controls reduce evidence-adjusted score and remain unverified', () => {
  const scorecard = auditIpsecSecurity({
    ikeVersion: 'IKEv2',
    operationalMode: 'Not determined from capture',
    ipVersion: 'IPv4',
    encryptionAlgorithm: 'Not observed in capture',
    encryptionKeyBits: 0,
    authIntegrityAlgorithm: 'Not observed in capture',
    dhGroup: 'Not observed in capture',
    dhGroupNumber: 0,
    dhBits: 0,
    pfsEnabled: null,
    keyLifetimeSeconds: null,
    replayProtection: null,
    initiatorSpi: '0x1',
    responderSpi: 'Not observed in capture',
    proposals: [],
  });

  assert.equal(scorecard.totalScore, 10);
  assert.equal(scorecard.riskPenalty, 0);
  assert.equal(scorecard.evidenceCoveragePercent, 10);
  assert.equal(scorecard.assessmentStatus, 'PARTIAL');
  assert.equal(scorecard.complianceNist, null);
  assert.equal(scorecard.complianceRfc8221, null);
});

test('fully evidenced approved suite receives full evidence coverage', () => {
  const scorecard = auditIpsecSecurity({
    ikeVersion: 'IKEv2',
    operationalMode: 'Tunnel Mode',
    ipVersion: 'IPv4',
    encryptionAlgorithm: 'AES-256-GCM',
    encryptionKeyBits: 256,
    authIntegrityAlgorithm: 'AEAD',
    dhGroup: 'Group 19',
    dhGroupNumber: 19,
    dhBits: 256,
    pfsEnabled: true,
    keyLifetimeSeconds: 7200,
    replayProtection: true,
    replayWindowSize: 64,
    initiatorSpi: '0x1',
    responderSpi: '0x2',
    proposals: [],
  });

  assert.equal(scorecard.totalScore, 100);
  assert.equal(scorecard.evidenceCoveragePercent, 100);
  assert.equal(scorecard.assessmentStatus, 'COMPLETE');
  assert.equal(scorecard.complianceNist, true);
});

test('known weak fully observed configuration lowers the security score', () => {
  const scorecard = auditIpsecSecurity({
    ikeVersion: 'IKEv1',
    operationalMode: 'Transport Mode',
    ipVersion: 'IPv4',
    encryptionAlgorithm: '3DES-CBC',
    encryptionKeyBits: 168,
    authIntegrityAlgorithm: 'HMAC-SHA1',
    dhGroup: 'Group 2',
    dhGroupNumber: 2,
    dhBits: 1024,
    pfsEnabled: false,
    keyLifetimeSeconds: 3600,
    replayProtection: false,
    initiatorSpi: '0x1',
    responderSpi: '0x2',
    proposals: [],
  });

  assert.equal(scorecard.evidenceCoveragePercent, 100);
  assert.equal(scorecard.assessmentStatus, 'COMPLETE');
  assert.equal(scorecard.totalScore, 0);
  assert.ok(scorecard.riskPenalty > 0);
  assert.equal(scorecard.complianceNist, false);
  assert.equal(scorecard.rating, 'Critical');
});