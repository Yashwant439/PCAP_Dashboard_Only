import assert from 'node:assert/strict';
import test from 'node:test';
import type { VpnCaptureScenario } from '../src/types';
import { classifyEspTraffic } from '../src/utils/aiClassifier';
import { buildAssessmentSnapshot, buildReportSections, formatAssessmentMarkdown } from '../src/utils/assessmentReport';
import { auditIpsecSecurity } from '../src/utils/securityAuditor';

const capture = (): VpnCaptureScenario => ({
  id: 'sample-1',
  name: 'Controlled capture',
  organization: 'Lab',
  badge: 'Lab',
  description: 'Synthetic test capture',
  actualTrafficType: 'Live Real Capture',
  packets: [],
  sa: {
    ikeVersion: 'IKEv2', operationalMode: 'Tunnel Mode', ipVersion: 'IPv4',
    encryptionAlgorithm: 'Not observed in capture', encryptionKeyBits: 0,
    authIntegrityAlgorithm: 'Not observed in capture', dhGroup: 'Not observed in capture',
    dhGroupNumber: 0, dhBits: 0, pfsEnabled: null, keyLifetimeSeconds: null,
    replayProtection: null, initiatorSpi: '0x1', responderSpi: 'Not observed in capture', proposals: [],
  },
  features: {
    packetCount: 30, totalBytes: 4800, meanPacketLength: 160, stdPacketLength: 15,
    minPacketLength: 130, maxPacketLength: 195, meanInterArrivalTimeMs: 20,
    burstRatio: 0.1, flowSymmetry: 0.9, calculatedEntropy: 7.4,
  },
});

test('executive and technical exports differ and keep unknown controls separate from scored risk', () => {
  const scenario = capture();
  const scorecard = auditIpsecSecurity(scenario.sa);
  const prediction = classifyEspTraffic(scenario.features);
  const snapshot = buildAssessmentSnapshot(scenario, scorecard, prediction);
  assert.equal(snapshot.riskScore, 0);
  assert.equal(snapshot.threats.length, 0);
  assert.ok(snapshot.evidenceGaps.length > 0);
  assert.equal(snapshot.aiConfidenceScore, null);
  assert.equal(prediction.source, 'DERIVED_FROM_OBSERVED_DATA');

  const executive = formatAssessmentMarkdown('EXECUTIVE', scenario, buildReportSections('EXECUTIVE', scenario, scorecard, prediction));
  const technical = formatAssessmentMarkdown('TECHNICAL', scenario, buildReportSections('TECHNICAL', scenario, scorecard, prediction));
  assert.match(executive, /Observed configuration risk score: 0\/100/);
  assert.match(executive, /Evidence gaps/);
  assert.match(executive, /AI confidence score: Unavailable/);
  assert.doesNotMatch(executive, /Cryptographic parameters/);
  assert.match(technical, /Cryptographic parameters/);
  assert.match(technical, /Traffic analysis and metadata inference/);
});

test('trained model confidence is reported separately from workload pattern match', () => {
  const scenario = capture();
  scenario.mlPredictions = {
    encryption: { prediction: 'AES128', confidence: 0.8, probabilities: { AES128: 0.8 } },
    hash: { prediction: 'SHA256', confidence: 0.7, probabilities: { SHA256: 0.7 } },
    dh_group: { prediction: 'DH14', confidence: 0.9, probabilities: { DH14: 0.9 } },
    pfs_group: { prediction: 'NOPFS', confidence: 0.6, probabilities: { NOPFS: 0.6 } },
  };
  const scorecard = auditIpsecSecurity(scenario.sa);
  const prediction = classifyEspTraffic(scenario.features);
  const snapshot = buildAssessmentSnapshot(scenario, scorecard, prediction);
  assert.equal(snapshot.aiConfidenceScore, 75);
  assert.equal(snapshot.aiConfidenceModels, 4);
  assert.notEqual(snapshot.trafficMatchScore, snapshot.aiConfidenceScore);
  const technical = formatAssessmentMarkdown('TECHNICAL', scenario, buildReportSections('TECHNICAL', scenario, scorecard, prediction));
  assert.match(technical, /Mean predicted-class probability across 4 available cryptographic inference models/);
  assert.match(technical, /Cryptographic model predictions/);
});
