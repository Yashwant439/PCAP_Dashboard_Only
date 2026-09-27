import assert from 'node:assert/strict';
import test from 'node:test';
import { buildGatewayTelemetrySummary } from '../src/utils/scapyClient';

test('buildGatewayTelemetrySummary marks exact SPI matches as confirmed', () => {
  const summary = buildGatewayTelemetrySummary({
    analysisId: 'analysis-001',
    pcapSpis: ['0x1234'],
    telemetry: [{
      gatewayId: 'gw-1',
      adapter: 'STRONGSWAN',
      source: 'GATEWAY_TELEMETRY',
      status: 'CONFIRMED',
      collectedAt: '2026-09-24T00:00:00Z',
      records: [{ outbound_spi: '0x1234', encr: 'aes256gcm16' }],
      evidence: ['Read-only swanctl SA telemetry was parsed from the gateway.'],
    }],
    correlation: {
      correlation_status: 'CONFIRMED',
      matched: [{ correlation_status: 'CONFIRMED', matched_spis: ['0x1234'], telemetry: { outbound_spi: '0x1234' } }],
      unmatchedTelemetry: [],
      unmatchedPcapSpis: [],
    },
  });

  assert.equal(summary.correlationStatus, 'CONFIRMED');
  assert.equal(summary.gatewayStatus, 'CONFIRMED');
  assert.equal(summary.matchedSpis.length, 1);
  assert.equal(summary.matchedSpis[0], '0x1234');
});

test('buildGatewayTelemetrySummary keeps unknown outcomes when telemetry is unavailable', () => {
  const summary = buildGatewayTelemetrySummary({
    analysisId: 'analysis-002',
    pcapSpis: ['0x99aa'],
    telemetry: [{
      gatewayId: 'gw-1',
      adapter: 'STRONGSWAN',
      source: 'GATEWAY_TELEMETRY',
      status: 'NOT_DETERMINABLE',
      collectedAt: '2026-09-24T00:00:00Z',
      records: [],
      evidence: ['swanctl is not installed or is not available on PATH.'],
      error: 'STRONGSWAN_CONTROL_TOOL_UNAVAILABLE',
    }],
    correlation: {
      correlation_status: 'UNKNOWN',
      matched: [],
      unmatchedTelemetry: [{ correlation_status: 'UNKNOWN', telemetry: { outbound_spi: '0x77bb' }, evidence: 'No exact PCAP SPI match was available.' }],
      unmatchedPcapSpis: ['0x99aa'],
    },
  });

  assert.equal(summary.correlationStatus, 'UNKNOWN');
  assert.equal(summary.gatewayStatus, 'NOT_DETERMINABLE');
  assert.deepEqual(summary.unmatchedPcapSpis, ['0x99aa']);
});
