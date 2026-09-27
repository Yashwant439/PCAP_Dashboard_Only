import assert from 'node:assert/strict';
import test from 'node:test';
import { buildManualCommands, renderSwanctlConfig, TestbedSettings, validateTestbedSettings } from '../src/utils/testbedConfig';

const settings: TestbedSettings = {
  ikeVersion: 'IKEv2',
  mode: 'Tunnel Mode',
  cipher: 'AES-256-GCM',
  dhGroup: 19,
  pfs: true,
  ipVersion: 'IPv4',
  localAddress: '172.20.0.2',
  remoteAddress: '172.20.0.3',
  localId: 'peerB',
  remoteId: 'peerA',
  authMethod: 'psk',
  localTs: '172.20.0.2/32',
  remoteTs: '172.20.0.3/32',
  trafficType: 'Video Streaming',
};

test('renders proposals, endpoints, selectors, and no credentials', () => {
  const config = renderSwanctlConfig(settings);
  assert.match(config, /aes256gcm16-prfsha384-ecp256/);
  assert.match(config, /esp_proposals = aes256gcm16-ecp256/);
  assert.match(config, /local_addrs = 172\.20\.0\.2/);
  assert.match(config, /remote_ts = 172\.20\.0\.3\/32/);
  assert.match(config, /auth = psk/);
  assert.doesNotMatch(config, /secret\s*=|data\s*=|private_key/i);
});

test('manual commands are fixed and reject shell-path injection', () => {
  assert.match(buildManualCommands(settings), /swanctl --load-conns --file/);
  assert.match(buildManualCommands(settings), /swanctl --initiate --child lab_child --ike lab_testbed/);
  assert.throws(() => buildManualCommands(settings, '/tmp/conf;touch /tmp/pwn'), /absolute config path/);
});

test('rejects invalid IPv4 octets, selector prefixes, IDs, and family mismatch', () => {
  assert.throws(() => validateTestbedSettings({ ...settings, localAddress: '999.20.0.2' }), /valid IPv4/);
  assert.throws(() => validateTestbedSettings({ ...settings, localTs: '172.20.0.2/33' }), /valid IPv4/);
  assert.throws(() => validateTestbedSettings({ ...settings, localId: 'peerB\nproposals=bad' }), /Peer IDs/);
  assert.throws(() => validateTestbedSettings({ ...settings, ipVersion: 'IPv6' }), /valid IPv6/);
});

test('supports correctly formatted IPv6 endpoints and selectors', () => {
  const ipv6 = {
    ...settings,
    ipVersion: 'IPv6' as const,
    localAddress: '2001:db8:1::10',
    remoteAddress: '2001:db8:2::20',
    localTs: '2001:db8:1::10/128',
    remoteTs: '2001:db8:2::20/128',
  };
  assert.equal(validateTestbedSettings(ipv6).remoteAddress, '2001:db8:2::20');
  assert.throws(() => validateTestbedSettings({ ...ipv6, localAddress: '2001:::1' }), /valid IPv6/);
});
