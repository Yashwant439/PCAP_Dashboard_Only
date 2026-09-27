export type TestbedSettings = {
  ikeVersion: 'IKEv1' | 'IKEv2';
  mode: 'Tunnel Mode' | 'Transport Mode';
  cipher: 'AES-256-GCM' | 'AES-128-GCM' | 'AES-256-CBC' | '3DES-CBC';
  dhGroup: 2 | 5 | 14 | 19 | 20;
  pfs: boolean;
  ipVersion: 'IPv4' | 'IPv6';
  localAddress: string;
  remoteAddress: string;
  localId: string;
  remoteId: string;
  authMethod: 'psk' | 'pubkey';
  localTs: string;
  remoteTs: string;
  trafficType: 'VoIP / Audio Call' | 'Video Streaming' | 'Web Browsing / HTTPS' | 'Bulk Data Transfer (DB/FTP)';
};

const dhSuffix: Record<TestbedSettings['dhGroup'], string> = {
  2: 'modp1024',
  5: 'modp1536',
  14: 'modp2048',
  19: 'ecp256',
  20: 'ecp384',
};

const safeId = /^[A-Za-z0-9_.@:+-]{1,128}$/;
const safeName = /^[a-z][a-z0-9_]{2,47}$/;
const safePath = /^\/[A-Za-z0-9_./-]+$/;

function validIpv4(value: string): boolean {
  const octets = value.split('.');
  return octets.length === 4 && octets.every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const number = Number(octet);
    return number >= 0 && number <= 255;
  });
}

function validIpv6(value: string): boolean {
  if (!value || value.includes('%') || value.includes(':::') ||
    (value.match(/::/g)?.length ?? 0) > 1 ||
    (value.startsWith(':') && !value.startsWith('::')) ||
    (value.endsWith(':') && !value.endsWith('::'))) return false;
  const compressed = value.includes('::');
  const groups = value.split(':').filter(Boolean);
  if (!groups.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group))) return false;
  return compressed ? groups.length < 8 : groups.length === 8;
}

function validCidr(value: string, ipv6: boolean): boolean {
  const slash = value.lastIndexOf('/');
  if (slash < 0) return false;
  const address = value.slice(0, slash);
  const prefixText = value.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixText)) return false;
  const prefix = Number(prefixText);
  return ipv6
    ? validIpv6(address) && prefix >= 0 && prefix <= 128
    : validIpv4(address) && prefix >= 0 && prefix <= 32;
}

export function validateTestbedSettings(settings: TestbedSettings): TestbedSettings {
  if (!safeId.test(settings.localId) || !safeId.test(settings.remoteId)) {
    throw new Error('Peer IDs may contain only letters, digits, dots, underscores, @, colon, plus, and hyphen.');
  }
  const isIpv6 = settings.ipVersion === 'IPv6';
  const addressValidator = isIpv6 ? validIpv6 : validIpv4;
  if (!addressValidator(settings.localAddress) || !addressValidator(settings.remoteAddress)) {
    throw new Error(`Enter valid ${settings.ipVersion} local and remote endpoint addresses.`);
  }
  if (!validCidr(settings.localTs, isIpv6) || !validCidr(settings.remoteTs, isIpv6)) {
    throw new Error(`Enter valid ${settings.ipVersion} traffic selectors in CIDR notation.`);
  }
  return settings;
}

export function renderSwanctlConfig(
  input: TestbedSettings,
  connectionName = 'lab_testbed',
  childName = 'lab_child',
): string {
  const settings = validateTestbedSettings(input);
  if (!safeName.test(connectionName) || !safeName.test(childName)) {
    throw new Error('Generated StrongSwan connection names are invalid.');
  }

  const dh = dhSuffix[settings.dhGroup];
  const proposals: Record<TestbedSettings['cipher'], { ike: string; esp: string }> = {
    'AES-256-GCM': { ike: `aes256gcm16-prfsha384-${dh}`, esp: `aes256gcm16${settings.pfs ? `-${dh}` : ''}` },
    'AES-128-GCM': { ike: `aes128gcm16-prfsha256-${dh}`, esp: `aes128gcm16${settings.pfs ? `-${dh}` : ''}` },
    'AES-256-CBC': { ike: `aes256-sha256-${dh}`, esp: `aes256-sha256${settings.pfs ? `-${dh}` : ''}` },
    '3DES-CBC': { ike: `3des-sha1-${dh}`, esp: `3des-sha1${settings.pfs ? `-${dh}` : ''}` },
  };
  const selected = proposals[settings.cipher];
  const mode = settings.mode === 'Tunnel Mode' ? 'tunnel' : 'transport';

  return `# Generated testbed configuration. No credentials are included.
# Matching PSK/certificate must already be provisioned on both peers.
connections {
  ${connectionName} {
    version = ${settings.ikeVersion === 'IKEv2' ? '2' : '1'}
    local_addrs = ${settings.localAddress}
    remote_addrs = ${settings.remoteAddress}
    proposals = ${selected.ike}
    reauth_time = 8h

    local {
      auth = ${settings.authMethod}
      id = ${settings.localId}
    }
    remote {
      auth = ${settings.authMethod}
      id = ${settings.remoteId}
    }

    children {
      ${childName} {
        mode = ${mode}
        local_ts = ${settings.localTs}
        remote_ts = ${settings.remoteTs}
        esp_proposals = ${selected.esp}
        rekey_time = 1h
      }
    }
  }
}
`;
}

export function buildManualCommands(
  settings: TestbedSettings,
  configPath = '/etc/swanctl/conf.d/lab-testbed.conf',
): string {
  validateTestbedSettings(settings);
  if (!safePath.test(configPath) || configPath.split('/').includes('..')) {
    throw new Error('Use an absolute config path containing only letters, numbers, dots, underscores, slashes, and hyphens.');
  }
  return [
    `sudo install -m 0644 lab-testbed.conf ${configPath}`,
    `sudo swanctl --load-conns --file ${configPath}`,
    'sudo swanctl --initiate --child lab_child --ike lab_testbed',
    'sudo swanctl --list-sas --raw',
  ].join('\n');
}
