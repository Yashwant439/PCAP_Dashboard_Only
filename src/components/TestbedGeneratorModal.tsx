import React, { useState } from 'react';
import { X, Sliders, Download, Copy, Check, Terminal, FileCode, Network, ShieldCheck, Server, CircleAlert } from 'lucide-react';
import { GatewaySummary, VpnCaptureScenario } from '../types';
import { generateSyntheticPcapBlob } from '../utils/pcapParser';
import { buildManualCommands, renderSwanctlConfig, TestbedSettings } from '../utils/testbedConfig';
import { getTestbedApplyStatus, queueTestbedApply } from '../utils/gatewayClient';

interface TestbedGeneratorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoadCustomScenario: (scenario: VpnCaptureScenario) => void;
  gateways: GatewaySummary[];
}

export const TestbedGeneratorModal: React.FC<TestbedGeneratorModalProps> = ({
  isOpen,
  onClose,
  onLoadCustomScenario,
  gateways,
}) => {
  const [ikeVersion, setIkeVersion] = useState<'IKEv1' | 'IKEv2'>('IKEv2');
  const [mode, setMode] = useState<'Tunnel Mode' | 'Transport Mode'>('Tunnel Mode');
  const [cipher, setCipher] = useState<'AES-256-GCM' | 'AES-128-GCM' | 'AES-256-CBC' | '3DES-CBC'>('AES-256-GCM');
  const [dhGroup, setDhGroup] = useState<number>(19);
  const [pfs, setPfs] = useState<boolean>(true);
  const [ipVersion, setIpVersion] = useState<'IPv4' | 'IPv6'>('IPv4');
  const [trafficType, setTrafficType] = useState<
    'VoIP / Audio Call' | 'Video Streaming' | 'Web Browsing / HTTPS' | 'Bulk Data Transfer (DB/FTP)'
  >('Video Streaming');
  const [localAddress, setLocalAddress] = useState('172.20.0.2');
  const [remoteAddress, setRemoteAddress] = useState('172.20.0.3');
  const [localId, setLocalId] = useState('peerB');
  const [remoteId, setRemoteId] = useState('peerA');
  const [localTs, setLocalTs] = useState('172.20.0.2/32');
  const [remoteTs, setRemoteTs] = useState('172.20.0.3/32');
  const [authMethod, setAuthMethod] = useState<'psk' | 'pubkey'>('psk');
  const [deploymentMode, setDeploymentMode] = useState<'manual' | 'agent'>('manual');
  const [selectedGatewayId, setSelectedGatewayId] = useState('');
  const [controlToken, setControlToken] = useState('');
  const [applyConfirmed, setApplyConfirmed] = useState(false);
  const [applyRunning, setApplyRunning] = useState(false);
  const [applyMessage, setApplyMessage] = useState<string | null>(null);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const getDhName = (num: number) => {
    switch (num) {
      case 2: return 'DH Group 2 (MODP 1024-bit - Legacy Weak)';
      case 5: return 'DH Group 5 (MODP 1536-bit - Deprecated)';
      case 14: return 'DH Group 14 (MODP 2048-bit - Minimum NIST Standard)';
      case 19: return 'DH Group 19 (ECDH 256-bit NIST P-256 - Modern)';
      case 20: return 'DH Group 20 (ECDH 384-bit NIST P-384 - CNSA Suite)';
      default: return `DH Group ${num}`;
    }
  };

  const getDhBits = (num: number) => {
    if (num === 2) return 1024;
    if (num === 5) return 1536;
    if (num === 14) return 2048;
    if (num === 19) return 256;
    if (num === 20) return 384;
    return 2048;
  };

  const changeIpVersion = (nextVersion: 'IPv4' | 'IPv6') => {
    setIpVersion(nextVersion);
    if (nextVersion === 'IPv6') {
      setLocalAddress('2001:db8:1::10');
      setRemoteAddress('2001:db8:2::20');
      setLocalTs('2001:db8:1::10/128');
      setRemoteTs('2001:db8:2::20/128');
    } else {
      setLocalAddress('172.20.0.2');
      setRemoteAddress('172.20.0.3');
      setLocalTs('172.20.0.2/32');
      setRemoteTs('172.20.0.3/32');
    }
  };

  const settings: TestbedSettings = {
    ikeVersion, mode, cipher, dhGroup: dhGroup as TestbedSettings['dhGroup'], pfs, ipVersion,
    localAddress, remoteAddress, localId, remoteId, authMethod,
    localTs, remoteTs, trafficType,
  };
  const generateConfigText = () => {
    try {
      return renderSwanctlConfig(settings);
    } catch (error) {
      return `# Fix testbed settings to preview a configuration.\n# ${error instanceof Error ? error.message : 'Invalid settings'}`;
    }
  };
  const generateCommandsText = () => buildManualCommands(settings);
  const configuredGateways = gateways.filter((gateway) => gateway.status === 'CONNECTED' && ['STRONGSWAN', 'STRONGSWAN_VICI'].includes(gateway.gateway_type));
  const agentRunCommand = 'python3 /opt/vpn-analyzer-agent/vpn_analyzer_agent.py run --config /agent_config.json --interval 10 --allow-testbed-apply';
  const previewConfig = generateConfigText();
  const configurationIsValid = !previewConfig.startsWith('# Fix testbed settings');

  const handleApplyToAnalyzer = () => {
    // Construct scenario
    const meanLen = trafficType.includes('VoIP') ? 160 : (trafficType.includes('Bulk') ? 1420 : 950);
    const stdLen = trafficType.includes('VoIP') ? 25 : (trafficType.includes('Bulk') ? 80 : 340);
    const iat = trafficType.includes('VoIP') ? 20.0 : (trafficType.includes('Bulk') ? 5.2 : 45.0);

    const customScenario: VpnCaptureScenario = {
      id: `custom-lab-${Date.now()}`,
      name: `Custom Lab: ${cipher} (${mode.split(' ')[0]})`,
      organization: 'Laboratory Testbed Generator',
      badge: 'Custom Generated Capture',
      description: `User-defined testbed configuration running ${trafficType} over ${cipher} with ${getDhName(dhGroup)}.`,
      sa: {
        ikeVersion,
        operationalMode: mode,
        ipVersion,
        encryptionAlgorithm: cipher,
        encryptionKeyBits: cipher.includes('256') ? 256 : (cipher.includes('128') ? 128 : 168),
        authIntegrityAlgorithm: cipher.includes('GCM') ? 'AEAD Combined' : (cipher.includes('3DES') ? 'HMAC-MD5' : 'HMAC-SHA256'),
        dhGroup: getDhName(dhGroup),
        dhGroupNumber: dhGroup,
        dhBits: getDhBits(dhGroup),
        pfsEnabled: pfs,
        keyLifetimeSeconds: 7200,
        replayProtection: true,
        replayWindowSize: 64,
        initiatorSpi: '0x' + Math.floor(Math.random() * 0xffffffff).toString(16),
        responderSpi: '0x' + Math.floor(Math.random() * 0xffffffff).toString(16),
      },
      features: {
        packetCount: 1200,
        totalBytes: 1200 * meanLen,
        meanPacketLength: meanLen,
        stdPacketLength: stdLen,
        minPacketLength: 64,
        maxPacketLength: 1460,
        meanInterArrivalTimeMs: iat,
        burstRatio: trafficType.includes('Bulk') ? 0.9 : 0.4,
        flowSymmetry: trafficType.includes('VoIP') ? 0.95 : 0.6,
        calculatedEntropy: 7.98,
      },
      actualTrafficType: trafficType,
      packets: [
        {
          id: 1,
          timestamp: 0,
          sourceIp: localAddress,
          destIp: remoteAddress,
          protocol: 'IKE',
          length: 320,
          info: `IKE Negotiation Request (${ikeVersion}) - Proposed: ${cipher}, ${getDhName(dhGroup)}`,
        },
        {
          id: 2,
          timestamp: 15,
          sourceIp: remoteAddress,
          destIp: localAddress,
          protocol: 'IKE',
          length: 320,
          info: `IKE Negotiation Response - Accepted SA: ${cipher}, PFS=${pfs ? 'YES' : 'NO'}`,
        },
        {
          id: 3,
          timestamp: 30,
          sourceIp: localAddress,
          destIp: remoteAddress,
          protocol: 'ESP',
          length: meanLen,
          info: `ESP Encrypted Datagram (Simulated ${trafficType})`,
          seq: 1,
        },
      ],
    };

    onLoadCustomScenario(customScenario);
    onClose();
  };

  const handleDownloadPcap = () => {
    // Generate synthetic PCAP
    const dummyScenario: VpnCaptureScenario = {
      id: 'test',
      name: 'Custom',
      organization: 'Lab',
      badge: 'Lab',
      description: 'Lab',
      sa: {
        ikeVersion,
        operationalMode: mode,
        ipVersion,
        encryptionAlgorithm: cipher,
        encryptionKeyBits: 256,
        authIntegrityAlgorithm: 'AEAD',
        dhGroup: getDhName(dhGroup),
        dhGroupNumber: dhGroup,
        dhBits: getDhBits(dhGroup),
        pfsEnabled: pfs,
        keyLifetimeSeconds: 3600,
        replayProtection: true,
        initiatorSpi: '0x1234',
        responderSpi: '0x5678',
      },
      features: {} as any,
      actualTrafficType: trafficType,
      packets: [
        { id: 1, timestamp: 0, sourceIp: localAddress, destIp: remoteAddress, protocol: 'IKE', length: 280, info: 'Simulated IKE request' },
        { id: 2, timestamp: 20, sourceIp: remoteAddress, destIp: localAddress, protocol: 'IKE', length: 280, info: 'Simulated IKE response' },
        { id: 3, timestamp: 40, sourceIp: localAddress, destIp: remoteAddress, protocol: 'ESP', length: 1420, info: `Simulated ESP traffic: ${trafficType}` },
      ],
    };

    const blob = generateSyntheticPcapBlob(dummyScenario);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vpn_lab_${cipher.toLowerCase()}_dh${dhGroup}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadConfig = () => {
    if (!configurationIsValid) return;
    const blob = new Blob([generateConfigText()], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'lab-testbed.conf';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyCommands = async () => {
    try {
      await navigator.clipboard.writeText(generateCommandsText());
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setApplyError('Clipboard access is unavailable. Download the config and copy the listed commands manually.');
    }
  };

  const handleAgentApply = async () => {
    if (!selectedGatewayId || !controlToken || !applyConfirmed) return;
    setApplyRunning(true);
    setApplyError(null);
    setApplyMessage('Queueing the validated configuration for the enrolled gateway agent...');
    try {
      const job = await queueTestbedApply(selectedGatewayId, settings, controlToken);
      const deadline = Date.now() + 120_000;
      while (Date.now() < deadline) {
        const status = await getTestbedApplyStatus(selectedGatewayId, job.jobId, controlToken);
        setApplyMessage(status.message);
        if (status.status === 'SUCCEEDED') return;
        if (status.status === 'FAILED') {
          setApplyError(status.message);
          return;
        }
        await new Promise((resolve) => window.setTimeout(resolve, 1500));
      }
      setApplyError('The agent did not finish before the 2-minute wait expired. Check the gateway agent status before retrying.');
    } catch (error) {
      setApplyError(error instanceof Error ? error.message : 'Could not apply the selected testbed configuration.');
    } finally {
      setApplyRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
      <div className="bg-white border border-slate-200 rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-xl overflow-hidden">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-white">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900">VPN Testbed</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Configure an existing peer pair or export commands for manual setup
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Controls */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5 text-xs text-slate-700">

          <div className="inline-flex p-1 bg-slate-100 border border-slate-200 rounded-lg" role="tablist" aria-label="Deployment mode">
            <button type="button" role="tab" aria-selected={deploymentMode === 'manual'} onClick={() => setDeploymentMode('manual')} className={`px-3 py-1.5 rounded text-xs font-medium ${deploymentMode === 'manual' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'}`}>
              <Terminal className="w-3.5 h-3.5 inline mr-1.5" />Manual CLI
            </button>
            <button type="button" role="tab" aria-selected={deploymentMode === 'agent'} onClick={() => setDeploymentMode('agent')} className={`px-3 py-1.5 rounded text-xs font-medium ${deploymentMode === 'agent' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'}`}>
              <Server className="w-3.5 h-3.5 inline mr-1.5" />Apply via Agent
            </button>
          </div>

          {deploymentMode === 'agent' && (
            <section className="p-4 space-y-3 bg-cyan-50 border border-cyan-200 rounded-lg">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">Apply on an enrolled gateway</h3>
                <p className="text-xs text-slate-600 mt-1">The agent loads this connection into the local StrongSwan daemon and initiates it. The remote peer must already have a matching configuration and credentials.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <label className="space-y-1">
                  <span className="block font-medium text-slate-700">Connected gateway</span>
                  <select value={selectedGatewayId} onChange={(event) => setSelectedGatewayId(event.target.value)} className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900">
                    <option value="">Select gateway</option>
                    {configuredGateways.map((gateway) => <option key={gateway.gateway_id} value={gateway.gateway_id}>{gateway.display_name} ({gateway.gateway_id})</option>)}
                  </select>
                </label>
                <label className="space-y-1">
                  <span className="block font-medium text-slate-700">Local testbed control token</span>
                  <input type="password" autoComplete="off" value={controlToken} onChange={(event) => setControlToken(event.target.value)} className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900" placeholder="From API .env" />
                </label>
              </div>
              <label className="flex items-start gap-2 text-xs text-slate-700">
                <input type="checkbox" checked={applyConfirmed} onChange={(event) => setApplyConfirmed(event.target.checked)} className="mt-0.5 accent-cyan-700" />
                <span>I confirm this will load a temporary connection and initiate traffic on the selected gateway. It does not configure the remote peer or provision credentials.</span>
              </label>
              <button type="button" onClick={handleAgentApply} disabled={!selectedGatewayId || !controlToken || !applyConfirmed || applyRunning || !configuredGateways.length} className="inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded-md bg-cyan-800 hover:bg-cyan-900 text-white disabled:opacity-50">
                <ShieldCheck className="w-4 h-4" />{applyRunning ? 'Waiting for agent...' : 'Apply and initiate tunnel'}
              </button>
              <p className="text-[11px] text-slate-600">Requires the gateway agent to be running with <code>--allow-testbed-apply</code>, plus the API token configured in `.env`. Run only in an authorized lab.</p>
              <div className="flex items-center gap-2">
                <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded bg-white border border-cyan-200 p-2 text-[11px] text-slate-700">{agentRunCommand}</code>
                <button type="button" title="Copy agent command" onClick={() => navigator.clipboard.writeText(agentRunCommand)} className="p-2 bg-white border border-cyan-200 rounded text-cyan-900"><Copy className="w-4 h-4" /></button>
              </div>
              {applyMessage && <p role="status" className="text-xs text-slate-700">{applyMessage}</p>}
              {applyError && <p role="alert" className="text-xs text-rose-700 flex items-start gap-1.5"><CircleAlert className="w-3.5 h-3.5 mt-0.5" />{applyError}</p>}
            </section>
          )}
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            
            {/* IKE Version */}
            <div>
              <label className="block font-medium text-slate-700 mb-1.5">IKE Version</label>
              <select
                value={ikeVersion}
                onChange={(e) => setIkeVersion(e.target.value as any)}
                className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900 text-xs font-medium focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="IKEv2">IKEv2 (Modern Standard - RFC 7296)</option>
                <option value="IKEv1">IKEv1 (Legacy Deprecated - RFC 2409)</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-slate-700 mb-1.5">IP version</label>
              <select value={ipVersion} onChange={(event) => changeIpVersion(event.target.value as 'IPv4' | 'IPv6')} className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900">
                <option value="IPv4">IPv4</option>
                <option value="IPv6">IPv6</option>
              </select>
            </div>

            <label className="space-y-1">
              <span className="block font-medium text-slate-700">Local endpoint</span>
              <input value={localAddress} onChange={(event) => setLocalAddress(event.target.value)} className="w-full bg-white border border-slate-300 rounded-md p-2 font-mono text-slate-900" />
            </label>
            <label className="space-y-1">
              <span className="block font-medium text-slate-700">Remote endpoint</span>
              <input value={remoteAddress} onChange={(event) => setRemoteAddress(event.target.value)} className="w-full bg-white border border-slate-300 rounded-md p-2 font-mono text-slate-900" />
            </label>
            <label className="space-y-1">
              <span className="block font-medium text-slate-700">Local traffic selector (CIDR)</span>
              <input value={localTs} onChange={(event) => setLocalTs(event.target.value)} className="w-full bg-white border border-slate-300 rounded-md p-2 font-mono text-slate-900" />
            </label>
            <label className="space-y-1">
              <span className="block font-medium text-slate-700">Remote traffic selector (CIDR)</span>
              <input value={remoteTs} onChange={(event) => setRemoteTs(event.target.value)} className="w-full bg-white border border-slate-300 rounded-md p-2 font-mono text-slate-900" />
            </label>
            <label className="space-y-1">
              <span className="block font-medium text-slate-700">Local IKE identity</span>
              <input value={localId} onChange={(event) => setLocalId(event.target.value)} className="w-full bg-white border border-slate-300 rounded-md p-2 font-mono text-slate-900" />
            </label>
            <label className="space-y-1">
              <span className="block font-medium text-slate-700">Remote IKE identity</span>
              <input value={remoteId} onChange={(event) => setRemoteId(event.target.value)} className="w-full bg-white border border-slate-300 rounded-md p-2 font-mono text-slate-900" />
            </label>

            <div>
              <label className="block font-medium text-slate-700 mb-1.5">Authentication method</label>
              <select value={authMethod} onChange={(event) => setAuthMethod(event.target.value as 'psk' | 'pubkey')} className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900">
                <option value="psk">PSK reference (must already exist)</option><option value="pubkey">Certificate (must already exist)</option>
              </select>
            </div>

            {/* Mode */}
            <div>
              <label className="block font-medium text-slate-700 mb-1.5">Operating Mode</label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as any)}
                className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900 text-xs font-medium focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="Tunnel Mode">Tunnel Mode (Full IP encapsulation)</option>
                <option value="Transport Mode">Transport Mode (Host-to-host, payload only)</option>
              </select>
            </div>

            {/* Cipher */}
            <div>
              <label className="block font-medium text-slate-700 mb-1.5">Encryption Cipher</label>
              <select
                value={cipher}
                onChange={(e) => setCipher(e.target.value as any)}
                className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900 text-xs font-medium focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="AES-256-GCM">AES-256-GCM (Authenticated AEAD - Recommended)</option>
                <option value="AES-128-GCM">AES-128-GCM (Authenticated AEAD)</option>
                <option value="AES-256-CBC">AES-256-CBC + HMAC-SHA256 (Legacy Mode)</option>
                <option value="3DES-CBC">3DES-CBC (Vulnerable to Sweet32 - Testbed)</option>
              </select>
            </div>

            {/* DH Group */}
            <div>
              <label className="block font-medium text-slate-700 mb-1.5">Diffie-Hellman Group</label>
              <select
                value={dhGroup}
                onChange={(e) => setDhGroup(Number(e.target.value))}
                className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900 text-xs font-medium focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value={19}>DH Group 19 (ECDH 256-bit NIST P-256 - CNSA)</option>
                <option value={20}>DH Group 20 (ECDH 384-bit NIST P-384)</option>
                <option value={14}>DH Group 14 (MODP 2048-bit - Minimum NIST)</option>
                <option value={5}>DH Group 5 (MODP 1536-bit - Weak)</option>
                <option value={2}>DH Group 2 (MODP 1024-bit - Broken Logjam)</option>
              </select>
            </div>

            <label className="flex items-center gap-2 min-h-10 px-3 border border-slate-300 rounded-md bg-white font-medium text-slate-700">
              <input type="checkbox" checked={pfs} onChange={(event) => setPfs(event.target.checked)} className="accent-cyan-800" />
              Perfect Forward Secrecy
            </label>

            {/* Simulated Traffic Type */}
            <div>
              <label className="block font-medium text-slate-700 mb-1.5">Simulated Ingress Traffic</label>
              <select
                value={trafficType}
                onChange={(e) => setTrafficType(e.target.value as any)}
                className="w-full bg-white border border-slate-300 rounded-md p-2 text-slate-900 text-xs font-medium focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="VoIP / Audio Call">VoIP / Audio Call (Small uniform 20ms packets)</option>
                <option value="Video Streaming">Video Streaming (High bandwidth downstream frames)</option>
                <option value="Web Browsing / HTTPS">Web Browsing / HTTPS (Burst then idle pauses)</option>
                <option value="Bulk Data Transfer (DB/FTP)">Bulk Data Transfer (Full MTU 1420b saturated flows)</option>
              </select>
            </div>

          </div>

          {(ikeVersion === 'IKEv1' || cipher === '3DES-CBC' || dhGroup === 2 || dhGroup === 5 || !pfs) && (
            <div className="flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-md text-xs text-amber-900">
              <CircleAlert className="w-4 h-4 shrink-0 mt-0.5" />
              <span>Weak/deprecated selections are for isolated lab testing only. Do not apply these settings to production gateways.</span>
            </div>
          )}

          {/* Generated Config Preview */}
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-800 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-blue-600" />
                Generated Configuration (strongSwan / Libreswan)
              </span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(previewConfig);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="text-xs text-blue-600 hover:text-blue-700 font-medium flex items-center gap-1 cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Config'}</span>
              </button>
            </div>

            <pre className="p-3.5 bg-slate-900 rounded-lg font-mono text-xs text-slate-200 overflow-x-auto border border-slate-800">{previewConfig}</pre>
          </div>

          {deploymentMode === 'manual' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-800 uppercase tracking-wider text-[11px] flex items-center gap-1.5"><Terminal className="w-3.5 h-3.5" />Manual CLI sequence</span>
                <button type="button" disabled={!configurationIsValid} onClick={handleCopyCommands} className="text-xs text-cyan-800 font-medium flex items-center gap-1 disabled:opacity-50"><Copy className="w-3.5 h-3.5" />Copy commands</button>
              </div>
              <pre className="p-3.5 bg-slate-950 rounded-lg font-mono text-xs text-cyan-100 overflow-x-auto border border-slate-800">{configurationIsValid ? generateCommandsText() : 'Correct the endpoint, selector, and identity fields to generate commands.'}</pre>
              <p className="text-[11px] text-slate-500">These commands load the local config and initiate one child SA. Existing peer credentials must already be provisioned; no PSK or private key is generated or included.</p>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-200 bg-slate-50 flex flex-wrap items-center justify-between gap-3">
          <button
            onClick={handleDownloadPcap}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>Download Synthetic .PCAP</span>
          </button>

          {deploymentMode === 'manual' && (
            <button type="button" disabled={!configurationIsValid} onClick={handleDownloadConfig} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 disabled:opacity-50">
              <Download className="w-3.5 h-3.5" />Download swanctl.conf
            </button>
          )}

          <button
            onClick={handleApplyToAnalyzer}
            className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white shadow-xs transition-colors cursor-pointer"
          >
            <span>Load &amp; Analyze This Testbed &rarr;</span>
          </button>
        </div>

      </div>
    </div>
  );
};
