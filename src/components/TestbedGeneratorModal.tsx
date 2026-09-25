import React, { useState } from 'react';
import { X, Sliders, Download, Copy, Check, Terminal, FileCode, Network } from 'lucide-react';
import { VpnCaptureScenario } from '../types';
import { generateSyntheticPcapBlob } from '../utils/pcapParser';

interface TestbedGeneratorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoadCustomScenario: (scenario: VpnCaptureScenario) => void;
}

export const TestbedGeneratorModal: React.FC<TestbedGeneratorModalProps> = ({
  isOpen,
  onClose,
  onLoadCustomScenario,
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

  const generateConfigText = () => {
    return `# ==============================================================
# strongSwan Testbed Configuration (swanctl.conf)
# Target: NTRO PS 26160 VPN Laboratory Generator
# ==============================================================

connections {
  lab-testbed {
    version = ${ikeVersion === 'IKEv2' ? '2' : '1'}
    local_addrs  = ${ipVersion === 'IPv6' ? '2001:db8:1::10' : '192.168.10.1'}
    remote_addrs = ${ipVersion === 'IPv6' ? '2001:db8:2::20' : '192.168.20.1'}

    # Phase 1: IKE SA Proposals
    proposals = ${
      cipher === 'AES-256-GCM'
        ? `aes256gcm16-sha384-${dhGroup === 19 ? 'ecp256' : 'modp' + getDhBits(dhGroup)}`
        : cipher === '3DES-CBC'
        ? '3des-md5-modp1024'
        : `aes256-sha256-modp${getDhBits(dhGroup)}`
    }
    
    children {
      lab-child {
        # Phase 2: ESP Child SA Proposals
        esp_proposals = ${
          cipher === 'AES-256-GCM'
            ? `aes256gcm16${pfs ? (dhGroup === 19 ? '-ecp256' : '-modp' + getDhBits(dhGroup)) : ''}`
            : cipher === '3DES-CBC'
            ? '3des-md5'
            : `aes256-sha256${pfs ? '-modp' + getDhBits(dhGroup) : ''}`
        }
        mode = ${mode === 'Tunnel Mode' ? 'tunnel' : 'transport'}
        rekey_time = 3600s
        esn = yes
      }
    }
  }
}`;
  };

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
          sourceIp: ipVersion === 'IPv6' ? '2001:db8:1::10' : '192.168.10.1',
          destIp: ipVersion === 'IPv6' ? '2001:db8:2::20' : '192.168.20.1',
          protocol: 'IKE',
          length: 320,
          info: `IKE Negotiation Request (${ikeVersion}) - Proposed: ${cipher}, ${getDhName(dhGroup)}`,
        },
        {
          id: 2,
          timestamp: 15,
          sourceIp: ipVersion === 'IPv6' ? '2001:db8:2::20' : '192.168.20.1',
          destIp: ipVersion === 'IPv6' ? '2001:db8:1::10' : '192.168.10.1',
          protocol: 'IKE',
          length: 320,
          info: `IKE Negotiation Response - Accepted SA: ${cipher}, PFS=${pfs ? 'YES' : 'NO'}`,
        },
        {
          id: 3,
          timestamp: 30,
          sourceIp: ipVersion === 'IPv6' ? '2001:db8:1::10' : '192.168.10.1',
          destIp: ipVersion === 'IPv6' ? '2001:db8:2::20' : '192.168.20.1',
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
        { id: 1, timestamp: 0, sourceIp: '192.168.1.1', destIp: '192.168.1.2', protocol: 'IKE', length: 280, info: 'IKE' },
        { id: 2, timestamp: 20, sourceIp: '192.168.1.2', destIp: '192.168.1.1', protocol: 'IKE', length: 280, info: 'IKE' },
        { id: 3, timestamp: 40, sourceIp: '192.168.1.1', destIp: '192.168.1.2', protocol: 'ESP', length: 1420, info: 'ESP' },
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center text-white">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                VPN Testbed &amp; Configuration Generator
              </h2>
              <p className="text-xs text-slate-400">
                Fulfills Task (a) &amp; (b): Generate lab environments, config scripts, and capture traces
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Controls */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5 text-xs text-slate-300">
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            
            {/* IKE Version */}
            <div>
              <label className="block font-semibold text-slate-300 mb-1.5">IKE Version</label>
              <select
                value={ikeVersion}
                onChange={(e) => setIkeVersion(e.target.value as any)}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-white font-medium focus:outline-none focus:border-blue-500"
              >
                <option value="IKEv2">IKEv2 (Modern Standard - RFC 7296)</option>
                <option value="IKEv1">IKEv1 (Legacy Deprecated - RFC 2409)</option>
              </select>
            </div>

            {/* Mode */}
            <div>
              <label className="block font-semibold text-slate-300 mb-1.5">Operating Mode</label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as any)}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-white font-medium focus:outline-none focus:border-blue-500"
              >
                <option value="Tunnel Mode">Tunnel Mode (Full IP encapsulation)</option>
                <option value="Transport Mode">Transport Mode (Host-to-host, payload only)</option>
              </select>
            </div>

            {/* Cipher */}
            <div>
              <label className="block font-semibold text-slate-300 mb-1.5">Encryption Cipher</label>
              <select
                value={cipher}
                onChange={(e) => setCipher(e.target.value as any)}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-white font-medium focus:outline-none focus:border-blue-500"
              >
                <option value="AES-256-GCM">AES-256-GCM (Authenticated AEAD - Recommended)</option>
                <option value="AES-128-GCM">AES-128-GCM (Authenticated AEAD)</option>
                <option value="AES-256-CBC">AES-256-CBC + HMAC-SHA256 (Legacy Mode)</option>
                <option value="3DES-CBC">3DES-CBC (Vulnerable to Sweet32 - Testbed)</option>
              </select>
            </div>

            {/* DH Group */}
            <div>
              <label className="block font-semibold text-slate-300 mb-1.5">Diffie-Hellman Group</label>
              <select
                value={dhGroup}
                onChange={(e) => setDhGroup(Number(e.target.value))}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-white font-medium focus:outline-none focus:border-blue-500"
              >
                <option value={19}>DH Group 19 (ECDH 256-bit NIST P-256 - CNSA)</option>
                <option value={20}>DH Group 20 (ECDH 384-bit NIST P-384)</option>
                <option value={14}>DH Group 14 (MODP 2048-bit - Minimum NIST)</option>
                <option value={5}>DH Group 5 (MODP 1536-bit - Weak)</option>
                <option value={2}>DH Group 2 (MODP 1024-bit - Broken Logjam)</option>
              </select>
            </div>

            {/* PFS */}
            <div>
              <label className="block font-semibold text-slate-300 mb-1.5">Perfect Forward Secrecy (PFS)</label>
              <select
                value={pfs ? 'yes' : 'no'}
                onChange={(e) => setPfs(e.target.value === 'yes')}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-white font-medium focus:outline-none focus:border-blue-500"
              >
                <option value="yes">Enabled (Child SA Rekeying with Ephemeral DH)</option>
                <option value="no">Disabled (Vulnerable to Retroactive Decryption)</option>
              </select>
            </div>

            {/* Simulated Traffic Type */}
            <div>
              <label className="block font-semibold text-slate-300 mb-1.5">Simulated Ingress Traffic</label>
              <select
                value={trafficType}
                onChange={(e) => setTrafficType(e.target.value as any)}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-white font-medium focus:outline-none focus:border-blue-500"
              >
                <option value="VoIP / Audio Call">VoIP / Audio Call (Small uniform 20ms packets)</option>
                <option value="Video Streaming">Video Streaming (High bandwidth downstream frames)</option>
                <option value="Web Browsing / HTTPS">Web Browsing / HTTPS (Burst then idle pauses)</option>
                <option value="Bulk Data Transfer (DB/FTP)">Bulk Data Transfer (Full MTU 1420b saturated flows)</option>
              </select>
            </div>

          </div>

          {/* Generated Config Preview */}
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-white uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-blue-400" />
                Generated Configuration (strongSwan / Libreswan)
              </span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generateConfigText());
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy Config'}</span>
              </button>
            </div>

            <pre className="p-3 bg-slate-950 rounded-lg font-mono text-[11px] text-slate-300 overflow-x-auto border border-slate-800">
              {generateConfigText()}
            </pre>
          </div>

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex flex-wrap items-center justify-between gap-3">
          <button
            onClick={handleDownloadPcap}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Synthetic .PCAP</span>
          </button>

          <button
            onClick={handleApplyToAnalyzer}
            className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition-colors cursor-pointer"
          >
            <span>Load &amp; Analyze This Testbed In Dashboard →</span>
          </button>
        </div>

      </div>
    </div>
  );
};
