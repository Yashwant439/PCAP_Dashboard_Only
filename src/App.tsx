import React, { useState, useMemo, useCallback } from 'react';
import { BackendCaptureAnalysis, PacketInfo, VpnCaptureScenario, MLAnalysisState, MLAnalysisResult } from './types';
import { auditIpsecSecurity } from './utils/securityAuditor';
import { classifyEspTraffic } from './utils/aiClassifier';
import { ParsedPcapResult, parseUploadedFile } from './utils/pcapParser';
import { analyzeCaptureWithBackend, runMLAnalysis } from './services/analysisApi';
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { AiTrafficAnalysis } from './components/AiTrafficAnalysis';
import { SecurityAssessment } from './components/SecurityAssessment';
import { PacketViewer } from './components/PacketViewer';
import { ReportModal } from './components/ReportModal';
import { TestbedGeneratorModal } from './components/TestbedGeneratorModal';
import { EvidenceSummary } from './components/EvidenceSummary';
import { EvidenceTopology } from './components/EvidenceTopology';
import { MLAnalysisWorkspace } from './components/MLAnalysisWorkspace';
import {
  Shield,
  ShieldAlert,
  Cpu,
  Terminal,
  Sliders,
  CheckCircle2,
  FileText,
  UploadCloud,
  FileCheck,
  AlertTriangle,
  Code2,
  Copy,
  Check,
  BrainCircuit,
} from 'lucide-react';

// ============================================================
// Helper: Map backend packets to frontend PacketInfo
// ============================================================
function mapBackendPackets(analysis: BackendCaptureAnalysis): PacketInfo[] {
  const firstTimestamp = analysis.packets[0]?.timestamp ?? 0;
  return analysis.packets.map((packet) => ({
    id: packet.number,
    timestamp: Math.max(0, (packet.timestamp - firstTimestamp) * 1000),
    sourceIp: packet.source_ip || 'Unknown',
    destIp: packet.destination_ip || 'Unknown',
    protocol: (packet.protocol === 'IKE' || packet.protocol === 'ESP' || packet.protocol === 'AH' || packet.protocol === 'ICMP'
      ? packet.protocol
      : 'OTHER') as PacketInfo['protocol'],
    length: packet.length,
    info: packet.info,
    spi: packet.spi || undefined,
    seq: packet.sequence === null ? undefined : packet.sequence,
    natT: packet.nat_t,
    rawPreview: packet.raw_preview,
  }));
}

function buildBackendCompatibilityResult(file: File, analysis: BackendCaptureAnalysis): ParsedPcapResult {
  const backendPackets = mapBackendPackets(analysis);
  const firstIke = analysis.ike_sas[0];
  return {
    scenarioName: file.name.replace(/\.[^/.]+$/, ''),
    packets: backendPackets,
    sa: {
      ikeVersion: firstIke?.version === 'IKEv1' ? 'IKEv1' : 'IKEv2',
      operationalMode: 'Tunnel Mode',
      ipVersion: backendPackets.some((packet) => packet.sourceIp.includes(':')) ? 'IPv6' : 'IPv4',
      encryptionAlgorithm: 'Not observable',
      encryptionKeyBits: 0,
      authIntegrityAlgorithm: 'Not observable',
      dhGroup: 'Not observable',
      dhGroupNumber: 0,
      dhBits: 0,
      pfsEnabled: false,
      keyLifetimeSeconds: 0,
      replayProtection: false,
      initiatorSpi: firstIke?.initiator_spi || '0x0000000000000000',
      responderSpi: firstIke?.responder_spi || '0x0000000000000000',
    },
    features: {
      packetCount: backendPackets.length,
      totalBytes: backendPackets.reduce((total, packet) => total + packet.length, 0),
      meanPacketLength: backendPackets.length ? Math.round(backendPackets.reduce((total, packet) => total + packet.length, 0) / backendPackets.length) : 0,
      stdPacketLength: 0,
      minPacketLength: backendPackets.length ? Math.min(...backendPackets.map((packet) => packet.length)) : 0,
      maxPacketLength: backendPackets.length ? Math.max(...backendPackets.map((packet) => packet.length)) : 0,
      meanInterArrivalTimeMs: 0,
      burstRatio: 0,
      flowSymmetry: 0,
      calculatedEntropy: 0,
    },
    fileSizeBytes: file.size,
  };
}

// ============================================================
// App
// ============================================================

type TopTab = 'PROTOCOL_ANALYSIS' | 'ML_CRYPTOGRAPHIC';

const INITIAL_ML_STATE: MLAnalysisState = {
  stage: 'IDLE',
  result: null,
  error: null,
};

export default function App() {
  const [scenarios, setScenarios] = useState<VpnCaptureScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<VpnCaptureScenario | null>(null);
  const [activeTab, setActiveTab] = useState<'SECURITY' | 'AI_TRAFFIC' | 'PACKETS'>('SECURITY');
  const [topTab, setTopTab] = useState<TopTab>('ML_CRYPTOGRAPHIC');
  const [inspectedPacketId, setInspectedPacketId] = useState<number | null>(null);

  // ML Analysis state
  const [mlState, setMlState] = useState<MLAnalysisState>(INITIAL_ML_STATE);
  const [mlFilename, setMlFilename] = useState('');

  // Modals
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isTestbedOpen, setIsTestbedOpen] = useState(false);

  // Drag & Drop State
  const [isDragging, setIsDragging] = useState(false);

  // Notifications
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const scorecard = useMemo(() => {
    if (!selectedScenario) return null;
    return auditIpsecSecurity(selectedScenario.sa);
  }, [selectedScenario]);

  const aiPrediction = useMemo(() => {
    if (!selectedScenario) return null;
    return classifyEspTraffic(selectedScenario.features);
  }, [selectedScenario]);

  // ============================================================
  // ML ANALYSIS PIPELINE
  // ============================================================
  const runMLPipeline = useCallback(async (file: File) => {
    setMlFilename(file.name);
    setMlState({ stage: 'UPLOADING', result: null, error: null });

    try {
      const result = await runMLAnalysis(file, {
        onStageChange: (stage) => {
          setMlState((prev) => ({ ...prev, stage }));
        },
      });
      setMlState({ stage: 'COMPLETED', result, error: null });
      showToast(`ML analysis complete for "${file.name}"`);
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'An unexpected error occurred.';
      setMlState({ stage: 'FAILED', result: null, error: errorMsg });
      showToast(`ML analysis failed: ${errorMsg}`);
    }
  }, []);

  const handleMLExportJson = useCallback(() => {
    if (!mlState.result) return;
    const json = JSON.stringify(mlState.result, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ipsec_ml_analysis_${mlState.result.file.name.replace(/\.[^/.]+$/, '')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Exported analysis as JSON');
  }, [mlState.result]);

  const handleMLReset = useCallback(() => {
    setMlState(INITIAL_ML_STATE);
    setMlFilename('');
  }, []);

  // ============================================================
  // PROTOCOL ANALYSIS (existing flow)
  // ============================================================
  const processFile = async (file: File) => {
    try {
      showToast(`Parsing real capture "${file.name}"...`);
      let backendAnalysis;
      try {
        backendAnalysis = await analyzeCaptureWithBackend(file);
        showToast(`Backend evidence analysis completed for "${file.name}".`);
      } catch (backendError) {
        console.warn('Backend analysis unavailable; retaining local compatibility analysis.', backendError);
        showToast('Backend unavailable; showing local compatibility analysis.');
      }

      let parsed;
      try {
        parsed = await parseUploadedFile(file);
      } catch (localError) {
        if (!backendAnalysis) throw localError;
        parsed = buildBackendCompatibilityResult(file, backendAnalysis);
      }

      if (parsed.packets.length === 0) {
        if (!backendAnalysis) {
          showToast('No packets found in capture file.');
          return;
        }
        parsed = buildBackendCompatibilityResult(file, backendAnalysis);
      }

      const newScenario: VpnCaptureScenario = {
        id: `uploaded-${Date.now()}`,
        name: parsed.scenarioName,
        organization: 'Real Captured Network Trace',
        badge: 'Live Capture File',
        description: `Parsed from "${file.name}" (${(parsed.fileSizeBytes / 1024).toFixed(1)} KB) containing ${parsed.packets.length} analyzed packets.`,
        sa: parsed.sa,
        features: parsed.features,
        packets: backendAnalysis ? mapBackendPackets(backendAnalysis) : parsed.packets,
        actualTrafficType: 'Live Real Capture',
        backendAnalysis,
      };

      setScenarios((prev) => [newScenario, ...prev]);
      setSelectedScenario(newScenario);
      showToast(`Analyzed ${parsed.packets.length} packets from "${file.name}"!`);
    } catch (err: unknown) {
      console.error(err);
      const errorMsg = err instanceof Error ? err.message : 'Ensure it is a valid .pcap or network capture.';
      showToast(`Error parsing file: ${errorMsg}`);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (topTab === 'ML_CRYPTOGRAPHIC') {
        await runMLPipeline(file);
      } else {
        await processFile(file);
      }
      e.target.value = '';
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      if (topTab === 'ML_CRYPTOGRAPHIC') {
        await runMLPipeline(file);
      } else {
        await processFile(file);
      }
    }
  };

  const handleLoadCustomScenario = (scenario: VpnCaptureScenario) => {
    setScenarios((prev) => [scenario, ...prev]);
    setSelectedScenario(scenario);
    showToast(`Loaded testbed configuration: ${scenario.name}`);
  };

  const handleSelectScenario = (scenario: VpnCaptureScenario) => {
    setSelectedScenario(scenario);
    setInspectedPacketId(null);
  };

  const handleClearTraces = () => {
    setScenarios([]);
    setSelectedScenario(null);
    setInspectedPacketId(null);
    showToast('Cleared all loaded traces.');
  };

  const handleEvidencePacketSelect = (packetId: number) => {
    setInspectedPacketId(packetId);
    setActiveTab('PACKETS');
  };

  const handleCopyTcpdump = () => {
    navigator.clipboard.writeText('sudo tcpdump -i any -nn -s 0 -w ipsec_capture.pcap "udp port 500 or udp port 4500 or proto 50"');
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
    showToast('Copied tcpdump command to clipboard!');
  };

  // Whether the ML pipeline is actively running
  const mlRunning = mlState.stage !== 'IDLE' && mlState.stage !== 'COMPLETED' && mlState.stage !== 'FAILED';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-blue-600 text-white text-xs font-semibold px-4 py-2.5 rounded-xl shadow-xl flex items-center gap-2 border border-blue-400/40 animate-fade-in">
          <CheckCircle2 className="w-4 h-4" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Header */}
      <Header
        scenarios={scenarios}
        selectedScenario={selectedScenario}
        onSelectScenario={handleSelectScenario}
        onOpenReport={() => setIsReportOpen(true)}
        onOpenTestbed={() => setIsTestbedOpen(true)}
        onFileUpload={handleFileUpload}
        onClearTraces={handleClearTraces}
      />

      {/* Top-level tab switcher */}
      <div className="bg-slate-900 border-b border-slate-800 sticky top-[calc(var(--header-height,72px)+1px)] z-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="flex items-center gap-1 py-2">
            <button
              id="top-tab-ml"
              onClick={() => setTopTab('ML_CRYPTOGRAPHIC')}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                topTab === 'ML_CRYPTOGRAPHIC'
                  ? 'bg-purple-600 text-white shadow-sm shadow-purple-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <BrainCircuit className="w-3.5 h-3.5" />
              <span>ML Cryptographic Analysis</span>
              {(mlState.stage === 'COMPLETED') && (
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              )}
            </button>
            <button
              id="top-tab-protocol"
              onClick={() => setTopTab('PROTOCOL_ANALYSIS')}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                topTab === 'PROTOCOL_ANALYSIS'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Protocol Evidence Analysis</span>
              {selectedScenario && (
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">

        {/* ===== ML CRYPTOGRAPHIC ANALYSIS TAB ===== */}
        {topTab === 'ML_CRYPTOGRAPHIC' && (
          <>
            {mlState.stage === 'IDLE' ? (
              /* Upload dropzone for ML analysis */
              <div className="space-y-6 py-4">
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-2xl p-10 text-center transition-all flex flex-col items-center justify-center ${
                    isDragging
                      ? 'border-purple-500 bg-purple-950/20'
                      : 'border-slate-800 bg-slate-900/60 hover:border-slate-700 hover:bg-slate-900/80'
                  }`}
                >
                  <div className="w-16 h-16 rounded-2xl bg-purple-600/10 border border-purple-500/20 text-purple-400 flex items-center justify-center mb-4 shadow-inner">
                    <BrainCircuit className="w-8 h-8" />
                  </div>

                  <h2 className="text-xl font-bold text-white mb-1">
                    ML Cryptographic Parameter Analysis
                  </h2>
                  <p className="text-xs text-slate-400 max-w-lg mx-auto mb-2 leading-relaxed">
                    Upload an IPsec PCAP capture. The system will extract 18 network traffic features and run four trained ML models to predict:
                  </p>
                  <div className="flex flex-wrap justify-center gap-2 mb-6 text-[11px]">
                    {['Encryption (AES128/AES256)', 'Hash (SHA256/SHA384)', 'DH Group (DH14/DH15)', 'PFS Group (NOPFS/PFS14/PFS15)'].map((l) => (
                      <span key={l} className="px-2 py-1 rounded bg-purple-950/40 border border-purple-800/60 text-purple-300 font-semibold">{l}</span>
                    ))}
                  </div>

                  <div className="flex flex-wrap items-center justify-center gap-3">
                    <label
                      htmlFor="ml-dropzone-file"
                      className="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-purple-500/20 cursor-pointer transition-all flex items-center gap-2"
                    >
                      <FileCheck className="w-4 h-4" />
                      <span>Select .PCAP / .PCAPNG for ML Analysis</span>
                      <input
                        id="ml-dropzone-file"
                        type="file"
                        accept=".pcap,.pcapng,.cap"
                        onChange={async (e) => {
                          const file = e.target.files?.[0];
                          if (file) {
                            await runMLPipeline(file);
                            e.target.value = '';
                          }
                        }}
                        className="hidden"
                      />
                    </label>
                  </div>

                  <div className="mt-4 p-3 rounded-lg bg-amber-950/20 border border-amber-900/50 max-w-lg text-[11px] text-amber-200/80 text-left">
                    <strong className="text-amber-300">Important:</strong> ML predictions are statistical estimates based on traffic patterns — not cryptographic proof.
                    All results are clearly labeled as ML PREDICTION vs OBSERVED.
                    The backend must be running at <code className="text-amber-300">http://localhost:8000</code>.
                  </div>
                </div>
              </div>
            ) : (
              /* ML Analysis workspace (progress + results) */
              <MLAnalysisWorkspace
                state={mlState}
                filename={mlFilename}
                onExportJson={handleMLExportJson}
                onReset={handleMLReset}
              />
            )}
          </>
        )}

        {/* ===== PROTOCOL EVIDENCE ANALYSIS TAB ===== */}
        {topTab === 'PROTOCOL_ANALYSIS' && (
          <>
            {!selectedScenario ? (
              <div className="space-y-6 py-4">

                {/* Main Dropzone Card */}
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-2xl p-10 text-center transition-all flex flex-col items-center justify-center ${
                    isDragging
                      ? 'border-blue-500 bg-blue-950/30'
                      : 'border-slate-800 bg-slate-900/60 hover:border-slate-700 hover:bg-slate-900/80'
                  }`}
                >
                  <div className="w-16 h-16 rounded-2xl bg-blue-600/10 border border-blue-500/20 text-blue-400 flex items-center justify-center mb-4 shadow-inner">
                    <UploadCloud className="w-8 h-8" />
                  </div>

                  <h2 className="text-xl font-bold text-white mb-1">
                    Upload Real Network Capture (.pcap / .pcapng)
                  </h2>
                  <p className="text-xs text-slate-400 max-w-lg mx-auto mb-6 leading-relaxed">
                    All mock/dummy scenarios have been removed. Drag and drop your real IPsec network capture file here, or click below to analyze actual IKE handshakes and ESP encrypted traffic flows.
                  </p>

                  <div className="flex flex-wrap items-center justify-center gap-3">
                    <label
                      htmlFor="dropzone-file"
                      className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-blue-500/20 cursor-pointer transition-all flex items-center gap-2"
                    >
                      <FileCheck className="w-4 h-4" />
                      <span>Select .PCAP / .PCAPNG File</span>
                      <input
                        id="dropzone-file"
                        type="file"
                        accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/vnd.tcpdump.pcapng,application/pcapng,application/json"
                        onChange={handleFileUpload}
                        className="hidden"
                      />
                    </label>

                    <button
                      onClick={() => setIsTestbedOpen(true)}
                      className="px-5 py-2.5 bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 text-xs font-semibold rounded-xl transition-all flex items-center gap-2 cursor-pointer"
                    >
                      <Sliders className="w-4 h-4 text-blue-400" />
                      <span>Generate Testbed Capture</span>
                    </button>
                  </div>

                  <div className="mt-6 flex items-center gap-4 text-[11px] text-slate-400">
                    <span>Supported: Standard Libpcap (.pcap), tcpdump, Wireshark, pcapng</span>
                  </div>
                </div>

                {/* Real Capture Command Guide */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-white text-xs font-bold">
                        <Terminal className="w-4 h-4 text-emerald-400" />
                        <span>How to Capture on Linux (tcpdump)</span>
                      </div>
                      <button
                        onClick={handleCopyTcpdump}
                        className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 border border-slate-700 cursor-pointer"
                      >
                        {copiedCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Run this command on your VPN client or gateway to capture IKE UDP 500/4500 handshakes and IP Protocol 50 (ESP):
                    </p>
                    <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800/80 font-mono text-[11px] text-emerald-300 break-all select-all">
                      sudo tcpdump -i any -nn -s 0 -w ipsec_capture.pcap "udp port 500 or udp port 4500 or proto 50"
                    </div>
                  </div>

                  <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                    <div className="flex items-center gap-2 text-white text-xs font-bold">
                      <Code2 className="w-4 h-4 text-blue-400" />
                      <span>How to Capture in Wireshark</span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      1. Open Wireshark and set the capture filter to: <code className="text-blue-300 bg-slate-950 px-1 py-0.5 rounded">udp port 500 or udp port 4500 or esp</code>
                    </p>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      2. Establish the IPsec connection and generate network traffic over the tunnel.
                    </p>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      3. Save capture as <code className="text-amber-300 bg-slate-950 px-1 py-0.5 rounded">.pcap</code> or <code className="text-amber-300 bg-slate-950 px-1 py-0.5 rounded">.pcapng</code> and drag it into the dropzone above.
                    </p>
                  </div>
                </div>

              </div>
            ) : (
              /* When a real capture file is loaded, show the full live inspection interface */
              <>
                {/* Active Context Banner */}
                <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-sm">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                        {selectedScenario.badge}
                      </span>
                      <h2 className="text-base font-bold text-white">
                        {selectedScenario.name}
                      </h2>
                      <span className="text-xs text-slate-400">
                        • {selectedScenario.organization}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
                      {selectedScenario.description}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      id="btn-quick-report"
                      onClick={() => setIsReportOpen(true)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
                    >
                      <FileText className="w-3.5 h-3.5 text-blue-400" />
                      <span>View Full Report</span>
                    </button>
                  </div>
                </div>

                {selectedScenario.backendAnalysis && (
                  <>
                    <EvidenceSummary analysis={selectedScenario.backendAnalysis} />
                    <EvidenceTopology
                      analysis={selectedScenario.backendAnalysis}
                      onSelectPacket={handleEvidencePacketSelect}
                    />
                  </>
                )}

                {/* 4 Primary Metric Cards */}
                {scorecard && aiPrediction && (
                  <MetricCards
                    sa={selectedScenario.sa}
                    scorecard={scorecard}
                    aiPrediction={aiPrediction}
                    actualTrafficType={selectedScenario.actualTrafficType}
                    backendAnalysis={selectedScenario.backendAnalysis}
                  />
                )}

                {/* Section Navigation Tabs */}
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <div className="inline-flex rounded-xl bg-slate-900 p-1 border border-slate-800 gap-1">
                    <button
                      id="tab-btn-security"
                      onClick={() => setActiveTab('SECURITY')}
                      className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                        activeTab === 'SECURITY'
                          ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Security Assessment &amp; Threat Matrix</span>
                    </button>

                    <button
                      id="tab-btn-ai"
                      onClick={() => setActiveTab('AI_TRAFFIC')}
                      className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                        activeTab === 'AI_TRAFFIC'
                          ? 'bg-purple-600 text-white shadow-sm shadow-purple-500/20'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Cpu className="w-3.5 h-3.5" />
                      <span>AI Traffic Fingerprinting (ESP)</span>
                    </button>

                    <button
                      id="tab-btn-packets"
                      onClick={() => setActiveTab('PACKETS')}
                      className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                        activeTab === 'PACKETS'
                          ? 'bg-cyan-600 text-white shadow-sm shadow-cyan-500/20'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>Packet Dissector &amp; Traces ({selectedScenario.packets.length})</span>
                    </button>
                  </div>

                  <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    <span>Live Dissector Engine Active</span>
                  </div>
                </div>

                {/* Tab Content Display */}
                {activeTab === 'SECURITY' && scorecard && (
                  <SecurityAssessment
                    scorecard={scorecard}
                    sa={selectedScenario.sa}
                    backendAnalysis={selectedScenario.backendAnalysis}
                    onSelectPacket={handleEvidencePacketSelect}
                  />
                )}

                {activeTab === 'AI_TRAFFIC' && aiPrediction && (
                  <AiTrafficAnalysis
                    features={selectedScenario.features}
                    prediction={aiPrediction}
                  />
                )}

                {activeTab === 'PACKETS' && (
                  <PacketViewer
                    packets={selectedScenario.packets}
                    selectedPacketId={inspectedPacketId}
                    onSelectPacket={setInspectedPacketId}
                  />
                )}
              </>
            )}
          </>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 px-6 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            Smart India Hackathon 2026 | Problem Statement 26160
          </div>
          <div className="text-slate-400">
            Target Organization: <strong>National Technical Research Organisation (NTRO)</strong>
          </div>
        </div>
      </footer>

      {/* Modals */}
      {selectedScenario && scorecard && aiPrediction && (
        <ReportModal
          isOpen={isReportOpen}
          onClose={() => setIsReportOpen(false)}
          scenario={selectedScenario}
          scorecard={scorecard}
          prediction={aiPrediction}
        />
      )}

      <TestbedGeneratorModal
        isOpen={isTestbedOpen}
        onClose={() => setIsTestbedOpen(false)}
        onLoadCustomScenario={handleLoadCustomScenario}
      />

    </div>
  );
}
