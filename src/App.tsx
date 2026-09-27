import React, { useState, useMemo, useEffect, useCallback, lazy, Suspense } from 'react';
import { VpnCaptureScenario, GatewaySummary, GatewayCorrelationResult } from './types';
import { auditIpsecSecurity } from './utils/securityAuditor';
import { classifyEspTraffic } from './utils/aiClassifier';
import { buildGatewayTelemetrySummary, fetchAnalysisTelemetry, parseWithScapy, registerAnalysis } from './utils/scapyClient';
import { addSecurityAssociationEvidence } from './analysis/evidence';
import { Header, AppNavView } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { ReportsView } from './components/ReportsView';
import { MetricCards } from './components/MetricCards';
import { AssessmentOverview } from './components/AssessmentOverview';
import { AiTrafficAnalysis } from './components/AiTrafficAnalysis';
import { SecurityAssessment } from './components/SecurityAssessment';
import { PacketViewer } from './components/PacketViewer';
import { GatewaysManager } from './components/GatewaysManager';
import { GatewayDetailsModal } from './components/GatewayDetailsModal';
import { AddGatewayModal } from './components/AddGatewayModal';
import { CommandPalette, PipelineStepper, StatusDrawer, useThemePreference } from './components/workstation/WorkstationTools';
import { CaptureProfile } from './components/workstation/CaptureProfile';
import { fetchGateways } from './utils/gatewayClient';
import type { AssessmentReportKind } from './utils/assessmentReport';
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
  Code2,
  Copy,
  Check,
  Server,
} from 'lucide-react';

// The testbed imports synthetic-PCAP code; defer it until the user opens the lab.
const TestbedGeneratorModal = lazy(() => import('./components/TestbedGeneratorModal').then(module => ({ default: module.TestbedGeneratorModal })));
const ReportModal = lazy(() => import('./components/ReportModal').then(module => ({ default: module.ReportModal })));
const GatewayReportModal = lazy(() => import('./components/GatewayReportModal').then(module => ({ default: module.GatewayReportModal })));

export default function App() {
  const { theme, setTheme } = useThemePreference();
  const [scenarios, setScenarios] = useState<VpnCaptureScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<VpnCaptureScenario | null>(null);
  const [activeTab, setActiveTab] = useState<'SECURITY' | 'AI_TRAFFIC' | 'PACKETS'>('SECURITY');

  // Top-level view navigation
  const [currentView, setCurrentView] = useState<AppNavView>('ANALYSIS');

  // Gateway count and available gateways for Mode 3 correlation
  const [gatewayCount, setGatewayCount] = useState(0);
  const [availableGateways, setAvailableGateways] = useState<GatewaySummary[]>([]);
  const [selectedGatewayId, setSelectedGatewayId] = useState<string>('');

  // Modals
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [requestedReportKind, setRequestedReportKind] = useState<AssessmentReportKind>('EXECUTIVE');
  const [isTestbedOpen, setIsTestbedOpen] = useState(false);
  const [isAddGatewayOpen, setIsAddGatewayOpen] = useState(false);
  const [selectedDetailGatewayId, setSelectedDetailGatewayId] = useState<string | null>(null);
  const [selectedReportGatewayId, setSelectedReportGatewayId] = useState<string | null>(null);

  // Drag & Drop State
  const [isDragging, setIsDragging] = useState(false);

  // Notifications
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStage, setAnalysisStage] = useState(0);
  const [isCommandOpen, setIsCommandOpen] = useState(false);
  const [isStatusOpen, setIsStatusOpen] = useState(false);
  const [technicalMode, setTechnicalMode] = useState(() => localStorage.getItem('vpn-analysis-mode') === 'technical');

  useEffect(() => { localStorage.setItem('vpn-analysis-mode', technicalMode ? 'technical' : 'simple'); }, [technicalMode]);

  const showToast = useCallback((msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  }, []);

  const openReport = (kind: AssessmentReportKind = 'EXECUTIVE') => {
    setRequestedReportKind(kind);
    setIsReportOpen(true);
  };

  // Fetch gateway count and list for nav badge and Mode 3 selection, auto-refresh every 15 seconds
  const refreshGatewayCount = useCallback(async () => {
    try {
      const gws = await fetchGateways();
      setGatewayCount(gws.length);
      setAvailableGateways(gws);
    } catch {
      // API may not be running — silently ignore
    }
  }, []);

  useEffect(() => {
    refreshGatewayCount();
    const timer = setInterval(refreshGatewayCount, 15000);
    return () => clearInterval(timer);
  }, [refreshGatewayCount]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setIsCommandOpen(true); }
      if (event.key === 'Escape') { setIsCommandOpen(false); setIsStatusOpen(false); }
      if (event.key === '?' && !(event.target instanceof HTMLInputElement)) showToast('Shortcuts: Ctrl/Cmd+K command palette · Esc closes panels.');
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [showToast]);

  // Compute security assessment & AI classification dynamically for the selected real scenario
  const scorecard = useMemo(() => {
    if (!selectedScenario) return null;
    return auditIpsecSecurity(selectedScenario.sa);
  }, [selectedScenario]);

  const aiPrediction = useMemo(() => {
    if (!selectedScenario) return null;
    return classifyEspTraffic(selectedScenario.features);
  }, [selectedScenario]);

  const processFile = async (file: File, gatewayOverride?: string) => {
    setIsAnalyzing(true);
    setAnalysisStage(0);
    try {
      const activeGwId = gatewayOverride !== undefined ? gatewayOverride : (selectedGatewayId || undefined);
      showToast(
        activeGwId
          ? `Analyzing capture "${file.name}" & correlating with gateway...`
          : `Analyzing real capture "${file.name}" with Scapy...`
      );

      setAnalysisStage(1);
      let parsed;
      try {
        parsed = await parseWithScapy(file);
      } catch (scapyError) {
        console.warn('Scapy analyzer unavailable; using browser parser.', scapyError);
        const { parseUploadedFile } = await import('./utils/pcapParser');
        parsed = await parseUploadedFile(file);
      }

      setAnalysisStage(2);

      if (parsed.packets.length === 0) {
        showToast('No packets found in capture file.');
        return;
      }

      let analysisId: string | undefined;
      let initialTelemetry = null;
      try {
        const analysis = await registerAnalysis(file, activeGwId);
        analysisId = analysis.analysisId;
        initialTelemetry = analysis.gatewayTelemetry ?? null;
      } catch (analysisError) {
        console.warn('Central analysis registration unavailable; continuing with local PCAP analysis only.', analysisError);
      }

      const packetSpis: string[] = (parsed.packets || [])
        .map((p) => p.spi)
        .filter((spi): spi is string => typeof spi === 'string' && spi.trim().length > 0);
      const obsSpis: string[] = parsed.sa?.observations?.espSpis ?? [];
      const pcapSpis: string[] = Array.from(new Set<string>([...obsSpis, ...packetSpis]));

      let telemetrySummary = initialTelemetry;
      if (analysisId && !telemetrySummary && activeGwId) {
        try {
          telemetrySummary = await fetchAnalysisTelemetry(analysisId, activeGwId);
        } catch (telemetryError) {
          console.warn('Gateway telemetry could not be fetched for this analysis.', telemetryError);
        }
      }

      const defaultCorrelation: GatewayCorrelationResult = {
        correlation_status: 'UNKNOWN',
        matched: [],
        unmatchedTelemetry: [],
        unmatchedPcapSpis: pcapSpis,
      };

      const mergedTelemetry = telemetrySummary ?? buildGatewayTelemetrySummary({
        analysisId,
        pcapSpis,
        telemetry: [],
        correlation: defaultCorrelation,
      });

      const matchedGw = activeGwId ? availableGateways.find((g) => g.gateway_id === activeGwId) : undefined;
      const newScenario: VpnCaptureScenario = {
        id: `uploaded-${Date.now()}`,
        name: parsed.scenarioName,
        organization: matchedGw ? `Gateway: ${matchedGw.display_name}` : 'Real Captured Network Trace',
        badge: activeGwId ? 'Mode 3 Combined' : 'Live Capture File',
        description: `Parsed from "${file.name}" (${(parsed.fileSizeBytes / 1024).toFixed(1)} KB) containing ${parsed.packets.length} analyzed packets.${
          activeGwId ? ` Correlated against gateway ${matchedGw?.display_name || activeGwId}.` : ''
        }`,
        sa: addSecurityAssociationEvidence(parsed.sa),
        features: parsed.features,
        packets: parsed.packets,
        actualTrafficType: 'Live Real Capture',
        gatewayTelemetry: mergedTelemetry,
        correlation: mergedTelemetry.correlation,
        mlPredictions: parsed.mlPredictions ?? null,
        mlSecurityFindings: parsed.mlSecurityFindings ?? [],
        mlWarning: parsed.mlWarning ?? null,
      };

      setScenarios((prev) => [newScenario, ...prev]);
      setAnalysisStage(3);
      setSelectedScenario(newScenario);
      // Switch to analysis view when a file is uploaded from Gateways view
      setCurrentView('ANALYSIS');
      showToast(
        activeGwId
          ? `Analysis & Gateway correlation complete: ${mergedTelemetry.correlationStatus}`
          : `Analyzed ${parsed.packets.length} packets from "${file.name}"!`
      );
    } catch (err: unknown) {
      console.error(err);
      const errorMsg = err instanceof Error ? err.message : 'Ensure it is a valid .pcap or network capture.';
      showToast(`Error parsing file: ${errorMsg}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCommand = (action: string) => {
    if (action === 'analysis') setCurrentView('ANALYSIS');
    else if (action === 'report' && selectedScenario) openReport();
    else if (action === 'gateways') setCurrentView('GATEWAYS');
    else if (action === 'testbed') setIsTestbedOpen(true);
    else if (action === 'theme') setTheme(theme === 'dark' ? 'light' : 'dark');
    else if (action === 'help') showToast('Source badges identify observed, inferred, telemetry, or rule-derived results.');
    else if (action === 'upload') document.getElementById('dropzone-file')?.click();
  };

  const correlateLoadedScenario = async (gatewayId: string) => {
    if (!selectedScenario) return;
    try {
      showToast(`Correlating loaded capture with gateway ${gatewayId}...`);
      const analysisId = selectedScenario.gatewayTelemetry?.analysisId;
      if (!analysisId) {
        showToast('No central analysis ID found for this session.');
        return;
      }
      const telemetrySummary = await fetchAnalysisTelemetry(analysisId, gatewayId);
      if (telemetrySummary) {
        setSelectedScenario((prev) => {
          if (!prev) return prev;
          const matchedGw = availableGateways.find((g) => g.gateway_id === gatewayId);
          return {
            ...prev,
            organization: matchedGw ? `Gateway: ${matchedGw.display_name}` : prev.organization,
            badge: 'Mode 3 Combined',
            gatewayTelemetry: telemetrySummary,
            correlation: telemetrySummary.correlation,
          };
        });
        showToast(`Correlation updated: ${telemetrySummary.correlationStatus}`);
      } else {
        showToast('Could not retrieve telemetry for this gateway.');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error';
      showToast(`Correlation failed: ${msg}`);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await processFile(file);
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
      await processFile(file);
    }
  };

  const handleLoadCustomScenario = (scenario: VpnCaptureScenario) => {
    setScenarios((prev) => [scenario, ...prev]);
    setSelectedScenario(scenario);
    setCurrentView('ANALYSIS');
    showToast(`Loaded testbed configuration: ${scenario.name}`);
  };

  const handleClearTraces = () => {
    setScenarios([]);
    setSelectedScenario(null);
    showToast('Cleared all loaded traces.');
  };

  const handleCopyTcpdump = () => {
    navigator.clipboard.writeText('sudo tcpdump -i any -nn -s 0 -w ipsec_capture.pcap "udp port 500 or udp port 4500 or proto 50"');
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
    showToast('Copied tcpdump command to clipboard!');
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans">

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 text-white text-xs font-semibold px-4 py-2.5 rounded-lg shadow-xl flex items-center gap-2 border border-slate-700 animate-fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Header */}
      <Header
        scenarios={scenarios}
        selectedScenario={selectedScenario}
        onSelectScenario={(s) => {
          setSelectedScenario(s);
          setCurrentView('ANALYSIS');
        }}
        onOpenReport={() => openReport()}
        onOpenTestbed={() => setIsTestbedOpen(true)}
        onFileUpload={handleFileUpload}
        onClearTraces={handleClearTraces}
        currentView={currentView}
        onViewChange={setCurrentView}
        gatewayCount={gatewayCount}
        theme={theme}
        onThemeChange={setTheme}
        onOpenCommandPalette={() => setIsCommandOpen(true)}
        onOpenStatus={() => setIsStatusOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-5">

        {/* ─── DASHBOARD VIEW ─── */}
        {currentView === 'DASHBOARD' && (
          <DashboardView
            gateways={availableGateways}
            scenarios={scenarios}
            onNavigateToAnalysis={() => setCurrentView('ANALYSIS')}
            onNavigateToGateways={() => setCurrentView('GATEWAYS')}
            onNavigateToReports={() => setCurrentView('REPORTS')}
            onSelectScenario={(s) => {
              setSelectedScenario(s);
              setCurrentView('ANALYSIS');
            }}
            onAddGateway={() => setIsAddGatewayOpen(true)}
            onViewGateway={(id) => {
              setSelectedDetailGatewayId(id);
            }}
          />
        )}

        {/* ─── REPORTS VIEW ─── */}
        {currentView === 'REPORTS' && (
          <ReportsView
            scenarios={scenarios}
            gateways={availableGateways}
            onViewScenarioReport={(s, kind) => {
              setSelectedScenario(s);
              openReport(kind);
            }}
            onViewGatewayReport={(gwId) => {
              setSelectedReportGatewayId(gwId);
            }}
          />
        )}

        {/* ─── GATEWAYS VIEW ─── */}
        {currentView === 'GATEWAYS' && (
          <GatewaysManager
            onSelectGatewayForAnalysis={(gatewayId) => {
              setSelectedGatewayId(gatewayId);
              setCurrentView('ANALYSIS');
              if (selectedScenario) {
                correlateLoadedScenario(gatewayId);
              } else {
                showToast(`Gateway selected. Upload a PCAP to perform Mode 3 correlation.`);
              }
            }}
            onShowToast={showToast}
          />
        )}

        {/* ─── ANALYSIS VIEW ─── */}
        {currentView === 'ANALYSIS' && (
          <>
            {/* If no real file has been uploaded yet, show Clean Upload & Testbed Hub */}
            {!selectedScenario ? (
              <div className="space-y-5 py-2">

                {/* Main Upload Zone */}
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-lg p-10 text-center transition-all flex flex-col items-center justify-center ${
                    isDragging
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-slate-300 bg-white hover:border-slate-400 hover:bg-slate-50'
                  }`}
                >
                  <div className="w-12 h-12 rounded-lg bg-slate-100 border border-slate-200 text-slate-400 flex items-center justify-center mb-4">
                    <UploadCloud className="w-6 h-6" />
                  </div>

                  <h2 className="text-base font-semibold text-slate-900 mb-1">
                    Upload Network Capture
                  </h2>
                  <p className="text-sm text-slate-500 max-w-lg mx-auto mb-6 leading-relaxed">
                    Drop a <code className="font-mono bg-slate-100 px-1 rounded text-xs">.pcap</code> or <code className="font-mono bg-slate-100 px-1 rounded text-xs">.pcapng</code> file here to analyze real IKE handshakes and ESP traffic flows.
                  </p>

                  {/* Mode 1 vs Mode 3 Gateway Correlation Selector */}
                  <div className="mb-6 w-full max-w-md mx-auto p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-left">
                    <div className="flex items-center justify-between mb-2">
                      <label htmlFor="gateway-mode-select" className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-blue-600" />
                        <span>Analysis Mode</span>
                      </label>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                        selectedGatewayId
                          ? 'bg-blue-50 text-blue-700 border-blue-200'
                          : 'bg-slate-100 text-slate-500 border-slate-200'
                      }`}>
                        {selectedGatewayId ? 'MODE 3: COMBINED' : 'MODE 1: PCAP ONLY'}
                      </span>
                    </div>
                    <select
                      id="gateway-mode-select"
                      value={selectedGatewayId}
                      onChange={(e) => setSelectedGatewayId(e.target.value)}
                      className="w-full text-xs font-mono bg-white border border-slate-300 rounded-lg px-3 py-2 text-slate-800 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
                    >
                      <option value="">No Gateway (Mode 1 — PCAP Analysis Only)</option>
                      {availableGateways.map((gw) => (
                        <option key={gw.gateway_id} value={gw.gateway_id}>
                          {gw.display_name} [{gw.status}] — Mode 3 Correlation
                        </option>
                      ))}
                    </select>
                    <p className="text-[11px] text-slate-500 mt-1.5">
                      {selectedGatewayId
                        ? '✓ Exact SPI correlation will match packet ESP headers against this gateway\'s SA telemetry.'
                        : 'Analyzes cryptographic handshakes and encrypted traffic directly from PCAP packets without gateway telemetry.'}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center justify-center gap-2.5">
                    <label
                      htmlFor="dropzone-file"
                      className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm cursor-pointer transition-colors flex items-center gap-2"
                    >
                      <FileCheck className="w-3.5 h-3.5" />
                      <span>{selectedGatewayId ? 'Select .PCAP & Correlate' : 'Select .PCAP File'}</span>
                      <input
                        id="dropzone-file"
                        type="file"
                        accept=".pcap,.pcapng,.cap"
                        onChange={handleFileUpload}
                        className="hidden"
                      />
                    </label>

                    <button
                      onClick={() => setIsTestbedOpen(true)}
                      className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 cursor-pointer shadow-sm"
                    >
                      <Sliders className="w-3.5 h-3.5 text-slate-500" />
                      <span>Generate Testbed Capture</span>
                    </button>

                    <button
                      onClick={() => setCurrentView('GATEWAYS')}
                      className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 cursor-pointer shadow-sm"
                    >
                      <Shield className="w-3.5 h-3.5 text-slate-500" />
                      <span>Manage Gateways</span>
                    </button>
                  </div>

                  <div className="mt-4 text-[11px] text-slate-400">
                    Supported: Standard Libpcap (.pcap), tcpdump, Wireshark, pcapng
                  </div>
                </div>

                {/* Capture Command Reference */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                  {/* Linux tcpdump */}
                  <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-slate-800 text-xs font-semibold">
                        <Terminal className="w-3.5 h-3.5 text-slate-500" />
                        <span>Capture on Linux (tcpdump)</span>
                      </div>
                      <button
                        onClick={handleCopyTcpdump}
                        className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-700 px-2 py-1 rounded bg-slate-100 border border-slate-200 cursor-pointer"
                      >
                        {copiedCmd ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      Run as root on your VPN gateway to capture IKE and ESP traffic:
                    </p>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-700 font-mono text-[11px] text-emerald-400 break-all select-all">
                      sudo tcpdump -i any -nn -s 0 -w ipsec_capture.pcap "udp port 500 or udp port 4500 or proto 50"
                    </div>
                  </div>

                  {/* Wireshark */}
                  <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs space-y-2">
                    <div className="flex items-center gap-2 text-slate-800 text-xs font-semibold">
                      <Code2 className="w-3.5 h-3.5 text-slate-500" />
                      <span>Capture in Wireshark</span>
                    </div>
                    <div className="space-y-1.5 text-[11px] text-slate-500 leading-relaxed">
                      <p>1. Set the capture filter to: <code className="text-blue-600 bg-slate-100 px-1 py-0.5 rounded font-mono">udp port 500 or udp port 4500 or esp</code></p>
                      <p>2. Establish the IPsec connection and generate traffic over the tunnel.</p>
                      <p>3. Save capture as <code className="text-amber-600 bg-slate-100 px-1 py-0.5 rounded font-mono">.pcap</code> and drag it into the dropzone above.</p>
                    </div>
                  </div>

                </div>

              </div>
            ) : (
              /* When a capture file is loaded — full live inspection interface */
              <>
                {/* Active Context Banner */}
                <div className="bg-white border border-slate-200 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-xs">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-mono uppercase">
                        {selectedScenario.badge}
                      </span>
                      <h2 className="text-sm font-semibold text-slate-900">
                        {selectedScenario.name}
                      </h2>
                      <span className="text-xs text-slate-400">
                        · {selectedScenario.organization}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 leading-relaxed max-w-3xl">
                      {selectedScenario.description}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 flex-wrap">
                    <div className="flex rounded-md border border-slate-200 p-0.5 text-[11px]" aria-label="Analysis detail mode">
                      <button onClick={() => setTechnicalMode(false)} className={`rounded px-2 py-1 ${!technicalMode ? 'bg-slate-100 font-semibold text-slate-800' : 'text-slate-500'}`}>Simple</button>
                      <button onClick={() => setTechnicalMode(true)} className={`rounded px-2 py-1 ${technicalMode ? 'bg-slate-100 font-semibold text-slate-800' : 'text-slate-500'}`}>Technical</button>
                    </div>
                    {/* Mode 3 Gateway Switcher for loaded capture */}
                    {availableGateways.length > 0 && (
                      <div className="flex items-center gap-1.5 bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-200 text-xs">
                        <Server className="w-3.5 h-3.5 text-blue-600" />
                        <span className="text-[11px] text-slate-500">Gateway:</span>
                        <select
                          value={selectedGatewayId}
                          onChange={(e) => {
                            const gwId = e.target.value;
                            setSelectedGatewayId(gwId);
                            if (gwId) {
                              correlateLoadedScenario(gwId);
                            }
                          }}
                          className="bg-transparent text-xs font-mono text-slate-700 border-none focus:outline-none cursor-pointer"
                        >
                          <option value="">None (PCAP Only)</option>
                          {availableGateways.map((gw) => (
                            <option key={gw.gateway_id} value={gw.gateway_id}>
                              {gw.display_name} ({gw.status})
                            </option>
                          ))}
                        </select>
                      </div>
                    )}

                    <button
                      id="btn-quick-report"
                      onClick={() => openReport()}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 transition-colors cursor-pointer shadow-xs"
                    >
                      <FileText className="w-3.5 h-3.5 text-blue-600" />
                      <span>View Report</span>
                    </button>
                  </div>
                </div>

                {/* Metric Cards */}
                {scorecard && aiPrediction && (
                  <MetricCards
                    sa={selectedScenario.sa}
                    scorecard={scorecard}
                    aiPrediction={aiPrediction}
                    actualTrafficType={selectedScenario.actualTrafficType}
                  />
                )}

                {scorecard && aiPrediction && (
                  <AssessmentOverview
                    scenario={selectedScenario}
                    scorecard={scorecard}
                    prediction={aiPrediction}
                    onOpenReport={() => openReport()}
                  />
                )}

                <CaptureProfile sa={selectedScenario.sa} technical={technicalMode} />

                {/* Analysis Navigation Tabs */}
                <div className="flex items-center justify-between border-b border-slate-200 pb-0">
                  <div className="flex items-center gap-0">
                    {[
                      { key: 'SECURITY' as const, label: 'Security Assessment', icon: ShieldAlert },
                      { key: 'AI_TRAFFIC' as const, label: 'AI Traffic Analysis', icon: Cpu },
                      { key: 'PACKETS' as const, label: `Packets (${selectedScenario.packets.length})`, icon: Terminal },
                    ].map(({ key, label, icon: Icon }) => (
                      <button
                        key={key}
                        id={`tab-btn-${key.toLowerCase()}`}
                        onClick={() => setActiveTab(key)}
                        className={`inline-flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors cursor-pointer -mb-px ${
                          activeTab === key
                            ? 'border-blue-600 text-blue-600 bg-white'
                            : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
                        }`}
                      >
                        <Icon className="w-3.5 h-3.5" />
                        <span>{label}</span>
                      </button>
                    ))}
                  </div>

                  <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-400 pb-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                    <span>Live Analysis Active</span>
                  </div>
                </div>

                {/* Tab Content */}
                <div className="pt-1">
                  {activeTab === 'SECURITY' && scorecard && (
                    <SecurityAssessment
                      scorecard={scorecard}
                      sa={selectedScenario.sa}
                      gatewayTelemetry={selectedScenario.gatewayTelemetry}
                      correlation={selectedScenario.correlation}
                      mlSecurityFindings={selectedScenario.mlSecurityFindings}
                    />
                  )}

                  {activeTab === 'AI_TRAFFIC' && aiPrediction && (
                    <AiTrafficAnalysis
                      features={selectedScenario.features}
                      prediction={aiPrediction}
                      mlPredictions={selectedScenario.mlPredictions}
                      mlWarning={selectedScenario.mlWarning}
                    />
                  )}

                  {activeTab === 'PACKETS' && (
                    <PacketViewer packets={selectedScenario.packets} />
                  )}
                </div>
              </>
            )}
          </>
        )}

      </main>

      <PipelineStepper active={isAnalyzing} stage={analysisStage} />
      <CommandPalette open={isCommandOpen} onClose={() => setIsCommandOpen(false)} onAction={handleCommand} />
      <StatusDrawer open={isStatusOpen} onClose={() => setIsStatusOpen(false)} />

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-3 px-6">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-400">
          <div>
            Smart India Hackathon 2026 · Problem Statement 26160
          </div>
          <div>
            Target Organization: <span className="font-medium text-slate-500">National Technical Research Organisation (NTRO)</span>
          </div>
        </div>
      </footer>

      {/* Modals */}
      <Suspense fallback={null}>
        {selectedScenario && scorecard && aiPrediction && (
          <ReportModal
            isOpen={isReportOpen}
            onClose={() => setIsReportOpen(false)}
            scenario={selectedScenario}
            scorecard={scorecard}
            prediction={aiPrediction}
            initialKind={requestedReportKind}
          />
        )}
      </Suspense>

      <Suspense fallback={null}>
        <TestbedGeneratorModal
          isOpen={isTestbedOpen}
          onClose={() => setIsTestbedOpen(false)}
          onLoadCustomScenario={handleLoadCustomScenario}
          gateways={availableGateways}
        />
      </Suspense>

      <GatewayDetailsModal
        gatewayId={selectedDetailGatewayId}
        isOpen={!!selectedDetailGatewayId}
        onClose={() => setSelectedDetailGatewayId(null)}
        onGatewayUpdated={refreshGatewayCount}
        onGatewayRemoved={refreshGatewayCount}
      />

      <Suspense fallback={null}>
        {selectedReportGatewayId && <GatewayReportModal
          isOpen
          onClose={() => setSelectedReportGatewayId(null)}
          gatewayId={selectedReportGatewayId}
        />}
      </Suspense>

      <AddGatewayModal
        isOpen={isAddGatewayOpen}
        onClose={() => setIsAddGatewayOpen(false)}
        onGatewayAdded={() => {
          refreshGatewayCount();
          showToast('Gateway enrolled successfully.');
        }}
        onViewGateway={(id) => {
          setSelectedDetailGatewayId(id);
        }}
      />

    </div>
  );
}
