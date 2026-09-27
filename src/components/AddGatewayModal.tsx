import React, { useState, useEffect } from 'react';
import {
  X,
  Server,
  Download,
  Terminal,
  CheckCircle2,
  Copy,
  Check,
  AlertTriangle,
  Loader2,
  ExternalLink,
  Shield,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import type { GatewayEnrollmentResult, GatewaySummary } from '../types';
import {
  createGateway,
  fetchGateway,
  getDownloadUrl,
  getEnrollCommand,
  getInstallCommand,
  getStartCommand,
} from '../utils/gatewayClient';
import { getApiBaseUrl } from '../utils/scapyClient';

interface AddGatewayModalProps {
  isOpen: boolean;
  onClose: () => void;
  onGatewayAdded: (gateway: GatewaySummary) => void;
  onViewGateway: (gatewayId: string) => void;
}

export const AddGatewayModal: React.FC<AddGatewayModalProps> = ({
  isOpen,
  onClose,
  onGatewayAdded,
  onViewGateway,
}) => {
  const [step, setStep] = useState<1 | 2 | 3 | 4 | 5>(1);
  const [displayName, setDisplayName] = useState('');
  const [gatewayType, setGatewayType] = useState('STRONGSWAN');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [enrollmentResult, setEnrollmentResult] = useState<GatewayEnrollmentResult | null>(null);
  const [connectedGateway, setConnectedGateway] = useState<GatewaySummary | null>(null);

  const [copiedInstall, setCopiedInstall] = useState(false);
  const [copiedEnroll, setCopiedEnroll] = useState(false);
  const [copiedStart, setCopiedStart] = useState(false);
  const [copiedToken, setCopiedToken] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setStep(1);
      setDisplayName('');
      setGatewayType('STRONGSWAN');
      setError(null);
      setEnrollmentResult(null);
      setConnectedGateway(null);
    }
  }, [isOpen]);

  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    let cancelled = false;

    if (step === 4 && enrollmentResult) {
      const poll = async () => {
        try {
          const gw = await fetchGateway(enrollmentResult.gateway_id);
          if (cancelled) return;
          if (gw && (gw.status === 'CONNECTED' || gw.status === 'STALE')) {
            setConnectedGateway(gw);
            onGatewayAdded(gw);
            setStep(5);
            return;
          }
        } catch (e) {
          console.warn('Polling gateway connection:', e);
        }
        if (!cancelled) {
          timer = setTimeout(poll, 2000);
        }
      };
      poll();
    }

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [step, enrollmentResult, onGatewayAdded]);

  if (!isOpen) return null;

  const serverUrl = enrollmentResult?.server_url || getApiBaseUrl();

  const handleCreateGateway = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!displayName.trim()) {
      setError('Please provide a gateway name');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await createGateway(displayName.trim(), gatewayType);
      setEnrollmentResult(res);
      setStep(2);
    } catch (err: any) {
      setError(err?.message || 'Failed to register gateway');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const installCmd = getInstallCommand(serverUrl);
  const enrollCmd = enrollmentResult ? getEnrollCommand(serverUrl, enrollmentResult.enrollment_token) : '';
  const startCmd = getStartCommand();
  const downloadUrl = getDownloadUrl(serverUrl);

  const steps = [
    { id: 1, label: 'Details' },
    { id: 2, label: 'Install' },
    { id: 3, label: 'Enroll' },
    { id: 4, label: 'Connect' },
    { id: 5, label: 'Done' },
  ];

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-white border border-slate-200 rounded-xl w-full max-w-2xl overflow-hidden shadow-xl">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 text-blue-600 flex items-center justify-center">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900">Add VPN Gateway</h2>
              <p className="text-xs text-slate-500">Register a Linux StrongSwan / IPsec gateway agent</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 p-1 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Stepper */}
        <div className="px-5 py-3 border-b border-slate-200 bg-slate-50">
          <div className="flex items-center gap-0">
            {steps.map((s, idx) => (
              <React.Fragment key={s.id}>
                <div className={`flex items-center gap-1.5 text-xs font-medium ${
                  step === s.id ? 'text-blue-600' : step > s.id ? 'text-emerald-600' : 'text-slate-400'
                }`}>
                  <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                    step === s.id ? 'bg-blue-600 text-white' :
                    step > s.id ? 'bg-emerald-500 text-white' :
                    'bg-slate-200 text-slate-500'
                  }`}>
                    {step > s.id ? '✓' : s.id}
                  </span>
                  <span className="hidden sm:inline">{s.label}</span>
                </div>
                {idx < steps.length - 1 && (
                  <div className="flex-1 h-px bg-slate-200 mx-2 min-w-4" />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Body */}
        <div className="p-5">
          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-500" />
              <span>{error}</span>
            </div>
          )}

          {/* STEP 1 */}
          {step === 1 && (
            <form onSubmit={handleCreateGateway} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Gateway Display Name *
                </label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="e.g. Production StrongSwan VPN — HQ"
                  className="w-full px-3 py-2.5 bg-white border border-slate-300 rounded-lg text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  autoFocus
                />
                <p className="mt-1 text-[11px] text-slate-400">
                  A human-readable label to identify this gateway in analysis and reports.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Telemetry Adapter
                </label>
                <select
                  value={gatewayType}
                  onChange={(e) => setGatewayType(e.target.value)}
                  className="w-full px-3 py-2.5 bg-white border border-slate-300 rounded-lg text-xs text-slate-800 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                >
                  <option value="STRONGSWAN">StrongSwan (swanctl CLI)</option>
                  <option value="STRONGSWAN_VICI">StrongSwan VICI (charon.vici socket)</option>
                </select>
                <p className="mt-1 text-[11px] text-slate-400">
                  Select how the gateway agent should query SA metadata on the gateway host.
                </p>
              </div>

              <div className="pt-3 border-t border-slate-200 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-600 text-xs font-medium rounded-lg border border-slate-300 transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !displayName.trim()}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center gap-2 shadow-sm transition-colors cursor-pointer"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Generating...</span>
                    </>
                  ) : (
                    <>
                      <span>Next: Install Agent</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </div>
            </form>
          )}

          {/* STEP 2 */}
          {step === 2 && enrollmentResult && (
            <div className="space-y-4">
              <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-xs">
                <p className="font-semibold text-blue-800">{enrollmentResult.display_name}</p>
                <p className="font-mono text-blue-600 text-[11px] mt-0.5">{enrollmentResult.gateway_id}</p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                    <Download className="w-3.5 h-3.5 text-slate-400" />
                    Option A: One-Line Installer (Recommended)
                  </span>
                  <button
                    onClick={() => copyToClipboard(installCmd, setCopiedInstall)}
                    className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-700 px-2 py-1 rounded bg-slate-100 border border-slate-200 cursor-pointer"
                  >
                    {copiedInstall ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedInstall ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <p className="text-[11px] text-slate-500">
                  Run as root on your Linux StrongSwan host:
                </p>
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-700 font-mono text-[11px] text-emerald-400 break-all select-all">
                  {installCmd}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-slate-400" />
                    Option B: Download Agent Package
                  </span>
                  <a
                    href={downloadUrl}
                    download="vpn-analyzer-agent.tar.gz"
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-white hover:bg-slate-50 text-slate-600 border border-slate-300 rounded text-[11px] font-medium transition-colors cursor-pointer"
                  >
                    <Download className="w-3 h-3 text-blue-600" />
                    Download Linux Agent (.tar.gz)
                  </a>
                </div>
                <p className="text-[11px] text-slate-500">
                  Extract to <code className="font-mono bg-slate-100 px-1 rounded">/opt/vpn-analyzer-agent</code> and run with Python 3.
                </p>
              </div>

              <div className="pt-3 border-t border-slate-200 flex justify-between items-center">
                <button type="button" onClick={() => setStep(1)} className="text-slate-500 hover:text-slate-700 text-xs cursor-pointer">
                  ← Back
                </button>
                <button
                  type="button"
                  onClick={() => setStep(3)}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg flex items-center gap-2 shadow-sm transition-colors cursor-pointer"
                >
                  <span>Next: Enroll</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* STEP 3 */}
          {step === 3 && enrollmentResult && (
            <div className="space-y-4">
              <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs flex items-start gap-2.5">
                <Shield className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-amber-800">One-Time Enrollment Credential</strong>
                  <p className="text-amber-700 text-[11px] mt-0.5">
                    Single-use, expires in 60 minutes. The agent exchanges it for a runtime credential. Not shown again.
                  </p>
                </div>
              </div>

              {[
                {
                  label: 'One-Time Token',
                  value: enrollmentResult.enrollment_token,
                  copied: copiedToken,
                  setCopied: setCopiedToken,
                  color: 'text-amber-600',
                },
                {
                  label: '1. Run Enrollment Command',
                  value: enrollCmd,
                  copied: copiedEnroll,
                  setCopied: setCopiedEnroll,
                  color: 'text-emerald-400',
                },
                {
                  label: '2. Start Telemetry Service',
                  value: startCmd,
                  copied: copiedStart,
                  setCopied: setCopiedStart,
                  color: 'text-slate-300',
                },
              ].map(({ label, value, copied, setCopied, color }) => (
                <div key={label}>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-semibold text-slate-700">{label}</label>
                    <button
                      onClick={() => copyToClipboard(value, setCopied)}
                      className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-700 px-2 py-0.5 rounded bg-slate-100 border border-slate-200 cursor-pointer"
                    >
                      {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className={`p-2.5 bg-slate-900 rounded-lg border border-slate-700 font-mono text-[11px] ${color} break-all select-all`}>
                    {value}
                  </div>
                </div>
              ))}

              <div className="pt-3 border-t border-slate-200 flex justify-between items-center">
                <button type="button" onClick={() => setStep(2)} className="text-slate-500 hover:text-slate-700 text-xs cursor-pointer">
                  ← Back
                </button>
                <button
                  type="button"
                  onClick={() => setStep(4)}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg flex items-center gap-2 shadow-sm transition-colors cursor-pointer"
                >
                  <span>Waiting for Connection</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* STEP 4 */}
          {step === 4 && enrollmentResult && (
            <div className="py-8 text-center space-y-4">
              <div className="relative w-14 h-14 mx-auto flex items-center justify-center">
                <div className="absolute inset-0 rounded-full bg-blue-100 animate-ping opacity-60" />
                <div className="w-11 h-11 rounded-full bg-blue-600 text-white flex items-center justify-center shadow-md">
                  <RefreshCw className="w-5 h-5 animate-spin" />
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-slate-900">Waiting for Gateway Connection...</h3>
                <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
                  Listening for authenticated communication from gateway{' '}
                  <span className="font-mono text-slate-700 font-semibold">{enrollmentResult.gateway_id}</span>.
                </p>
              </div>

              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg max-w-md mx-auto text-left space-y-1.5 text-xs">
                <div className="flex items-center justify-between text-slate-500">
                  <span>Server</span>
                  <span className="font-mono text-slate-700">{serverUrl}</span>
                </div>
                <div className="flex items-center justify-between text-slate-500">
                  <span>Status</span>
                  <span className="text-amber-600 font-semibold">Listening for initial ping...</span>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setStep(3)}
                className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-600 text-xs font-medium rounded-lg border border-slate-300 cursor-pointer"
              >
                View Commands Again
              </button>
            </div>
          )}

          {/* STEP 5 */}
          {step === 5 && connectedGateway && (
            <div className="py-6 text-center space-y-4">
              <div className="w-14 h-14 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-500 mx-auto flex items-center justify-center shadow-sm">
                <CheckCircle2 className="w-7 h-7" />
              </div>

              <div>
                <h3 className="text-base font-semibold text-slate-900">Gateway Connected!</h3>
                <p className="text-xs text-slate-500 mt-1">
                  Authenticated agent communication verified. Real StrongSwan telemetry is now available.
                </p>
              </div>

              <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg max-w-md mx-auto text-left space-y-2 text-xs">
                {[
                  { label: 'Gateway', value: connectedGateway.display_name },
                  { label: 'ID', value: connectedGateway.gateway_id, mono: true },
                  { label: 'Agent Version', value: connectedGateway.agent_version || '1.x', mono: true },
                  { label: 'Last Telemetry', value: connectedGateway.last_seen_at || 'Just now', mono: true },
                ].map(({ label, value, mono }) => (
                  <div key={label} className="flex items-center justify-between border-b border-slate-200 pb-1.5 last:border-0 last:pb-0">
                    <span className="text-slate-500">{label}</span>
                    <span className={`font-semibold text-slate-800 ${mono ? 'font-mono' : ''}`}>{value}</span>
                  </div>
                ))}
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Connection</span>
                  <span className="text-emerald-600 font-bold flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    CONNECTED
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-center gap-2">
                <button
                  type="button"
                  onClick={() => { onClose(); onViewGateway(connectedGateway.gateway_id); }}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg flex items-center gap-2 shadow-sm transition-colors cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  View Gateway Details
                </button>
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-600 text-xs font-medium rounded-lg border border-slate-300 cursor-pointer"
                >
                  Done
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
