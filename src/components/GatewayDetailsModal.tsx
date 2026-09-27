import React, { useState, useEffect } from 'react';
import {
  X,
  Server,
  Wifi,
  Shield,
  Activity,
  AlertTriangle,
  Clock,
  RefreshCw,
  Trash2,
  Ban,
  Key,
  CheckCircle2,
  Copy,
  Check,
  Cpu,
} from 'lucide-react';
import type { GatewaySummary, GatewayTelemetryRecord } from '../types';
import {
  fetchGateway,
  regenerateEnrollmentToken,
  revokeGateway,
  removeGateway,
  getEnrollCommand,
} from '../utils/gatewayClient';
import { getApiBaseUrl } from '../utils/scapyClient';
const GatewayReportModal = React.lazy(() => import('./GatewayReportModal').then(module => ({ default: module.GatewayReportModal })));

interface GatewayDetailsModalProps {
  gatewayId: string | null;
  isOpen: boolean;
  onClose: () => void;
  onGatewayUpdated: () => void;
  onGatewayRemoved: () => void;
}

export const GatewayDetailsModal: React.FC<GatewayDetailsModalProps> = ({
  gatewayId,
  isOpen,
  onClose,
  onGatewayUpdated,
  onGatewayRemoved,
}) => {
  const [gateway, setGateway] = useState<GatewaySummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [regenToken, setRegenToken] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedEnrollCmd, setCopiedEnrollCmd] = useState(false);
  const [isReportOpen, setIsReportOpen] = useState(false);

  const loadDetails = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchGateway(id);
      setGateway(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load gateway details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && gatewayId) {
      setRegenToken(null);
      loadDetails(gatewayId);
    }
  }, [isOpen, gatewayId]);

  if (!isOpen || !gatewayId) return null;

  const handleRegenerateToken = async () => {
    if (!window.confirm('Generate a new one-time enrollment token for this gateway?')) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await regenerateEnrollmentToken(gatewayId);
      setRegenToken(res.enrollment_token);
      onGatewayUpdated();
      await loadDetails(gatewayId);
    } catch (err: any) {
      setError(err?.message || 'Failed to regenerate enrollment token');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRevoke = async () => {
    if (
      !window.confirm(
        `Are you sure you want to REVOKE "${gateway?.display_name || gatewayId}"? The agent token will be permanently invalidated and all new telemetry submissions will be rejected.`,
      )
    ) {
      return;
    }
    setActionLoading(true);
    setError(null);
    try {
      await revokeGateway(gatewayId);
      onGatewayUpdated();
      await loadDetails(gatewayId);
    } catch (err: any) {
      setError(err?.message || 'Failed to revoke gateway');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRemove = async () => {
    if (
      !window.confirm(
        `Are you sure you want to permanently DELETE "${gateway?.display_name || gatewayId}"? All gateway records will be removed.`,
      )
    ) {
      return;
    }
    setActionLoading(true);
    setError(null);
    try {
      await removeGateway(gatewayId);
      onGatewayRemoved();
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Failed to remove gateway');
      setActionLoading(false);
    }
  };

  const copyToClipboard = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'CONNECTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            CONNECTED
          </span>
        );
      case 'STALE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            STALE
          </span>
        );
      case 'OFFLINE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-red-50 text-red-700 border border-red-200">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
            OFFLINE
          </span>
        );
      case 'REVOKED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-purple-50 text-purple-700 border border-purple-200">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-500" />
            REVOKED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
            NEVER CONNECTED
          </span>
        );
    }
  };

  // Find real IKE and Child SA records from latest telemetry
  const latestTelem = gateway?.latest_telemetry;
  const records = latestTelem?.records || [];
  const ikeRecord = records.find(
    (r: any) => r.version || r.initiator_spi || r.responder_spi || r.prf,
  ) as Record<string, any> | undefined;

  const childRecords = records.filter(
    (r: any) => r.protocol === 'ESP' || r.inbound_spi || r.outbound_spi,
  ) as Record<string, any>[];

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-white border border-slate-200 rounded-xl w-full max-w-3xl overflow-hidden shadow-xl my-6">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-white">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200 text-blue-600 flex items-center justify-center">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-sm font-semibold text-slate-900">
                  {gateway?.display_name || 'Gateway Details'}
                </h2>
                {gateway && getStatusBadge(gateway.status)}
              </div>
              <p className="text-xs font-mono text-slate-500 mt-0.5">
                {gatewayId} &bull; {gateway?.telemetry_adapter || 'STRONGSWAN'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsReportOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-xs font-medium transition-colors cursor-pointer shadow-xs"
              title="Generate immutable Mode 2 Gateway Security Report"
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Security Report</span>
            </button>
            <button
              onClick={() => loadDetails(gatewayId)}
              disabled={loading}
              title="Refresh details"
              className="text-slate-400 hover:text-slate-600 p-1.5 rounded-md hover:bg-slate-100 transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-600 p-1.5 rounded-md hover:bg-slate-100 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-500" />
              <span>{error}</span>
            </div>
          )}

          {regenToken && (
            <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900 space-y-2">
              <div className="flex items-center justify-between">
                <strong className="text-slate-900 font-semibold flex items-center gap-1.5">
                  <Key className="w-4 h-4 text-amber-600" />
                  New One-Time Enrollment Token Generated
                </strong>
                <button
                  onClick={() => copyToClipboard(regenToken, setCopiedToken)}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-white border border-slate-300 text-xs text-slate-700 hover:bg-slate-50 cursor-pointer font-medium"
                >
                  {copiedToken ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-500" />}
                  <span>{copiedToken ? 'Copied' : 'Copy Token'}</span>
                </button>
              </div>
              <div className="p-2.5 bg-slate-900 rounded-md font-mono text-xs text-amber-300 break-all select-all">
                {regenToken}
              </div>
              <div className="flex items-center justify-between pt-1">
                <span className="text-xs text-slate-600">Enrollment command:</span>
                <button
                  onClick={() =>
                    copyToClipboard(
                      getEnrollCommand(getApiBaseUrl(), regenToken),
                      setCopiedEnrollCmd,
                    )
                  }
                  className="inline-flex items-center gap-1 text-xs text-blue-600 hover:text-blue-700 font-medium cursor-pointer"
                >
                  {copiedEnrollCmd ? 'Copied command!' : 'Copy enroll command'}
                </button>
              </div>
            </div>
          )}

          {/* Metadata Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
              <div className="text-slate-500 flex items-center gap-1 mb-1 font-medium">
                <Activity className="w-3.5 h-3.5 text-blue-600" />
                <span>Connection</span>
              </div>
              <div className="font-semibold text-slate-900 text-sm">
                {gateway?.status || 'UNKNOWN'}
              </div>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
              <div className="text-slate-500 flex items-center gap-1 mb-1 font-medium">
                <Clock className="w-3.5 h-3.5 text-emerald-600" />
                <span>Last Seen</span>
              </div>
              <div className="font-semibold text-slate-800 truncate">
                {gateway?.last_seen_at || 'Never connected'}
              </div>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
              <div className="text-slate-500 flex items-center gap-1 mb-1 font-medium">
                <Cpu className="w-3.5 h-3.5 text-purple-600" />
                <span>Agent Version</span>
              </div>
              <div className="font-mono font-semibold text-slate-800">
                {gateway?.agent_version || 'Not detected'}
              </div>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
              <div className="text-slate-500 flex items-center gap-1 mb-1 font-medium">
                <Shield className="w-3.5 h-3.5 text-sky-600" />
                <span>Active SAs</span>
              </div>
              <div className="font-semibold text-slate-800">
                {gateway?.active_ike_sa_count || 0} IKE / {gateway?.active_child_sa_count || 0} Child
              </div>
            </div>
          </div>

          {/* Telemetry Status Banner if error */}
          {latestTelem?.error && (
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
              <span>
                <strong>Gateway Reporting Note:</strong> {latestTelem.error} (Status: {latestTelem.status})
              </span>
            </div>
          )}

          {/* StrongSwan Real Telemetry Section */}
          <div className="space-y-4 pt-1">
            <div className="flex items-center justify-between pb-2 border-b border-slate-200">
              <div className="flex items-center gap-2">
                <Wifi className="w-4 h-4 text-emerald-600" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-800">
                  Real StrongSwan SA Telemetry
                </h3>
              </div>
              <div className="text-xs text-slate-500">
                Source: <span className="text-slate-700 font-mono">{latestTelem?.source || 'GATEWAY_TELEMETRY'}</span> | Adapter: <span className="text-slate-700 font-mono">{latestTelem?.adapter || gateway?.telemetry_adapter || 'STRONGSWAN'}</span>
              </div>
            </div>

            {records.length === 0 ? (
              <div className="p-6 bg-slate-50 border border-slate-200 rounded-lg text-center space-y-1">
                <p className="text-xs font-semibold text-slate-700">
                  No active Security Associations reported yet
                </p>
                <p className="text-xs text-slate-500">
                  {gateway?.status === 'NEVER_CONNECTED'
                    ? 'Complete agent enrollment on the StrongSwan gateway to stream live telemetry.'
                    : 'The gateway agent is connected, but StrongSwan currently has no established tunnels.'}
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {/* Active IKE SA */}
                {ikeRecord && (
                  <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-500" />
                        <span className="text-xs font-semibold text-slate-900">
                          IKE Security Association ({ikeRecord.name || 'vpn'})
                        </span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-blue-50 text-blue-700 border border-blue-200">
                        {ikeRecord.version ? `IKEv${ikeRecord.version}` : 'IKEv2'}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs font-mono">
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">State</div>
                        <div className="text-emerald-700 font-bold mt-0.5">{ikeRecord.state || 'ESTABLISHED'}</div>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">Encryption (IKE)</div>
                        <div className="text-slate-800 font-medium truncate mt-0.5">{ikeRecord.encr || 'UNKNOWN'}</div>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">PRF Algorithm</div>
                        <div className="text-slate-800 font-medium truncate mt-0.5">{ikeRecord.prf || 'UNKNOWN'}</div>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">Diffie-Hellman Group</div>
                        <div className="text-slate-800 font-medium truncate mt-0.5">{ikeRecord.dh || 'UNKNOWN'}</div>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">Initiator SPI</div>
                        <div className="text-slate-700 truncate mt-0.5">{ikeRecord.initiator_spi || 'UNKNOWN'}</div>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">Responder SPI</div>
                        <div className="text-slate-700 truncate mt-0.5">{ikeRecord.responder_spi || 'UNKNOWN'}</div>
                      </div>
                    </div>

                    {(ikeRecord.local_host || ikeRecord.remote_host) && (
                      <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                        <span>Endpoints:</span>
                        <span className="font-mono text-slate-700">
                          {ikeRecord.local_host || '?'} ↔ {ikeRecord.remote_host || '?'}
                        </span>
                      </div>
                    )}
                  </div>
                )}

                {/* Child SAs (ESP Tunnels) */}
                {childRecords.map((child, idx) => (
                  <div key={idx} className="bg-white border border-slate-200 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-blue-500" />
                        <span className="text-xs font-semibold text-slate-900">
                          Child SA (IPsec ESP Tunnel #{child.reqid || idx + 1})
                        </span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-100 text-slate-700 border border-slate-200">
                        {child.mode || 'TUNNEL'} • {child.protocol || 'ESP'}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">Inbound SPI (spi-in)</div>
                        <div className="text-emerald-700 font-bold break-all mt-0.5">{child.inbound_spi || child.spi || 'UNKNOWN'}</div>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">Outbound SPI (spi-out)</div>
                        <div className="text-blue-700 font-bold break-all mt-0.5">{child.outbound_spi || 'UNKNOWN'}</div>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">ESP Encryption</div>
                        <div className="text-slate-800 font-medium truncate mt-0.5">{child.encr || 'UNKNOWN'}</div>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-sans">Traffic In / Out</div>
                        <div className="text-slate-700 mt-0.5">
                          {child.bytes_in ?? 0} B / {child.bytes_out ?? 0} B
                        </div>
                      </div>
                    </div>

                    {(child.local_ts || child.remote_ts) && (
                      <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                        <span>Traffic Selectors:</span>
                        <span className="font-mono text-slate-700">
                          {child.local_ts || '?'} → {child.remote_ts || '?'}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Evidence details */}
          {latestTelem?.evidence && latestTelem.evidence.length > 0 && (
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1">
              <span className="text-slate-700 font-medium">Gateway Audit Evidence:</span>
              <ul className="list-disc list-inside text-slate-600 text-xs space-y-0.5">
                {latestTelem.evidence.map((evi, i) => (
                  <li key={i}>{evi}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Actions Footer */}
          <div className="pt-4 border-t border-slate-200 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setIsReportOpen(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded-md text-xs font-medium transition-colors cursor-pointer"
              >
                <Shield className="w-3.5 h-3.5 text-blue-600" />
                <span>Security Report</span>
              </button>

              <button
                type="button"
                onClick={handleRegenerateToken}
                disabled={actionLoading || gateway?.status === 'REVOKED'}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 disabled:opacity-50 text-slate-700 border border-slate-300 rounded-md text-xs font-medium transition-colors cursor-pointer"
              >
                <Key className="w-3.5 h-3.5 text-amber-600" />
                <span>Regenerate Enrollment Token</span>
              </button>

              {gateway?.status !== 'REVOKED' && (
                <button
                  type="button"
                  onClick={handleRevoke}
                  disabled={actionLoading}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-red-50 text-red-600 border border-red-200 rounded-md text-xs font-medium transition-colors cursor-pointer"
                >
                  <Ban className="w-3.5 h-3.5 text-red-500" />
                  <span>Revoke Gateway</span>
                </button>
              )}
            </div>

            <button
              type="button"
              onClick={handleRemove}
              disabled={actionLoading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-red-50 text-slate-500 hover:text-red-600 border border-slate-200 hover:border-red-200 rounded-md text-xs font-medium transition-colors cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Remove Gateway</span>
            </button>
          </div>
        </div>
      </div>

      <React.Suspense fallback={null}>
        {isReportOpen && <GatewayReportModal
          isOpen
          onClose={() => setIsReportOpen(false)}
          gatewayId={gatewayId}
          gatewayName={gateway?.display_name}
        />}
      </React.Suspense>
    </div>
  );
};
