import React, { useState, useEffect } from 'react';
import {
  Server,
  Plus,
  RefreshCw,
  Wifi,
  Clock,
  Key,
  Ban,
  Trash2,
  Shield,
  AlertTriangle,
  Check,
  Copy,
  X,
} from 'lucide-react';
import type { GatewaySummary } from '../types';
import {
  fetchGateways,
  regenerateEnrollmentToken,
  revokeGateway,
  removeGateway,
  getEnrollCommand,
} from '../utils/gatewayClient';
import { getApiBaseUrl } from '../utils/scapyClient';
import { AddGatewayModal } from './AddGatewayModal';
import { GatewayDetailsModal } from './GatewayDetailsModal';
const GatewayReportModal = React.lazy(() => import('./GatewayReportModal').then(module => ({ default: module.GatewayReportModal })));

interface GatewaysManagerProps {
  onSelectGatewayForAnalysis?: (gatewayId: string) => void;
  onShowToast?: (msg: string) => void;
}

export const GatewaysManager: React.FC<GatewaysManagerProps> = ({
  onSelectGatewayForAnalysis,
  onShowToast,
}) => {
  const [gateways, setGateways] = useState<GatewaySummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedDetailsId, setSelectedDetailsId] = useState<string | null>(null);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);

  const [quickToken, setQuickToken] = useState<{ id: string; token: string } | null>(null);
  const [copiedQuick, setCopiedQuick] = useState(false);

  const loadGateways = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchGateways();
      setGateways(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load gateways');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGateways();
    const interval = setInterval(loadGateways, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleRegenToken = async (id: string, name: string) => {
    if (!window.confirm(`Generate a new one-time enrollment token for "${name}"?`)) return;
    try {
      const res = await regenerateEnrollmentToken(id);
      setQuickToken({ id, token: res.enrollment_token });
      await loadGateways();
    } catch (err: any) {
      alert(`Error: ${err?.message || 'Failed to regenerate token'}`);
    }
  };

  const handleRevoke = async (id: string, name: string) => {
    if (!window.confirm(`Revoke gateway "${name}"? The agent will no longer be authorized.`)) return;
    try {
      await revokeGateway(id);
      await loadGateways();
    } catch (err: any) {
      alert(`Error: ${err?.message || 'Failed to revoke gateway'}`);
    }
  };

  const handleRemove = async (id: string, name: string) => {
    if (!window.confirm(`Permanently delete gateway "${name}"?`)) return;
    try {
      await removeGateway(id);
      await loadGateways();
    } catch (err: any) {
      alert(`Error: ${err?.message || 'Failed to remove gateway'}`);
    }
  };

  const getStatusBadge = (status: string) => {
    const base = 'inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border';
    switch (status) {
      case 'CONNECTED':
        return (
          <span className={`${base} bg-emerald-50 text-emerald-700 border-emerald-200`}>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            CONNECTED
          </span>
        );
      case 'STALE':
        return (
          <span className={`${base} bg-amber-50 text-amber-700 border-amber-200`}>
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            STALE
          </span>
        );
      case 'OFFLINE':
        return (
          <span className={`${base} bg-red-50 text-red-700 border-red-200`}>
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
            OFFLINE
          </span>
        );
      case 'REVOKED':
        return (
          <span className={`${base} bg-slate-100 text-slate-600 border-slate-200`}>
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
            REVOKED
          </span>
        );
      default:
        return (
          <span className={`${base} bg-slate-100 text-slate-500 border-slate-200`}>
            <span className="w-1.5 h-1.5 rounded-full bg-slate-300" />
            NEVER CONNECTED
          </span>
        );
    }
  };

  const totalCount = gateways.length;
  const connectedCount = gateways.filter((g) => g.status === 'CONNECTED').length;
  const staleCount = gateways.filter((g) => g.status === 'STALE' || g.status === 'OFFLINE').length;
  const revokedCount = gateways.filter((g) => g.status === 'REVOKED').length;

  return (
    <div className="space-y-5">

      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-500" />
            Gateway Management
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Register and monitor StrongSwan VPN gateways for SPI telemetry correlation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadGateways}
            disabled={loading}
            title="Refresh gateways list"
            className="p-1.5 bg-white hover:bg-slate-50 text-slate-500 rounded-lg border border-slate-200 transition-colors cursor-pointer shadow-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 shadow-sm transition-colors cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Gateway</span>
          </button>
        </div>
      </div>

      {/* Quick Token Banner */}
      {quickToken && (
        <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <strong className="text-amber-800 flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5" />
              New Token for {quickToken.id}:
            </strong>
            <span className="font-mono text-amber-700 font-semibold block mt-0.5">
              {quickToken.token}
            </span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => {
                navigator.clipboard.writeText(getEnrollCommand(getApiBaseUrl(), quickToken.token));
                setCopiedQuick(true);
                setTimeout(() => setCopiedQuick(false), 2000);
              }}
              className="inline-flex items-center gap-1 px-2.5 py-1 bg-white hover:bg-amber-100 text-amber-700 rounded border border-amber-200 cursor-pointer text-[11px]"
            >
              {copiedQuick ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
              <span>{copiedQuick ? 'Copied!' : 'Copy Command'}</span>
            </button>
            <button onClick={() => setQuickToken(null)} className="text-amber-500 hover:text-amber-700 p-0.5">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Summary Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Gateways', value: totalCount, icon: Server, color: 'text-slate-600' },
          { label: 'Connected', value: connectedCount, icon: Wifi, color: 'text-emerald-600' },
          { label: 'Stale / Offline', value: staleCount, icon: Clock, color: 'text-amber-600' },
          { label: 'Revoked', value: revokedCount, icon: Ban, color: 'text-slate-500' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-white border border-slate-200 rounded-lg p-3.5 shadow-xs">
            <div className="flex items-center gap-1.5 text-xs text-slate-500 mb-1">
              <Icon className={`w-3.5 h-3.5 ${color}`} />
              <span>{label}</span>
            </div>
            <div className={`text-xl font-bold ${color}`}>{value}</div>
          </div>
        ))}
      </div>

      {/* Main Table */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-800 flex items-center gap-2">
            Registered Gateways
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">
              {gateways.length}
            </span>
          </h3>
          <span className="text-[11px] text-slate-400 hidden sm:inline">
            Auto-refreshes every 10 seconds
          </span>
        </div>

        {error && (
          <div className="p-3 bg-red-50 border-b border-red-200 text-red-700 text-xs flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {gateways.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <div className="w-12 h-12 rounded-lg bg-slate-100 border border-slate-200 text-slate-400 mx-auto flex items-center justify-center">
              <Server className="w-6 h-6" />
            </div>
            <div>
              <h4 className="text-sm font-semibold text-slate-700">No Gateways Registered</h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
                Add your Linux StrongSwan gateway to obtain a one-time enrollment token and deploy the telemetry agent.
              </p>
            </div>
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg inline-flex items-center gap-1.5 shadow-sm transition-colors cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Gateway
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs table-compact">
              <thead>
                <tr>
                  <th>Gateway</th>
                  <th>Adapter</th>
                  <th>Status</th>
                  <th>Active SAs</th>
                  <th>Last Seen</th>
                  <th>Agent Ver</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {gateways.map((gw) => (
                  <tr key={gw.gateway_id} className="hover:bg-slate-50 transition-colors">
                    <td>
                      <button
                        onClick={() => setSelectedDetailsId(gw.gateway_id)}
                        className="font-medium text-blue-600 hover:text-blue-800 text-left cursor-pointer"
                      >
                        {gw.display_name}
                      </button>
                      <div className="font-mono text-[10px] text-slate-400">
                        {gw.gateway_id}
                      </div>
                    </td>

                    <td>
                      <span className="font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200 text-[10px]">
                        {gw.telemetry_adapter || gw.gateway_type}
                      </span>
                    </td>

                    <td>
                      {getStatusBadge(gw.status)}
                      {gw.last_error && (
                        <span className="block text-[10px] text-amber-600 truncate max-w-[150px] mt-0.5" title={gw.last_error}>
                          ⚠ {gw.last_error}
                        </span>
                      )}
                    </td>

                    <td className="font-mono text-slate-700">
                      {gw.active_ike_sa_count || 0} IKE / {gw.active_child_sa_count || 0} Child
                    </td>

                    <td className="text-slate-600">
                      {gw.last_seen_at || <span className="text-slate-400 italic">Never</span>}
                    </td>

                    <td className="font-mono text-slate-500">
                      {gw.agent_version || '—'}
                    </td>

                    <td className="text-right">
                      <div className="inline-flex items-center gap-1">
                        <button
                          onClick={() => setSelectedReportId(gw.gateway_id)}
                          title="Generate Gateway Report"
                          className="px-2 py-1 bg-blue-50 hover:bg-blue-100 text-blue-600 border border-blue-200 rounded text-[10px] font-medium transition-colors cursor-pointer flex items-center gap-1"
                        >
                          <Shield className="w-3 h-3" />
                          Report
                        </button>

                        <button
                          onClick={() => setSelectedDetailsId(gw.gateway_id)}
                          title="View Gateway Details"
                          className="px-2 py-1 bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-200 rounded text-[10px] font-medium transition-colors cursor-pointer"
                        >
                          View
                        </button>

                        <button
                          onClick={() => handleRegenToken(gw.gateway_id, gw.display_name)}
                          disabled={gw.status === 'REVOKED'}
                          title="Regenerate enrollment token"
                          className="p-1 text-slate-400 hover:text-amber-600 rounded hover:bg-amber-50 disabled:opacity-30 cursor-pointer"
                        >
                          <Key className="w-3 h-3" />
                        </button>

                        {gw.status !== 'REVOKED' && (
                          <button
                            onClick={() => handleRevoke(gw.gateway_id, gw.display_name)}
                            title="Revoke Gateway"
                            className="p-1 text-slate-400 hover:text-red-600 rounded hover:bg-red-50 cursor-pointer"
                          >
                            <Ban className="w-3 h-3" />
                          </button>
                        )}

                        <button
                          onClick={() => handleRemove(gw.gateway_id, gw.display_name)}
                          title="Remove Gateway"
                          className="p-1 text-slate-400 hover:text-red-600 rounded hover:bg-red-50 cursor-pointer"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modals */}
      <AddGatewayModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onGatewayAdded={(gw) => {
          loadGateways();
          if (onShowToast) onShowToast(`Gateway "${gw.display_name}" registered successfully!`);
        }}
        onViewGateway={(id) => {
          setSelectedDetailsId(id);
          loadGateways();
        }}
      />

      <GatewayDetailsModal
        gatewayId={selectedDetailsId}
        isOpen={!!selectedDetailsId}
        onClose={() => setSelectedDetailsId(null)}
        onGatewayUpdated={() => loadGateways()}
        onGatewayRemoved={() => loadGateways()}
      />

      <React.Suspense fallback={null}>
        {selectedReportId && <GatewayReportModal
          gatewayId={selectedReportId}
          isOpen
          onClose={() => setSelectedReportId(null)}
          gatewayName={gateways.find((g) => g.gateway_id === selectedReportId)?.display_name}
        />}
      </React.Suspense>
    </div>
  );
};
