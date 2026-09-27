import React from 'react';
import {
  Server,
  FileCode,
  FileText,
  Activity,
  Plus,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  Clock,
  Layers,
} from 'lucide-react';
import { GatewaySummary, VpnCaptureScenario } from '../types';

interface DashboardViewProps {
  gateways: GatewaySummary[];
  scenarios: VpnCaptureScenario[];
  onNavigateToAnalysis: () => void;
  onNavigateToGateways: () => void;
  onNavigateToReports: () => void;
  onSelectScenario: (scenario: VpnCaptureScenario) => void;
  onAddGateway: () => void;
  onViewGateway: (gatewayId: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  gateways,
  scenarios,
  onNavigateToAnalysis,
  onNavigateToGateways,
  onNavigateToReports,
  onSelectScenario,
  onAddGateway,
  onViewGateway,
}) => {
  const connectedCount = gateways.filter((g) => g.status === 'CONNECTED').length;
  const staleCount = gateways.filter((g) => g.status === 'STALE').length;

  // Derive recent activity from real scenarios & real gateways
  const activities = [
    ...scenarios.map((s) => ({
      id: s.id,
      time: s.features ? 'Recent' : 'Saved',
      activity: 'PCAP Analysis',
      source: s.name,
      status: s.correlation?.correlation_status === 'CONFIRMED' ? 'Confirmed' : 'Completed',
      type: 'PCAP' as const,
      scenario: s,
    })),
    ...gateways.map((g) => ({
      id: g.gateway_id,
      time: g.last_seen_at ? g.last_seen_at.split('T')[1]?.substring(0, 5) || 'Active' : 'Enrolled',
      activity: 'Gateway Telemetry',
      source: g.display_name,
      status: g.status === 'CONNECTED' ? 'Connected' : g.status === 'STALE' ? 'Stale' : 'Offline',
      type: 'GATEWAY' as const,
      gatewayId: g.gateway_id,
    })),
  ].slice(0, 8);

  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'CONNECTED':
      case 'CONFIRMED':
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1 text-xs text-emerald-700 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
            {status}
          </span>
        );
      case 'STALE':
      case 'WARNING':
        return (
          <span className="inline-flex items-center gap-1 text-xs text-amber-700 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-600" />
            {status}
          </span>
        );
      case 'OFFLINE':
      case 'ERROR':
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 text-xs text-rose-700 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-600" />
            {status}
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 text-xs text-slate-600 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">System Overview</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Operational status of IPsec protocol verification, capture analysis, and enrolled VPN gateways.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onNavigateToAnalysis}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-xs font-semibold shadow-xs transition-colors cursor-pointer"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Analyze PCAP</span>
          </button>
          <button
            onClick={onAddGateway}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 rounded-md text-xs font-semibold shadow-xs transition-colors cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Gateway</span>
          </button>
        </div>
      </div>

      {/* Compact Metrics Row (Section 6: "Do not turn every metric into a giant colorful card. Use compact summary blocks with strong typography.") */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-white border border-slate-200 rounded-lg p-3.5">
          <span className="text-xs font-medium text-slate-500 block">Total Gateways</span>
          <div className="text-2xl font-bold text-slate-900 mt-1">{gateways.length}</div>
          <span className="text-[11px] text-slate-400 mt-0.5 block">Configured agents</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3.5">
          <span className="text-xs font-medium text-slate-500 block">Connected</span>
          <div className="text-2xl font-bold text-emerald-700 mt-1">{connectedCount}</div>
          <span className="text-[11px] text-slate-400 mt-0.5 block">{staleCount} stale / offline</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3.5">
          <span className="text-xs font-medium text-slate-500 block">Analyzed Captures</span>
          <div className="text-2xl font-bold text-slate-900 mt-1">{scenarios.length}</div>
          <span className="text-[11px] text-slate-400 mt-0.5 block">Loaded sessions</span>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-3.5">
          <span className="text-xs font-medium text-slate-500 block">Available Reports</span>
          <div className="text-2xl font-bold text-slate-900 mt-1">
            {scenarios.reduce((count, scenario) => count + 2 + (scenario.gatewayTelemetry?.matchedSpis?.length ? 1 : 0), gateways.length)}
          </div>
          <span className="text-[11px] text-slate-400 mt-0.5 block">Audit documents</span>
        </div>

        <div className="col-span-2 md:col-span-1 bg-white border border-slate-200 rounded-lg p-3.5">
          <span className="text-xs font-medium text-slate-500 block">Engine Status</span>
          <div className="flex items-center gap-1.5 mt-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span className="text-sm font-semibold text-slate-800">Operational</span>
          </div>
          <span className="text-[11px] text-slate-400 mt-1 block">API & Scapy ready</span>
        </div>
      </div>

      {/* Two-Column Grid: Gateway Status & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Gateway Status Table (Section 6) */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-lg overflow-hidden shadow-xs">
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Enrolled Gateways</h3>
              <p className="text-xs text-slate-500">Live operational status reported via authenticated daemon telemetry</p>
            </div>
            <button
              onClick={onNavigateToGateways}
              className="text-xs text-blue-600 hover:text-blue-800 font-medium inline-flex items-center gap-1 cursor-pointer"
            >
              <span>View all</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {gateways.length === 0 ? (
            <div className="p-8 text-center text-slate-500 space-y-2">
              <Server className="w-8 h-8 mx-auto text-slate-300" />
              <p className="text-xs">No gateways have been connected yet.</p>
              <button
                onClick={onAddGateway}
                className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-blue-600 hover:text-blue-800 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add your first gateway</span>
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs table-compact">
                <thead>
                  <tr>
                    <th>Gateway</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {gateways.slice(0, 5).map((gw) => (
                    <tr key={gw.gateway_id}>
                      <td className="font-medium text-slate-900">
                        <div>{gw.display_name}</div>
                        <span className="text-[11px] font-mono text-slate-400 block">{gw.gateway_id}</span>
                      </td>
                      <td className="font-mono text-slate-600">{gw.telemetry_adapter || gw.gateway_type}</td>
                      <td>{getStatusBadge(gw.status)}</td>
                      <td className="text-slate-500 font-mono text-[11px]">
                        {gw.last_seen_at ? gw.last_seen_at.split('T')[0] : 'Never'}
                      </td>
                      <td className="text-right">
                        <button
                          onClick={() => onViewGateway(gw.gateway_id)}
                          className="px-2 py-1 text-xs font-medium text-slate-700 hover:text-blue-600 hover:bg-slate-100 rounded cursor-pointer"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column: Recent Activity (Section 6) */}
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-lg overflow-hidden shadow-xs">
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Recent Activity</h3>
              <p className="text-xs text-slate-500">Capture analyses and gateway updates</p>
            </div>
            <button
              onClick={onNavigateToReports}
              className="text-xs text-blue-600 hover:text-blue-800 font-medium inline-flex items-center gap-1 cursor-pointer"
            >
              <span>Reports</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {activities.length === 0 ? (
            <div className="p-8 text-center text-slate-500 space-y-2">
              <Activity className="w-8 h-8 mx-auto text-slate-300" />
              <p className="text-xs">No analysis sessions or gateway activity recorded.</p>
              <button
                onClick={onNavigateToAnalysis}
                className="text-xs text-blue-600 hover:text-blue-800 font-medium"
              >
                Upload a capture file to begin
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs table-compact">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Activity</th>
                    <th>Source</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {activities.map((act, i) => (
                    <tr
                      key={i}
                      className="cursor-pointer hover:bg-slate-50"
                      onClick={() => {
                        if (act.type === 'PCAP') {
                          onSelectScenario(act.scenario);
                          onNavigateToAnalysis();
                        } else if (act.type === 'GATEWAY') {
                          onViewGateway(act.gatewayId);
                        }
                      }}
                    >
                      <td className="text-slate-500 font-mono text-[11px] whitespace-nowrap">{act.time}</td>
                      <td className="font-medium text-slate-900 whitespace-nowrap">{act.activity}</td>
                      <td className="text-slate-600 max-w-[140px] truncate" title={act.source}>
                        {act.source}
                      </td>
                      <td>{getStatusBadge(act.status)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>

    </div>
  );
};
