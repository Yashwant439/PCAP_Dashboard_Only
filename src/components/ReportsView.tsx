import React, { useState } from 'react';
import { FileText, Download, Eye, Server, Shield, Search, Filter } from 'lucide-react';
import { GatewaySummary, VpnCaptureScenario } from '../types';
import type { AssessmentReportKind } from '../utils/assessmentReport';

interface ReportsViewProps {
  scenarios: VpnCaptureScenario[];
  gateways: GatewaySummary[];
  onViewScenarioReport: (scenario: VpnCaptureScenario, kind: AssessmentReportKind) => void;
  onViewGatewayReport: (gatewayId: string) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  scenarios,
  gateways,
  onViewScenarioReport,
  onViewGatewayReport,
}) => {
  const [filterMode, setFilterMode] = useState<'ALL' | 'PCAP' | 'GATEWAY' | 'COMBINED'>('ALL');
  const [search, setSearch] = useState('');

  // Assemble list of available audit documents
  const scenarioReports = scenarios.flatMap((s) => {
    const isCombined = !!s.gatewayTelemetry && s.gatewayTelemetry.matchedSpis?.length > 0;
    const base = {
      gateway: s.gatewayTelemetry?.gatewayId || '—',
      created: s.id.startsWith('uploaded-') ? new Date(Number(s.id.split('-')[1])).toLocaleTimeString() : 'Recent',
      rawScenario: s,
    };
    return [
      { ...base, id: `pcap-${s.id}-executive`, title: `${s.name} — Executive`, mode: 'PCAP' as const, reportKind: 'EXECUTIVE' as const },
      { ...base, id: `pcap-${s.id}-technical`, title: `${s.name} — Technical`, mode: 'PCAP' as const, reportKind: 'TECHNICAL' as const },
      ...(isCombined ? [{ ...base, id: `pcap-${s.id}-combined`, title: `${s.name} — Combined`, mode: 'COMBINED' as const, reportKind: 'COMBINED' as const }] : []),
    ];
  });

  const gatewayReports = gateways.map((g) => ({
    id: `gw-${g.gateway_id}`,
    title: `${g.display_name} Security Audit`,
    mode: 'GATEWAY' as const,
    gateway: g.display_name,
    created: g.last_seen_at ? g.last_seen_at.split('T')[0] : 'Active',
    gatewayId: g.gateway_id,
  }));

  const allReports = [...scenarioReports, ...gatewayReports].filter((r) => {
    if (filterMode !== 'ALL' && r.mode !== filterMode) return false;
    if (search) {
      const q = search.toLowerCase();
      return r.title.toLowerCase().includes(q) || r.gateway.toLowerCase().includes(q);
    }
    return true;
  });

  const getModeBadge = (mode: 'PCAP' | 'GATEWAY' | 'COMBINED') => {
    switch (mode) {
      case 'COMBINED':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-blue-50 text-blue-700 border border-blue-200">
            Combined Audit
          </span>
        );
      case 'GATEWAY':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
            Gateway Only
          </span>
        );
      case 'PCAP':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
            PCAP Only
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Header & Filter Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Security Assessment Reports</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Formal cryptographic compliance verifications and empirical traffic telemetry audits.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <input
              type="text"
              placeholder="Filter reports..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-48 pl-3 pr-3 py-1.5 bg-white border border-slate-300 rounded-md text-xs text-slate-800 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Mode Switcher */}
          <div className="inline-flex rounded-md bg-slate-100 p-0.5 border border-slate-200">
            {(['ALL', 'PCAP', 'GATEWAY', 'COMBINED'] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => setFilterMode(mode)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer ${
                  filterMode === mode
                    ? 'bg-white text-slate-900 shadow-xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {mode === 'ALL' ? 'All' : mode === 'COMBINED' ? 'Combined' : mode === 'GATEWAY' ? 'Gateway' : 'PCAP'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Reports Table (Section 16) */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden shadow-xs">
        {allReports.length === 0 ? (
          <div className="p-12 text-center text-slate-500 space-y-2">
            <FileText className="w-8 h-8 mx-auto text-slate-300" />
            <h4 className="text-sm font-semibold text-slate-800">No Reports Available</h4>
            <p className="text-xs max-w-sm mx-auto">
              Upload a PCAP capture file or connect a VPN gateway to generate cryptographic audit documents.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs table-compact">
              <thead>
                <tr>
                  <th>Report Name</th>
                  <th>Audit Mode</th>
                  <th>Target / Gateway</th>
                  <th>Timestamp</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {allReports.map((report) => (
                  <tr key={report.id} className="hover:bg-slate-50">
                    <td className="font-medium text-slate-900">
                      <div>{report.title}</div>
                      <span className="text-[11px] font-mono text-slate-400 block">{report.id}</span>
                    </td>
                    <td>{getModeBadge(report.mode)}</td>
                    <td className="font-mono text-slate-600">{report.gateway}</td>
                    <td className="font-mono text-slate-500 text-[11px]">{report.created}</td>
                    <td className="text-right">
                      <button
                        onClick={() => {
                          if (report.mode === 'GATEWAY') {
                            onViewGatewayReport(report.gatewayId);
                          } else {
                            onViewScenarioReport(report.rawScenario, report.reportKind);
                          }
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded hover:border-slate-400 cursor-pointer shadow-xs"
                      >
                        <Eye className="w-3.5 h-3.5 text-slate-500" />
                        <span>View</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
};
