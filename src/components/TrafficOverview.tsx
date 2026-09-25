import React from 'react';
import { Activity, Package, Clock, Wifi, Database, Radio } from 'lucide-react';
import { MLObservedFeatures } from '../types';

interface TrafficOverviewProps {
  observed: MLObservedFeatures;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function formatDuration(seconds: number): string {
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(2)} s`;
  const m = Math.floor(seconds / 60);
  const s = (seconds % 60).toFixed(0).padStart(2, '0');
  return `${m}m ${s}s`;
}

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ReactNode;
  badge?: string;
  badgeColor?: string;
}

const StatCard: React.FC<StatCardProps> = ({ label, value, sub, icon, badge, badgeColor }) => (
  <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3 flex items-start gap-3">
    <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 mt-0.5">
      {icon}
    </div>
    <div className="min-w-0 flex-1">
      <div className="flex items-center gap-1.5 flex-wrap">
        <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">{label}</span>
        {badge && (
          <span className={`text-[9px] font-bold px-1 py-0.5 rounded border ${badgeColor ?? 'bg-cyan-950 border-cyan-800 text-cyan-300'}`}>
            {badge}
          </span>
        )}
      </div>
      <div className="text-base font-bold text-white mt-0.5 font-mono">{value}</div>
      {sub && <div className="text-[10px] text-slate-500 mt-0.5">{sub}</div>}
    </div>
  </div>
);

export const TrafficOverview: React.FC<TrafficOverviewProps> = ({ observed }) => {
  const ikeExchanges = Object.entries(observed.ike_exchange_distribution);

  return (
    <div id="section-traffic-overview" className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <Activity className="w-4 h-4 text-blue-400" />
        <h3 className="text-sm font-bold text-white">Traffic Overview</h3>
        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-cyan-950/60 border-cyan-800 text-cyan-300 ml-auto">
          OBSERVED
        </span>
      </div>

      {/* Core metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-3 gap-3">
        <StatCard
          label="Packet Count"
          value={observed.packet_count.toLocaleString()}
          icon={<Package className="w-4 h-4 text-blue-400" />}
          badge="OBSERVED"
          badgeColor="bg-cyan-950/60 border-cyan-800 text-cyan-300"
        />
        <StatCard
          label="Total Bytes"
          value={formatBytes(observed.total_bytes)}
          sub={`${observed.total_bytes.toLocaleString()} bytes`}
          icon={<Database className="w-4 h-4 text-purple-400" />}
          badge="OBSERVED"
          badgeColor="bg-cyan-950/60 border-cyan-800 text-cyan-300"
        />
        <StatCard
          label="Capture Duration"
          value={formatDuration(observed.capture_duration_seconds)}
          icon={<Clock className="w-4 h-4 text-emerald-400" />}
          badge="OBSERVED"
          badgeColor="bg-cyan-950/60 border-cyan-800 text-cyan-300"
        />
      </div>

      {/* Packet size stats */}
      <div className="grid grid-cols-3 gap-3">
        <StatCard
          label="Avg Pkt Size"
          value={`${observed.avg_packet_size.toFixed(1)} B`}
          icon={<Radio className="w-4 h-4 text-cyan-400" />}
          badge="DERIVED"
          badgeColor="bg-slate-800 border-slate-600 text-slate-300"
        />
        <StatCard
          label="Min Pkt Size"
          value={`${observed.min_packet_size} B`}
          icon={<Radio className="w-4 h-4 text-slate-400" />}
          badge="OBSERVED"
          badgeColor="bg-cyan-950/60 border-cyan-800 text-cyan-300"
        />
        <StatCard
          label="Max Pkt Size"
          value={`${observed.max_packet_size} B`}
          icon={<Radio className="w-4 h-4 text-slate-400" />}
          badge="OBSERVED"
          badgeColor="bg-cyan-950/60 border-cyan-800 text-cyan-300"
        />
      </div>

      {/* Protocol breakdown */}
      <div>
        <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2">Protocol Breakdown</div>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
          {[
            { label: 'IKE Pkts', value: observed.ike_packet_count, color: 'text-blue-400' },
            { label: 'ESP Pkts', value: observed.esp_packet_count, color: 'text-emerald-400' },
            { label: 'UDP/500', value: observed.udp_500_count, color: 'text-cyan-400' },
            { label: 'UDP/4500', value: observed.udp_4500_count, color: 'text-purple-400' },
            { label: 'UDP Total', value: observed.udp_packet_count, color: 'text-slate-300' },
            { label: 'IKE Bytes', value: formatBytes(observed.ike_bytes), color: 'text-blue-300' },
            { label: 'ESP Bytes', value: formatBytes(observed.esp_bytes), color: 'text-emerald-300' },
            { label: 'IKE Avg', value: `${observed.ike_avg_packet_size.toFixed(0)} B`, color: 'text-slate-300' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-slate-950/60 border border-slate-800 rounded-lg p-2.5">
              <div className="text-[9px] uppercase tracking-wider text-slate-600 font-semibold">{label}</div>
              <div className={`text-sm font-bold ${color} mt-0.5 font-mono`}>{value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* IKE Exchange Breakdown */}
      <div>
        <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2">IKE Exchange Distribution</div>
        {ikeExchanges.length === 0 ? (
          <div className="text-xs text-slate-500 italic py-2">
            No IKE exchange types detected in this capture.
          </div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {ikeExchanges.map(([exchange, count]) => (
              <div key={exchange} className="bg-slate-950/60 border border-slate-800 rounded-lg p-2.5">
                <div className="text-[9px] uppercase tracking-wider text-slate-600 font-semibold truncate">{exchange.replace('IKE_', '')}</div>
                <div className="text-lg font-bold text-white mt-0.5">{count}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* IKE Request/Response */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">IKE Requests</div>
          <div className="text-xl font-bold text-white mt-1 font-mono">{observed.ike_request_count}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">Initiator messages</div>
        </div>
        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">IKE Responses</div>
          <div className="text-xl font-bold text-white mt-1 font-mono">{observed.ike_response_count}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">Responder messages</div>
        </div>
      </div>

      {/* IKE version */}
      {observed.ike_version_detected && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-blue-950/30 border border-blue-900/60">
          <Wifi className="w-4 h-4 text-blue-400 shrink-0" />
          <div className="text-xs text-blue-200">
            <span className="font-bold">IKE Version Detected:</span>{' '}
            <span className="font-mono text-white">{observed.ike_version_detected}</span>
            <span className="text-blue-400 ml-1">(from Scapy IKE header version byte)</span>
          </div>
          <span className="ml-auto text-[10px] font-bold px-1.5 py-0.5 rounded border bg-cyan-950/60 border-cyan-800 text-cyan-300 shrink-0">OBSERVED</span>
        </div>
      )}
    </div>
  );
};
