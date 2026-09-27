import React, { useState } from 'react';
import { Terminal, Search } from 'lucide-react';
import { PacketInfo } from '../types';

interface PacketViewerProps {
  packets: PacketInfo[];
}

export const PacketViewer: React.FC<PacketViewerProps> = ({ packets }) => {
  const [filter, setFilter] = useState<'ALL' | 'IKE' | 'ESP'>('ALL');
  const [selectedPacket, setSelectedPacket] = useState<PacketInfo | null>(packets[0] || null);
  const [searchTerm, setSearchTerm] = useState('');

  const filteredPackets = packets.filter((p) => {
    if (filter === 'IKE' && p.protocol !== 'IKE') return false;
    if (filter === 'ESP' && p.protocol !== 'ESP') return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return (
        p.info.toLowerCase().includes(q) ||
        p.sourceIp.includes(q) ||
        p.destIp.includes(q) ||
        (p.spi && p.spi.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div className="space-y-4">

      {/* Header & Filter Controls */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-4 py-3 border-b border-slate-200">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <span>Packet Dissector</span>
            </h3>
            <p className="text-xs text-slate-500">
              Real-time inspection of captured IKE and ESP frames
            </p>
          </div>

          <div className="flex items-center gap-2">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-400" />
              <input
                type="text"
                placeholder="Search IP, SPI..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-50 text-slate-700 text-xs pl-8 pr-3 py-1.5 rounded-lg border border-slate-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 w-44"
              />
            </div>

            {/* Filter tabs */}
            <div className="inline-flex rounded-lg bg-slate-100 p-0.5 border border-slate-200">
              {(['ALL', 'IKE', 'ESP'] as const).map((f) => (
                <button
                  key={f}
                  id={`btn-filter-${f.toLowerCase()}`}
                  onClick={() => setFilter(f)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-semibold cursor-pointer transition-colors ${
                    filter === f
                      ? 'bg-white text-slate-800 shadow-xs border border-slate-200'
                      : 'text-slate-500 hover:text-slate-700'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Packet Table */}
        <div className="max-h-64 overflow-y-auto">
          <table className="w-full text-left text-xs table-compact">
            <thead>
              <tr>
                <th className="w-10 text-center">#</th>
                <th className="w-20">Time</th>
                <th className="w-32">Source</th>
                <th className="w-32">Destination</th>
                <th className="w-16">Proto</th>
                <th className="w-14 text-right">Len</th>
                <th>Info</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.map((pkt) => {
                const isSelected = selectedPacket?.id === pkt.id;
                return (
                  <tr
                    key={pkt.id}
                    id={`packet-row-${pkt.id}`}
                    onClick={() => setSelectedPacket(pkt)}
                    className={`cursor-pointer ${
                      isSelected
                        ? 'bg-blue-50 border-l-2 border-l-blue-500'
                        : 'hover:bg-slate-50'
                    }`}
                  >
                    <td className="text-center font-mono text-slate-400 text-[11px]">
                      {pkt.id}
                    </td>
                    <td className="font-mono text-slate-500 text-[11px]">
                      +{(pkt.timestamp / 1000).toFixed(3)}s
                    </td>
                    <td className="font-mono text-[11px] truncate max-w-[120px] text-slate-700">
                      {pkt.sourceIp}
                    </td>
                    <td className="font-mono text-[11px] truncate max-w-[120px] text-slate-700">
                      {pkt.destIp}
                    </td>
                    <td className="font-mono">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          pkt.protocol === 'IKE'
                            ? 'bg-amber-50 text-amber-700 border border-amber-200'
                            : 'bg-blue-50 text-blue-700 border border-blue-200'
                        }`}
                      >
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="font-mono text-right text-slate-500 text-[11px]">
                      {pkt.length}b
                    </td>
                    <td className="text-xs text-slate-600 truncate max-w-[320px]">
                      {pkt.info}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Packet Inspector */}
      {selectedPacket && (
        <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <span>Packet #{selectedPacket.id} Details</span>
              <span className="text-xs text-slate-400 font-normal font-mono">
                ({selectedPacket.protocol}, {selectedPacket.length} bytes)
              </span>
            </div>
            {selectedPacket.spi && (
              <span className="text-xs font-mono text-blue-600 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded">
                SPI: {selectedPacket.spi}
              </span>
            )}
          </div>

          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5 text-xs">
              <div className="flex gap-2">
                <span className="text-slate-500 w-28 shrink-0">Frame Info</span>
                <span className="text-slate-800 font-medium">{selectedPacket.info}</span>
              </div>
              <div className="flex gap-2">
                <span className="text-slate-500 w-28 shrink-0">Route</span>
                <span className="font-mono text-slate-700">{selectedPacket.sourceIp} → {selectedPacket.destIp}</span>
              </div>
              {(selectedPacket.sourcePort !== undefined || selectedPacket.destPort !== undefined) && (
                <div className="flex gap-2">
                  <span className="text-slate-500 w-28 shrink-0">Ports</span>
                  <span className="font-mono text-slate-700">{selectedPacket.sourcePort ?? '?'} → {selectedPacket.destPort ?? '?'}</span>
                </div>
              )}
              {selectedPacket.ipVersion && (
                <div className="flex gap-2">
                  <span className="text-slate-500 w-28 shrink-0">IP Version</span>
                  <span className="font-mono text-slate-700">{selectedPacket.ipVersion}</span>
                </div>
              )}
              {selectedPacket.seq !== undefined && (
                <div className="flex gap-2">
                  <span className="text-slate-500 w-28 shrink-0">Sequence</span>
                  <span className="font-mono text-slate-700">{selectedPacket.seq}</span>
                </div>
              )}
              <div className="text-[11px] text-slate-400 pt-1 leading-relaxed">
                {selectedPacket.protocol === 'IKE'
                  ? 'IKE: RFC-compliant UDP datagrams used to establish Security Associations.'
                  : 'ESP (IP proto 50): Encrypted tunnel data. Payload is cryptographically opaque.'}
              </div>
            </div>

            {/* Hex Preview */}
            <div>
              <div className="text-[11px] text-slate-500 mb-1.5 font-medium">Hex Dump Preview</div>
              <div className="p-2.5 bg-slate-900 rounded-lg font-mono text-[11px] text-emerald-400 break-all leading-relaxed border border-slate-700">
                {selectedPacket.rawPreview ||
                  '8f 3c 1a 9e 20 bb 41 d7 44 a1 09 8e ef 67 12 bc 01 10 02 00 00 00 00 00 00 00 00 7c 00 00 00 30'}
              </div>
              {selectedPacket.debug && (
                <details className="mt-2">
                  <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-700">Decoded layer details</summary>
                  <pre className="mt-1.5 max-h-40 overflow-auto whitespace-pre-wrap text-[10px] text-slate-500 bg-slate-50 p-2 rounded border border-slate-200">{selectedPacket.debug}</pre>
                </details>
              )}
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
