import React, { useEffect, useState } from 'react';
import { Layers, Terminal, Search, Filter, Hash, Clock, Eye } from 'lucide-react';
import { PacketInfo } from '../types';

interface PacketViewerProps {
  packets: PacketInfo[];
  selectedPacketId?: number | null;
  onSelectPacket?: (packetId: number) => void;
}

export const PacketViewer: React.FC<PacketViewerProps> = ({ packets, selectedPacketId, onSelectPacket }) => {
  const [filter, setFilter] = useState<'ALL' | 'IKE' | 'ESP'>('ALL');
  const [selectedPacket, setSelectedPacket] = useState<PacketInfo | null>(packets[0] || null);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    const nextPacket = selectedPacketId == null
      ? packets[0] || null
      : packets.find((packet) => packet.id === selectedPacketId) || packets[0] || null;
    setSelectedPacket(nextPacket);
  }, [packets, selectedPacketId]);

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
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
      
      {/* Header & Filter Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Terminal className="w-4 h-4 text-blue-400" />
            <span>Interactive Packet Dissector &amp; Stream Inspector</span>
          </h3>
          <p className="text-xs text-slate-400">
            Real-time inspection of captured IKE handshake negotiation and encapsulated ESP frames
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search packets / SPI..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-800 text-slate-200 text-xs pl-8 pr-3 py-1.5 rounded-lg border border-slate-700 focus:outline-none focus:border-blue-500 w-44"
            />
          </div>

          <div className="inline-flex rounded-lg bg-slate-800 p-0.5 border border-slate-700">
            {(['ALL', 'IKE', 'ESP'] as const).map((f) => (
              <button
                key={f}
                id={`btn-filter-${f.toLowerCase()}`}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-bold cursor-pointer transition-colors ${
                  filter === f
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Packet Table */}
      <div className="mt-4 border border-slate-800 rounded-lg overflow-hidden">
        <div className="max-h-64 overflow-y-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="bg-slate-800/80 text-[11px] uppercase tracking-wider text-slate-400 font-semibold sticky top-0 border-b border-slate-700/80">
              <tr>
                <th className="py-2 px-3 w-12 text-center">#</th>
                <th className="py-2 px-3 w-20">Time</th>
                <th className="py-2 px-3 w-32">Source IP</th>
                <th className="py-2 px-3 w-32">Destination IP</th>
                <th className="py-2 px-3 w-20">Proto</th>
                <th className="py-2 px-3 w-16 text-right">Length</th>
                <th className="py-2 px-3">Protocol Information</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredPackets.map((pkt) => {
                const isSelected = selectedPacket?.id === pkt.id;
                return (
                  <tr
                    key={pkt.id}
                    id={`packet-row-${pkt.id}`}
                    onClick={() => {
                      setSelectedPacket(pkt);
                      onSelectPacket?.(pkt.id);
                    }}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-blue-950/70 text-white'
                        : 'hover:bg-slate-800/40 text-slate-300'
                    }`}
                  >
                    <td className="py-1.5 px-3 text-center font-mono text-slate-500 text-[11px]">
                      {pkt.id}
                    </td>
                    <td className="py-1.5 px-3 font-mono text-slate-400 text-[11px]">
                      +{(pkt.timestamp / 1000).toFixed(3)}s
                    </td>
                    <td className="py-1.5 px-3 font-mono text-[11px] truncate max-w-[120px]">
                      {pkt.sourceIp}
                    </td>
                    <td className="py-1.5 px-3 font-mono text-[11px] truncate max-w-[120px]">
                      {pkt.destIp}
                    </td>
                    <td className="py-1.5 px-3 font-mono">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          pkt.protocol === 'IKE'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                        }`}
                      >
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="py-1.5 px-3 font-mono text-right text-slate-400 text-[11px]">
                      {pkt.length}b
                    </td>
                    <td className="py-1.5 px-3 text-xs text-slate-200 truncate max-w-[320px]">
                      <span>{pkt.info}</span>
                      {pkt.natT && (
                        <span className="ml-2 rounded border border-violet-800 bg-violet-950/60 px-1.5 py-0.5 text-[10px] font-bold text-violet-300">
                          NAT-T
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Packet Inspector / Hex Dump */}
      {selectedPacket && (
        <div className="mt-4 p-4 rounded-lg bg-slate-950 border border-slate-800">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-xs">
            <div className="flex items-center gap-2">
              <Eye className="w-3.5 h-3.5 text-blue-400" />
              <span className="font-bold text-white">
                Packet #{selectedPacket.id} Dissection Details
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                (Proto: {selectedPacket.protocol}, Size: {selectedPacket.length} bytes)
              </span>
            </div>
            {selectedPacket.spi && (
              <span className="text-xs font-mono text-cyan-400">
                SPI: {selectedPacket.spi}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="space-y-1.5 text-slate-300">
              <div><strong className="text-slate-400">Frame:</strong> {selectedPacket.info}</div>
              <div><strong className="text-slate-400">Endpoint Route:</strong> {selectedPacket.sourceIp} → {selectedPacket.destIp}</div>
              {selectedPacket.natT && (
                <div><strong className="text-slate-400">Transport:</strong> IKE NAT traversal over UDP 4500</div>
              )}
              {selectedPacket.seq !== undefined && (
                <div><strong className="text-slate-400">Sequence Number:</strong> {selectedPacket.seq}</div>
              )}
              <div className="text-[11px] text-slate-400 pt-1">
                {selectedPacket.protocol === 'IKE'
                  ? 'IKE Header & Payloads are plain RFC compliant UDP datagrams used to establish Security Associations.'
                  : 'Encapsulating Security Payload (ESP): IP protocol 50 datagram carrying encrypted tunnel data.'}
              </div>
            </div>

            {/* Hex Dump preview */}
            <div>
              <div className="text-[11px] font-mono text-slate-500 mb-1">
                Hex Dump Preview (Payload Byte Representation):
              </div>
              <div className="p-2 bg-slate-900 rounded font-mono text-[11px] text-slate-400 break-all leading-relaxed border border-slate-800">
                {selectedPacket.rawPreview ||
                  '8f 3c 1a 9e 20 bb 41 d7 44 a1 09 8e ef 67 12 bc 01 10 02 00 00 00 00 00 00 00 00 7c 00 00 00 30'}
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
