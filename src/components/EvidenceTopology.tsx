import React from 'react';
import { CircleDot, GitBranch, Radio } from 'lucide-react';
import { BackendCaptureAnalysis } from '../types';

interface EvidenceTopologyProps {
  analysis: BackendCaptureAnalysis;
  onSelectPacket?: (packetId: number) => void;
}

export const EvidenceTopology: React.FC<EvidenceTopologyProps> = ({ analysis, onSelectPacket }) => {
  const firstAssociation = analysis.ike_sas[0];
  const childByIndex = (index: number) => analysis.child_sas[index];

  return (
    <section className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-cyan-300" />
            Security Association Evidence Graph
          </h3>
          <p className="text-xs text-slate-400 mt-1">Observed relationships from IKE messages, CHILD_SA proposals, and ESP flows</p>
        </div>
        <span className="text-[11px] text-cyan-300">{analysis.ike_sas.length} IKE · {analysis.child_sas.length} CHILD_SA · {analysis.esp_flows.length} ESP</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mt-4">
        <div className="rounded-lg border border-blue-900/70 bg-blue-950/20 p-3">
          <div className="text-[10px] uppercase tracking-wider text-blue-300">IKE Security Association</div>
          {firstAssociation ? (
            <div className="mt-2 space-y-2">
              <div className="font-mono text-xs text-white">{firstAssociation.version}</div>
              <div className="text-[11px] text-slate-400 break-all">{firstAssociation.initiator_spi}</div>
              <div className="text-[11px] text-slate-400 break-all">{firstAssociation.responder_spi}</div>
              <div className="flex flex-wrap gap-1.5">
                {firstAssociation.message_packets.map((packet) => (
                  <button key={packet} type="button" onClick={() => onSelectPacket?.(packet)} className="text-[10px] text-cyan-300 border border-cyan-900 rounded px-1.5 py-1 enabled:hover:bg-cyan-950">
                    Packet {packet}
                  </button>
                ))}
              </div>
            </div>
          ) : <div className="mt-2 text-xs text-amber-300">Not observed</div>}
        </div>

        <div className="rounded-lg border border-amber-900/70 bg-amber-950/20 p-3">
          <div className="text-[10px] uppercase tracking-wider text-amber-300">CHILD_SA</div>
          {analysis.child_sas.length > 0 ? (
            <div className="mt-2 space-y-2">
              {analysis.child_sas.map((child, index) => (
                <div key={`${child.spi}-${index}`} className="rounded border border-slate-700 bg-slate-950/70 p-2">
                  <div className="font-mono text-xs text-white">{child.spi || 'SPI not observable'}</div>
                  <div className="text-[10px] text-slate-500">
                    Initiator SPI: {child.initiator_spi || 'not observable'} · Responder SPI: {child.responder_spi || 'not observable'}
                  </div>
                  <div className="text-[10px] text-slate-400">{child.lifecycle} · {child.direction} · {child.proposal_role}</div>
                  <div className="text-[10px] text-slate-500">
                    PFS: {child.pfs === null ? 'not observable' : child.pfs ? 'yes' : 'no'} · ESN: {child.esn === null ? 'not observable' : child.esn ? 'yes' : 'no'}
                  </div>
                  <div className="text-[10px] text-slate-500">
                    Lifetime: {child.lifetime_seconds === null ? 'not observable' : `${child.lifetime_seconds}s`}
                  </div>
                  <button type="button" onClick={() => onSelectPacket?.(child.proposal_packet)} className="mt-1 text-[10px] text-cyan-300 enabled:hover:underline">
                    Proposal packet {child.proposal_packet}
                  </button>
                </div>
              ))}
            </div>
          ) : <div className="mt-2 text-xs text-amber-300">No observable CHILD_SA proposal</div>}
        </div>

        <div className="rounded-lg border border-cyan-900/70 bg-cyan-950/20 p-3">
          <div className="text-[10px] uppercase tracking-wider text-cyan-300">ESP Flows</div>
          {analysis.esp_flows.length > 0 ? (
            <div className="mt-2 space-y-2">
              {analysis.esp_flows.map((flow) => (
                <div key={flow.spi} className="rounded border border-slate-700 bg-slate-950/70 p-2">
                  <div className="font-mono text-xs text-white">{flow.spi}</div>
                  <div className="text-[10px] text-slate-400">{flow.direction} · {flow.status}</div>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {flow.packet_numbers.slice(0, 4).map((packet) => (
                      <button key={packet} type="button" onClick={() => onSelectPacket?.(packet)} className="text-[10px] text-cyan-300 enabled:hover:underline">Packet {packet}</button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : <div className="mt-2 text-xs text-amber-300">No ESP flow observed</div>}
        </div>
      </div>

      <div className="mt-5 pt-4 border-t border-slate-800">
        <div className="text-[10px] uppercase tracking-wider text-slate-400 flex items-center gap-1.5"><Radio className="w-3 h-3 text-cyan-300" /> Capture timeline</div>
        <div className="mt-3 space-y-2">
          {analysis.events.length > 0 ? analysis.events.map((event) => (
            <button key={`${event.packet}-${event.name}`} type="button" onClick={() => onSelectPacket?.(event.packet)} className="w-full flex items-center gap-3 text-left rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 enabled:hover:border-cyan-800">
              <span className="font-mono text-[10px] text-cyan-300 w-16">#{event.packet}</span>
              <CircleDot className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-xs text-white">{event.name}</span>
              <span className="text-[10px] text-slate-500 ml-auto">Exchange {event.exchange_type}</span>
            </button>
          )) : (
            <div className="text-xs text-slate-400">No IKE lifecycle events observed.</div>
          )}
        </div>
      </div>
    </section>
  );
};