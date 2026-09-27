import React from 'react';
import {
  FileCode,
  Server,
  GitCompare,
  Clock,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import { GatewayCorrelationResult, GatewayTelemetrySummary, IkeSecurityAssociation } from '../types';

interface CombinedAnalysisPanelProps {
  sa: IkeSecurityAssociation;
  gatewayTelemetry: GatewayTelemetrySummary;
  correlation?: GatewayCorrelationResult | null;
  packetCount?: number;
}

export const CombinedAnalysisPanel: React.FC<CombinedAnalysisPanelProps> = ({
  sa,
  gatewayTelemetry,
  correlation,
  packetCount,
}) => {
  const isConfirmed =
    (correlation?.correlation_status === 'CONFIRMED' || gatewayTelemetry.correlationStatus === 'CONFIRMED') &&
    gatewayTelemetry.matchedSpis.length > 0;

  const pcapSpis: string[] = gatewayTelemetry.pcapSpis || [];
  const matchedSpis: string[] = gatewayTelemetry.matchedSpis || [];
  const unmatchedPcap: string[] = gatewayTelemetry.unmatchedPcapSpis || [];

  return (
    <div className="space-y-5">
      
      {/* Overview & Verdict Banner */}
      <div className="flex flex-col gap-4 rounded-xl border border-stone-300 bg-white p-4 shadow-[0_10px_24px_rgba(68,64,60,0.07)] md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="rounded border border-teal-200 bg-teal-50 px-2 py-0.5 text-xs font-semibold text-teal-800">
              MODE 3: COMBINED AUDIT
            </span>
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold ${
                isConfirmed
                  ? 'border border-teal-200 bg-teal-50 text-teal-800'
                  : 'border border-amber-200 bg-amber-50 text-amber-800'
              }`}
            >
              {isConfirmed ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-teal-600" />
                  <span>Correlation Confirmed: Exact SPI Match</span>
                </>
              ) : (
                <>
                  <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
                  <span>Correlation Status: Unknown</span>
                </>
              )}
            </span>
          </div>
          <p className="mt-1 max-w-2xl text-xs text-stone-500">
            Correlating empirical packet evidence from network capture against authenticated StrongSwan daemon state using exact normalized hexadecimal SPI matching.
          </p>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono shrink-0">
          <div className="rounded border border-stone-200 bg-stone-50 p-2 text-right">
            <span className="block font-sans text-[10px] uppercase text-stone-400">Matched SPIs</span>
            <span className="font-bold text-stone-900">{matchedSpis.length} / {pcapSpis.length}</span>
          </div>
          <div className="rounded border border-stone-200 bg-stone-50 p-2 text-right">
            <span className="block font-sans text-[10px] uppercase text-stone-400">Gateway Status</span>
            <span className="font-bold text-stone-900">{gatewayTelemetry.gatewayStatus}</span>
          </div>
        </div>
      </div>

      {/* 3 Explicit Evidence Tables (Section 14) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* ========================================================================= */}
        {/* SECTION A: PCAP OBSERVED */}
        {/* ========================================================================= */}
        <div className="flex flex-col justify-between overflow-hidden rounded-xl border border-stone-200 bg-white shadow-[0_6px_16px_rgba(68,64,60,0.05)]">
          <div>
            <div className="flex items-center justify-between border-b border-stone-200 bg-stone-50 px-4 py-3">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-teal-700" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-stone-900">
                  Section A: PCAP Observed
                </h4>
              </div>
              <span className="font-mono text-[11px] text-stone-500">Source: Capture</span>
            </div>

            <div className="p-4 space-y-3">
              <table className="w-full text-xs text-left">
                <tbody className="divide-y divide-stone-100">
                  <tr>
                    <td className="w-28 py-2 font-medium text-stone-500">Packets</td>
                    <td className="py-2 font-mono font-semibold text-stone-900">{packetCount ? packetCount.toLocaleString() : 'N/A'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 font-medium text-stone-500">Protocol</td>
                    <td className="py-2 font-mono text-stone-900">{sa.operationalMode} ({sa.ipVersion})</td>
                  </tr>
                  <tr>
                    <td className="py-2 font-medium text-stone-500">IKE Version</td>
                    <td className="py-2 font-mono text-stone-900">{sa.ikeVersion}</td>
                  </tr>
                  <tr>
                    <td className="py-2 font-medium text-stone-500">Cipher</td>
                    <td className="truncate py-2 font-mono text-stone-900" title={sa.encryptionAlgorithm}>
                      {sa.encryptionAlgorithm}
                    </td>
                  </tr>
                </tbody>
              </table>

              <div className="border-t border-stone-100 pt-2">
                <span className="mb-1 block text-[11px] font-semibold text-stone-600">
                  Observed ESP SPIs ({pcapSpis.length}):
                </span>
                {pcapSpis.length === 0 ? (
                  <span className="text-xs italic text-stone-400">None detected</span>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {pcapSpis.map((spi, i) => (
                      <span
                        key={i}
                        className={`text-[11px] font-mono px-1.5 py-0.5 rounded border ${
                          matchedSpis.includes(spi)
                            ? 'border-teal-300 bg-teal-50 font-semibold text-teal-800'
                            : 'border-stone-200 bg-stone-100 text-stone-700'
                        }`}
                      >
                        {spi}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="border-t border-stone-200 bg-stone-50 px-4 py-2 text-[11px] text-stone-400">
            Empirical observation from captured frames.
          </div>
        </div>

        {/* ========================================================================= */}
        {/* SECTION B: GATEWAY OBSERVED */}
        {/* ========================================================================= */}
        <div className="flex flex-col justify-between overflow-hidden rounded-xl border border-stone-200 bg-white shadow-[0_6px_16px_rgba(68,64,60,0.05)]">
          <div>
            <div className="flex items-center justify-between border-b border-stone-200 bg-stone-50 px-4 py-3">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-teal-700" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-stone-900">
                  Section B: Gateway Observed
                </h4>
              </div>
              <span className="font-mono text-[11px] text-stone-500">Source: Telemetry</span>
            </div>

            <div className="p-4 space-y-3">
              <table className="w-full text-xs text-left">
                <tbody className="divide-y divide-stone-100">
                  <tr>
                    <td className="w-28 py-2 font-medium text-stone-500">Gateway ID</td>
                    <td className="truncate py-2 font-mono text-stone-900" title={gatewayTelemetry.gatewayId}>
                      {gatewayTelemetry.gatewayId || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2 font-medium text-stone-500">Adapter</td>
                    <td className="py-2 font-mono text-stone-900">{gatewayTelemetry.adapter || 'STRONGSWAN'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 font-medium text-stone-500">Collected At</td>
                    <td className="truncate py-2 font-mono text-[11px] text-stone-900">
                      {gatewayTelemetry.collectedAt || 'N/A'}
                    </td>
                  </tr>
                </tbody>
              </table>

              <div className="border-t border-stone-100 pt-2">
                <span className="mb-1 block text-[11px] font-semibold text-stone-600">
                  Active SA Records ({gatewayTelemetry.telemetry?.length || 0}):
                </span>
                {(!gatewayTelemetry.telemetry || gatewayTelemetry.telemetry.length === 0) ? (
                  <span className="text-xs italic text-stone-400">No SA records reported</span>
                ) : (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {gatewayTelemetry.telemetry.map((rawT, idx) => {
                      const t = rawT as Record<string, any>;
                      return (
                        <div key={idx} className="rounded border border-stone-200 bg-stone-50 p-2 font-mono text-[11px]">
                          <div className="font-semibold text-stone-800">{String(t.name || `SA #${idx + 1}`)}</div>
                          <div className="text-stone-600">
                            Inbound: {String(t.inbound_spi || t.spi || 'N/A')}
                            {t.outbound_spi ? ` | Outbound: ${String(t.outbound_spi)}` : ''}
                          </div>
                          {t.encr ? <div className="text-stone-500">Cipher: {String(t.encr)}</div> : null}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="border-t border-stone-200 bg-stone-50 px-4 py-2 text-[11px] text-stone-400">
            Reported directly from local kernel/daemon via VICI.
          </div>
        </div>

        {/* ========================================================================= */}
        {/* SECTION C: CORRELATION */}
        {/* ========================================================================= */}
        <div className="flex flex-col justify-between overflow-hidden rounded-xl border border-stone-200 bg-white shadow-[0_6px_16px_rgba(68,64,60,0.05)]">
          <div>
            <div className="flex items-center justify-between border-b border-stone-200 bg-stone-50 px-4 py-3">
              <div className="flex items-center gap-2">
                <GitCompare className="w-4 h-4 text-teal-700" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-stone-900">
                  Section C: Correlation
                </h4>
              </div>
              <span className={`font-mono text-[11px] font-semibold ${isConfirmed ? 'text-teal-700' : 'text-amber-700'}`}>
                {isConfirmed ? 'CONFIRMED' : 'UNKNOWN'}
              </span>
            </div>

            <div className="p-4 space-y-3">
              <div>
                <span className="mb-1 block text-[11px] font-semibold text-stone-600">
                  Exact Matched SPIs ({matchedSpis.length}):
                </span>
                {matchedSpis.length === 0 ? (
                  <div className="rounded border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800">
                    No matching SPIs between PCAP packets and active gateway SAs.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {matchedSpis.map((spi, i) => (
                      <span
                        key={i}
                        className="rounded border border-teal-300 bg-teal-50 px-2 py-0.5 font-mono text-[11px] font-semibold text-teal-800"
                      >
                        {spi}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {unmatchedPcap.length > 0 && (
                <div>
                    <span className="mb-1 block text-[11px] font-semibold text-stone-600">
                    Unmatched PCAP SPIs ({unmatchedPcap.length}):
                  </span>
                  <div className="truncate font-mono text-[11px] text-stone-500" title={unmatchedPcap.join(', ')}>
                    {unmatchedPcap.slice(0, 4).join(', ')}
                    {unmatchedPcap.length > 4 ? ` (+${unmatchedPcap.length - 4} more)` : ''}
                  </div>
                </div>
              )}

              <div className="border-t border-stone-100 pt-2">
                <span className="mb-1 block text-[11px] font-semibold text-stone-600">
                  Technical Evidence &amp; Justification:
                </span>
                <p className="text-xs leading-relaxed text-stone-600">
                  {isConfirmed
                    ? 'Exact normalized hex SPI match established between observed ESP packets and active gateway Child SA.'
                    : 'No cryptographic correspondence could be verified with current gateway state.'}
                </p>
              </div>

              {gatewayTelemetry.evidence && gatewayTelemetry.evidence.length > 0 && (
                <div className="border-t border-stone-100 pt-2">
                  <span className="mb-1 block text-[10px] font-semibold uppercase text-stone-400">
                    Audit Trail:
                  </span>
                  <ul className="list-inside list-disc space-y-0.5 font-mono text-[11px] text-stone-600">
                    {gatewayTelemetry.evidence.slice(0, 3).map((evi, i) => (
                      <li key={i}>{evi}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>

          <div className="border-t border-stone-200 bg-stone-50 px-4 py-2 text-[11px] text-stone-400">
            Deterministic hex comparison only. No heuristic guessing.
          </div>
        </div>

      </div>

    </div>
  );
};
