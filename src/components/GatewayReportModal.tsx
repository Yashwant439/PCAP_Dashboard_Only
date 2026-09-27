import React, { useState, useEffect } from 'react';
import {
  X,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Download,
  FileDown,
  Copy,
  Check,
  RefreshCw,
  Server,
  Activity,
  AlertTriangle,
  Info,
  Clock,
  Key,
  Sparkles,
} from 'lucide-react';
import { GatewayAiReport, GatewaySecurityReport, fetchGatewayReport, generateGatewayAiReport } from '../utils/gatewayClient';
import { downloadGatewayReportPdf } from '../utils/gatewayPdf';

interface GatewayReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  gatewayId: string | null;
  gatewayName?: string;
}

export const GatewayReportModal: React.FC<GatewayReportModalProps> = ({
  isOpen,
  onClose,
  gatewayId,
  gatewayName,
}) => {
  const [report, setReport] = useState<GatewaySecurityReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [aiReport, setAiReport] = useState<GatewayAiReport | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && gatewayId) {
      loadReport(gatewayId);
    } else {
      setReport(null);
      setError(null);
      setAiReport(null);
      setAiError(null);
    }
  }, [isOpen, gatewayId]);

  const loadReport = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchGatewayReport(id);
      setReport(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch gateway security report');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  const generateMarkdown = (): string => {
    if (!report) return '';
    const { gateway, telemetry, securityAssessment, reportGeneratedAt } = report;

    const findingsMd = securityAssessment.findings
      .map(
        (f) =>
          `- **[${f.severity.toUpperCase()}] ${f.category}**: \`${f.value || 'N/A'}\` — ${f.detail}`
      )
      .join('\n');

    const limitationsMd = securityAssessment.limitations
      .map((l) => `- ${l}`)
      .join('\n');

    const recommendationMd = securityAssessment.configurationRecommendations
      .map((item) => `| ${item.setting} | ${item.current} | ${item.recommended} | ${item.basis} |`)
      .join('\n');

    const ikeMd =
      telemetry.ikeRecords.length > 0
        ? telemetry.ikeRecords
            .map(
              (r, i) =>
                `### IKE SA #${i + 1} (${r.name || 'Unnamed'})\n` +
                `- **Version:** ${r.version || 'IKEv2'}\n` +
                `- **Encr / Integ / PRF:** \`${r.encr || 'N/A'}\` / \`${r.integ || 'N/A'}\` / \`${r.prf || 'N/A'}\`\n` +
                `- **DH Group:** \`${r.dh || 'N/A'}\`\n` +
                `- **Initiator SPI:** \`${r.initiator_spi || 'N/A'}\` | **Responder SPI:** \`${r.responder_spi || 'N/A'}\`\n` +
                `- **Endpoints:** \`${r.local_host || 'N/A'}\` -> \`${r.remote_host || 'N/A'}\``
            )
            .join('\n\n')
        : '_No active IKE SAs observed at time of report._';

    const childMd =
      telemetry.childRecords.length > 0
        ? telemetry.childRecords
            .map(
              (r, i) =>
                `### Child SA #${i + 1} (${r.name || 'Unnamed'})\n` +
                `- **Protocol / Mode:** \`${r.protocol || 'ESP'}\` / \`${r.mode || 'Not determinable'}\`\n` +
                `- **Inbound SPI:** \`${r.inbound_spi || r.spi || 'N/A'}\` | **Outbound SPI:** \`${r.outbound_spi || 'N/A'}\`\n` +
                `- **Cipher / Integrity:** \`${r.encr || 'N/A'}\` / \`${r.integ || 'N/A'}\`\n` +
                `- **Traffic selectors:** \`${r.local_ts || 'Not determinable'}\` -> \`${r.remote_ts || 'Not determinable'}\`\n` +
                `- **Gateway-reported rekey in / expires in (seconds):** \`${r.rekey_time ?? 'Not determinable'}\` / \`${r.life_time ?? 'Not determinable'}\`\n` +
                `- **Inbound / outbound replay window:** \`${r.replay_window_in ?? 'Not determinable'}\` / \`${r.replay_window_out ?? 'Not determinable'}\` packets\n` +
                `- **Inbound / outbound ESN:** \`${r.esn_in ?? r.esn ?? 'Not determinable'}\` / \`${r.esn_out ?? r.esn ?? 'Not determinable'}\`\n` +
                `- **Traffic:** In: ${r.packets_in ?? 0} pkts (${r.bytes_in ?? 0} B) | Out: ${r.packets_out ?? 0} pkts (${r.bytes_out ?? 0} B)`
            )
            .join('\n\n')
        : '_No active Child SAs observed at time of report._';

    return `# Gateway Security Assessment Report: ${gateway.display_name}
**Report Type:** Mode 2 — Enrolled Gateway Security Audit
**Gateway ID:** \`${gateway.gateway_id}\`
**Gateway Type:** \`${gateway.gateway_type}\` (${gateway.telemetry_adapter})
**Report Snapshot Timestamp:** ${reportGeneratedAt} (UTC)
**Telemetry Collected At:** ${telemetry.collectedAt || 'N/A'}
**Evidence Source:** Gateway Telemetry (StrongSwan / VICI / swanctl)

---

## 1. Gateway Status & Connectivity
- **Status:** ${gateway.status}
- **Agent Version:** ${gateway.agent_version || 'Unknown'}
- **Active IKE SAs:** ${gateway.active_ike_sa_count}
- **Active Child SAs:** ${gateway.active_child_sa_count}
- **Last Seen:** ${gateway.last_seen_at || 'Never'}

---

## 2. Security Assessment Findings
**Verified Score:** ${securityAssessment.score.value}/100 (${securityAssessment.score.rating})
**Evidence Coverage:** ${securityAssessment.score.evidenceCoveragePercent}% (${securityAssessment.score.status})
**Scoring Method:** ${securityAssessment.score.method}

${findingsMd || '_No cryptographic findings evaluated._'}

---

## 3. Configuration Hardening Recommendations
| Setting | Current | Recommended | Basis |
| --- | --- | --- | --- |
${recommendationMd}

---

## 4. Active IKE Security Associations
${ikeMd}

---

## 5. Active Child Security Associations (ESP)
${childMd}

---

## 6. Scope & Limitations
${limitationsMd}

---
*Generated by VPN/PCAP Analyzer Gateway Management System — Smart India Hackathon 2026*
`;
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(generateMarkdown());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadMarkdown = () => {
    const md = generateMarkdown();
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gateway_security_report_${gatewayId || 'gw'}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJson = () => {
    if (!report) return;
    const json = JSON.stringify(report, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gateway_security_report_${gatewayId || 'gw'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleGenerateAiReport = async () => {
    if (!gatewayId) return;
    setAiLoading(true);
    setAiError(null);
    try {
      setAiReport(await generateGatewayAiReport(gatewayId));
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'AI narrative generation failed.');
    } finally {
      setAiLoading(false);
    }
  };

  const handleDownloadPdf = () => {
    if (!report) return;
    downloadGatewayReportPdf(report, aiReport);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-white border border-slate-200 rounded-xl shadow-xl flex flex-col overflow-hidden text-slate-800">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-white">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-50 border border-blue-200 text-blue-600">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold text-slate-900">Gateway Security Assessment Report</h2>
                <span className="px-2 py-0.5 text-xs font-mono font-medium rounded bg-blue-50 text-blue-700 border border-blue-200">
                  MODE 2 — GATEWAY ONLY
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                {gatewayName || report?.gateway.display_name || gatewayId} &bull; Immutable Snapshot
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {loading && (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-500">
              <RefreshCw className="w-6 h-6 animate-spin text-blue-600" />
              <p className="text-sm">Fetching and evaluating gateway telemetry snapshot...</p>
            </div>
          )}

          {error && !loading && (
            <div className="p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-red-500" />
              <div>
                <p className="text-sm font-semibold">Report Generation Error</p>
                <p className="text-xs mt-1 text-red-600">{error}</p>
                <button
                  onClick={() => gatewayId && loadReport(gatewayId)}
                  className="mt-3 px-3 py-1 bg-red-100 hover:bg-red-200 border border-red-300 rounded-md text-xs font-medium text-red-800 transition-colors"
                >
                  Retry Report
                </button>
              </div>
            </div>
          )}

          {report && !loading && (
            <>
              {/* Snapshot Info Card */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 p-4 rounded-lg bg-slate-50 border border-slate-200">
                <div>
                  <span className="text-[11px] font-medium uppercase text-slate-500">Gateway Status</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span
                      className={`inline-block w-2 h-2 rounded-full ${
                        report.gateway.status === 'CONNECTED'
                          ? 'bg-emerald-500'
                          : report.gateway.status === 'STALE'
                          ? 'bg-amber-500'
                          : 'bg-slate-400'
                      }`}
                    />
                    <span className="text-sm font-semibold text-slate-900">{report.gateway.status}</span>
                  </div>
                </div>

                <div>
                  <span className="text-[11px] font-medium uppercase text-slate-500">Telemetry Adapter</span>
                  <p className="text-sm font-semibold text-slate-900 mt-1 font-mono">
                    {report.telemetry.adapter}
                  </p>
                </div>

                <div>
                  <span className="text-[11px] font-medium uppercase text-slate-500">Active SAs (IKE / Child)</span>
                  <p className="text-sm font-semibold text-slate-900 mt-1">
                    {report.gateway.active_ike_sa_count} IKE / {report.gateway.active_child_sa_count} Child
                  </p>
                </div>

                <div>
                  <span className="text-[11px] font-medium uppercase text-slate-500">Snapshot Timestamp</span>
                  <p className="text-xs text-slate-700 mt-1 font-mono">
                    {report.reportGeneratedAt} UTC
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-[180px_1fr] gap-4 p-4 rounded-lg bg-white border border-slate-200">
                <div>
                  <span className="text-[11px] font-semibold uppercase text-slate-500">Verified Score</span>
                  <div className="flex items-baseline gap-1 mt-1">
                    <strong className="text-3xl text-slate-900">{report.securityAssessment.score.value}</strong>
                    <span className="text-sm text-slate-500">/ 100</span>
                  </div>
                  <div className="text-xs font-medium text-slate-600">{report.securityAssessment.score.rating} · {report.securityAssessment.score.status}</div>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-xs text-slate-600"><span>Evidence coverage</span><strong>{report.securityAssessment.score.evidenceCoveragePercent}%</strong></div>
                  <div className="h-2 bg-slate-100 rounded overflow-hidden"><div className="h-full bg-cyan-700" style={{ width: `${report.securityAssessment.score.evidenceCoveragePercent}%` }} /></div>
                  <p className="text-[11px] text-slate-500">Unknown controls earn no points; they are not treated as confirmed vulnerabilities.</p>
                </div>
              </div>

              {aiError && <div className="p-3 rounded bg-amber-50 border border-amber-200 text-xs text-amber-800">{aiError}</div>}
              {aiReport && (
                <div className="p-4 rounded-lg bg-cyan-50 border border-cyan-200 space-y-2">
                  <div className="text-xs font-semibold uppercase text-cyan-900">AI-assisted narrative · {aiReport.model}</div>
                  <p className="text-sm text-slate-800">{aiReport.narrative.executive_summary}</p>
                  <p className="text-xs text-slate-600">{aiReport.narrative.technical_interpretation}</p>
                  <p className="text-[11px] text-cyan-900">AI prose does not change deterministic findings, scores, or recommendations.</p>
                </div>
              )}

              {/* Security Findings Section */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-blue-600" />
                    Cryptographic & Protocol Evaluation
                  </h3>
                  <div className="flex items-center gap-2">
                    {report.securityAssessment.findings.filter((f) => f.severity === 'Critical').length > 0 && (
                      <span className="px-2 py-0.5 text-xs font-medium rounded bg-red-50 text-red-700 border border-red-200">
                        {report.securityAssessment.findings.filter((f) => f.severity === 'Critical').length} Critical
                      </span>
                    )}
                    {report.securityAssessment.findings.filter((f) => f.severity === 'High').length > 0 && (
                      <span className="px-2 py-0.5 text-xs font-medium rounded bg-amber-50 text-amber-700 border border-amber-200">
                        {report.securityAssessment.findings.filter((f) => f.severity === 'High').length} High
                      </span>
                    )}
                    <span className="px-2 py-0.5 text-xs font-medium rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                      {report.securityAssessment.findings.filter((f) => f.severity === 'Pass').length} Pass
                    </span>
                  </div>
                </div>

                {report.securityAssessment.findings.length === 0 ? (
                  <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-center text-slate-500 text-xs">
                    No conclusive security findings are available. Review the evidence and limitations below.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {report.securityAssessment.findings.map((f, idx) => {
                      const isCritical = f.severity === 'Critical';
                      const isHigh = f.severity === 'High';

                      return (
                        <div
                          key={idx}
                          className={`p-3.5 rounded-lg border flex items-start justify-between gap-4 ${
                            isCritical
                              ? 'bg-red-50/40 border-red-200'
                              : isHigh
                              ? 'bg-amber-50/40 border-amber-200'
                              : 'bg-emerald-50/40 border-emerald-200'
                          }`}
                        >
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span
                                className={`px-1.5 py-0.5 text-[10px] font-semibold uppercase rounded ${
                                  isCritical
                                    ? 'bg-red-600 text-white'
                                    : isHigh
                                    ? 'bg-amber-600 text-white'
                                    : 'bg-emerald-600 text-white'
                                }`}
                              >
                                {f.severity}
                              </span>
                              <span className="text-xs font-mono font-semibold text-slate-800">
                                {f.category}
                              </span>
                              {f.value && (
                                <span className="text-xs font-mono bg-white px-2 py-0.5 rounded text-slate-700 border border-slate-200">
                                  {f.value}
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-slate-600">{f.detail}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-700">Configuration Hardening Matrix</h3>
                <div className="overflow-x-auto border border-slate-200 rounded-lg">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-50 text-slate-600">
                      <tr><th className="p-2">Setting</th><th className="p-2">Observed</th><th className="p-2">Recommended</th><th className="p-2">Basis</th></tr>
                    </thead>
                    <tbody>
                      {report.securityAssessment.configurationRecommendations.map((item) => {
                        const note = aiReport?.narrative.recommendation_notes.find((entry) => entry.id === item.id)?.note;
                        return <tr key={item.id} className="border-t border-slate-100 align-top">
                          <td className="p-2 font-medium text-slate-800">{item.setting}</td>
                          <td className="p-2 font-mono text-slate-700">{item.current}</td>
                          <td className="p-2 text-slate-800">{item.recommended}</td>
                          <td className="p-2 text-slate-600">{item.basis}{note ? ` ${note}` : ''}</td>
                        </tr>;
                      })}
                    </tbody>
                  </table>
                </div>
                <p className="text-[11px] text-slate-500">Recommendations are deterministic; AI only adds explanations tied to these rows.</p>
              </div>

              {/* Active IKE SAs */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                  <Key className="w-4 h-4 text-purple-600" />
                  IKE Security Associations ({report.telemetry.ikeRecords.length})
                </h3>
                {report.telemetry.ikeRecords.length === 0 ? (
                  <p className="text-xs text-slate-500 italic p-3 rounded-lg bg-slate-50 border border-slate-200">
                    No active IKE SAs reported in the latest telemetry snapshot.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {report.telemetry.ikeRecords.map((ike, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs"
                      >
                        <div className="flex items-center justify-between text-slate-700 font-mono">
                          <span className="font-semibold text-purple-700">{String(ike.name || `IKE SA #${idx + 1}`)}</span>
                          <span className="text-slate-500">{String(ike.version || 'IKEv2')}</span>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-slate-700 font-mono text-xs">
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-sans">ENCR:</span>
                            <span className="text-slate-900 font-medium">{String(ike.encr || 'N/A')}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-sans">INTEG:</span>
                            <span className="text-slate-900 font-medium">{String(ike.integ || 'N/A')}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-sans">PRF:</span>
                            <span className="text-slate-900 font-medium">{String(ike.prf || 'N/A')}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-sans">DH GROUP:</span>
                            <span className="text-slate-900 font-medium">{String(ike.dh || 'N/A')}</span>
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-xs text-slate-500 font-mono border-t border-slate-200 pt-1.5">
                          <span>Init SPI: <span className="text-slate-800">{String(ike.initiator_spi || 'N/A')}</span></span>
                          <span>Resp SPI: <span className="text-slate-800">{String(ike.responder_spi || 'N/A')}</span></span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Active Child SAs */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-emerald-600" />
                  Child SAs / ESP Tunnels ({report.telemetry.childRecords.length})
                </h3>
                {report.telemetry.childRecords.length === 0 ? (
                  <p className="text-xs text-slate-500 italic p-3 rounded-lg bg-slate-50 border border-slate-200">
                    No active Child SAs reported in the latest telemetry snapshot.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {report.telemetry.childRecords.map((child, idx) => {
                      const evidence = report.securityAssessment.childSaEvidence?.[idx];
                      const evidenceValue = (field: string) => {
                        const item = evidence?.fields[field];
                        return item?.status === 'CONFIRMED' && item.value !== null
                          ? String(item.value)
                          : 'Not determinable';
                      };

                      return (<div
                        key={idx}
                        className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs"
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="font-semibold text-blue-700">{String(child.name || `Child SA #${idx + 1}`)}</span>
                          <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 text-xs">
                            {String(child.protocol || 'ESP')} &bull; {evidenceValue('mode')}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-slate-700 font-mono text-xs">
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-sans">INBOUND SPI:</span>
                            <span className="text-slate-900 font-medium">{String(child.inbound_spi || child.spi || 'N/A')}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-sans">OUTBOUND SPI:</span>
                            <span className="text-slate-900 font-medium">{String(child.outbound_spi || 'N/A')}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-sans">ENCR:</span>
                            <span className="text-slate-900 font-medium">{String(child.encr || 'N/A')}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase font-sans">INTEG:</span>
                            <span className="text-slate-900 font-medium">{String(child.integ || 'N/A')}</span>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-slate-700 font-mono text-xs border-t border-slate-200 pt-2">
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">LOCAL SELECTORS:</span>{evidenceValue('local_ts')}</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">REMOTE SELECTORS:</span>{evidenceValue('remote_ts')}</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">STATE:</span>{evidenceValue('state')}</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">CHILD-SA DH GROUP:</span>{evidenceValue('dh_group')}</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">REKEY IN (S):</span>{evidenceValue('rekey_time')}</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">EXPIRES IN (S):</span>{evidenceValue('life_time')}</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">PFS:</span>{evidenceValue('pfs')}</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">ESN IN / OUT:</span>{evidenceValue('esn_in')} / {evidenceValue('esn_out')}</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">REPLAY WINDOW IN / OUT:</span>{evidenceValue('replay_window_in')} / {evidenceValue('replay_window_out')} packets</div>
                          <div><span className="text-slate-500 block text-[10px] uppercase font-sans">INBOUND ANTI-REPLAY:</span>{evidenceValue('replay_protection')}</div>
                        </div>
                        {(child.packets_in !== undefined || child.bytes_in !== undefined) && (
                          <div className="flex items-center justify-between text-xs text-slate-500 font-mono border-t border-slate-200 pt-1.5">
                            <span>In: {Number(child.packets_in || 0).toLocaleString()} pkts ({Number(child.bytes_in || 0).toLocaleString()} B)</span>
                            <span>Out: {Number(child.packets_out || 0).toLocaleString()} pkts ({Number(child.bytes_out || 0).toLocaleString()} B)</span>
                          </div>
                        )}
                      </div>);
                    })}
                  </div>
                )}
              </div>

              {/* Scope & Limitations */}
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 uppercase tracking-wider">
                  <Info className="w-4 h-4 text-blue-600" />
                  Audit Scope & Formal Limitations
                </div>
                <ul className="space-y-1.5 text-xs text-slate-600">
                  {report.securityAssessment.limitations.map((lim, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="text-blue-500 select-none">&bull;</span>
                      <span>{lim}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex flex-wrap items-center justify-between gap-2 px-6 py-3.5 border-t border-slate-200 bg-slate-50">
          <div className="text-xs text-slate-500 font-mono">
            {report?.reportGeneratedAt ? `Snapshot: ${report.reportGeneratedAt}` : ''}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleGenerateAiReport}
              disabled={!report || loading || aiLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-cyan-900 bg-cyan-50 hover:bg-cyan-100 border border-cyan-300 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <Sparkles className="w-4 h-4" />
              {aiLoading ? 'Generating...' : aiReport ? 'Refresh AI Narrative' : 'Generate AI Narrative'}
            </button>
            <button
              onClick={handleDownloadPdf}
              disabled={!report || loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <FileDown className="w-4 h-4" />
              Download PDF
            </button>
            <button
              onClick={handleCopy}
              disabled={!report || loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 transition-colors disabled:opacity-50 cursor-pointer"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4 text-slate-500" />}
              {copied ? 'Copied' : 'Copy MD'}
            </button>
            <button
              onClick={handleDownloadMarkdown}
              disabled={!report || loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <Download className="w-4 h-4 text-slate-500" />
              Download Markdown
            </button>
            <button
              onClick={handleDownloadJson}
              disabled={!report || loading}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 shadow-xs transition-colors disabled:opacity-50 cursor-pointer"
            >
              <Download className="w-4 h-4" />
              Export JSON
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
