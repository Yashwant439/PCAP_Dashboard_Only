import React, { useEffect, useRef, useState } from 'react';
import {
  X,
  Download,
  FileDown,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  FileText,
  FileJson,
  Wifi,
  Sparkles,
} from 'lucide-react';
import { CaptureAiNarrative, generateCaptureAiNarrative } from '../utils/reportClient';
import { AssessmentReportKind, buildAssessmentSnapshot, buildReportSections, formatAssessmentMarkdown } from '../utils/assessmentReport';
import { AiPrediction, IkeSecurityAssociation, SecurityScorecard, VpnCaptureScenario } from '../types';
import { CombinedAnalysisPanel } from './CombinedAnalysisPanel';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  scenario: VpnCaptureScenario;
  scorecard: SecurityScorecard;
  prediction: AiPrediction;
  initialKind?: AssessmentReportKind;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  scenario,
  scorecard,
  prediction,
  initialKind = 'EXECUTIVE',
}) => {
  const [reportType, setReportType] = useState<AssessmentReportKind>(initialKind);
  const [copied, setCopied] = useState(false);
  const [aiNarrative, setAiNarrative] = useState<CaptureAiNarrative | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const requestedScenario = useRef<string | null>(null);
  const currentScenario = useRef(scenario.id);
  currentScenario.current = scenario.id;

  useEffect(() => { if (isOpen) setReportType(initialKind); }, [isOpen, initialKind, scenario.id]);

  // Deterministic reports are ready immediately. Enrich the current capture
  // once when the report opens; a provider failure leaves both reports usable.
  useEffect(() => {
    if (!isOpen || requestedScenario.current === scenario.id) return;
    requestedScenario.current = scenario.id;
    setAiNarrative(null);
    setAiError(null);
    setAiLoading(true);
    generateCaptureAiNarrative(scenario, scorecard, prediction)
      .then((result) => { if (currentScenario.current === scenario.id) setAiNarrative(result); })
      .catch((error: unknown) => { if (currentScenario.current === scenario.id) setAiError(error instanceof Error ? error.message : 'AI narrative generation failed.'); })
      .finally(() => { if (currentScenario.current === scenario.id) setAiLoading(false); });
  }, [isOpen, scenario, scorecard, prediction]);

  if (!isOpen) return null;

  const snapshot = buildAssessmentSnapshot(scenario, scorecard, prediction);
  const reportSections = buildReportSections(reportType, scenario, scorecard, prediction, aiNarrative?.narrative);

  const handleGenerateAiNarrative = async () => {
    setAiLoading(true); setAiError(null);
    try { setAiNarrative(await generateCaptureAiNarrative(scenario, scorecard, prediction)); }
    catch (error) { setAiError(error instanceof Error ? error.message : 'AI narrative generation failed.'); }
    finally { setAiLoading(false); }
  };

  const handleCopyMarkdown = () => {
    const content = generateMarkdownReport();
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadMarkdown = () => {
    const content = generateMarkdownReport();
    const blob = new Blob([content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IPsec_Security_Report_${scenario.id}_${reportType.toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJson = () => {
    const exportData = {
      reportType: 'IPSEC_SECURITY_AUDIT_EVIDENCE',
      generatedAt: new Date().toISOString(),
      scenario: {
        id: scenario.id,
        name: scenario.name,
        organization: scenario.organization,
        description: scenario.description,
        sa: scenario.sa,
        features: scenario.features,
        packetCount: scenario.packets.length,
        gatewayTelemetry: scenario.gatewayTelemetry ?? null,
        correlation: scenario.correlation ?? null,
      },
      scorecard,
      prediction,
      aiNarrative,
      assessment: snapshot,
      sections: reportSections,
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IPsec_Security_Audit_${scenario.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPdf = () => {
    const doc = new jsPDF({ unit: 'mm', format: 'a4' });
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 14;
    let y = 16;

    const section = (title: string) => {
      if (y > pageHeight - 22) {
        doc.addPage();
        y = margin;
      }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(12);
      doc.setTextColor(25, 50, 72);
      doc.text(title, margin, y);
      y += 7;
    };
    const paragraph = (text: string) => {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(45, 55, 65);
      const lines = doc.splitTextToSize(text, pageWidth - margin * 2);
      if (y + lines.length * 4.5 > pageHeight - margin) {
        doc.addPage();
        y = margin;
      }
      doc.text(lines, margin, y);
      y += lines.length * 4.5 + 4;
    };
    const table = (head: string[], body: string[][]) => {
      if (y > pageHeight - 25) {
        doc.addPage();
        y = margin;
      }
      autoTable(doc, {
        startY: y,
        head: [head],
        body: body.length ? body : [["No data", ...head.slice(1).map(() => "")]],
        margin: { left: margin, right: margin },
        styles: { font: 'helvetica', fontSize: 7.5, cellPadding: 2, overflow: 'linebreak' },
        headStyles: { fillColor: [28, 66, 83], textColor: 255 },
        alternateRowStyles: { fillColor: [245, 248, 249] },
      });
      y = (doc as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY ?? y + 12;
      y += 7;
    };

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(17);
    doc.setTextColor(24, 54, 70);
    doc.text('IPsec Security Assessment Report', margin, y);
    y += 8;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(75, 85, 95);
    doc.text(`${scenario.name} | ${reportType} | ${new Date().toISOString()}`, margin, y);
    y += 9;

    section('Assessment scores');
    paragraph(`Security ${scorecard.totalScore}/100 | Observed risk ${snapshot.riskScore === null ? 'Not rated' : `${snapshot.riskScore}/100`} | Evidence coverage ${scorecard.evidenceCoveragePercent}% (${scorecard.assessmentStatus})`);
    const barWidth = pageWidth - margin * 2;
    const scoreBar = (label: string, value: number, color: [number, number, number]) => {
      doc.setFontSize(8);
      doc.text(`${label}: ${value}%`, margin, y);
      y += 2;
      doc.setFillColor(230, 235, 238);
      doc.rect(margin, y, barWidth, 4, 'F');
      doc.setFillColor(...color);
      doc.rect(margin, y, barWidth * Math.max(0, Math.min(100, value)) / 100, 4, 'F');
      y += 8;
    };
    scoreBar('Evidence-adjusted score', scorecard.totalScore, [25, 132, 105]);
    scoreBar('Evidence coverage', scorecard.evidenceCoveragePercent, [42, 115, 165]);

    for (const reportSection of reportSections) {
      section(reportSection.title);
      for (const line of reportSection.lines || []) paragraph(line);
      if (reportSection.table) table(reportSection.table.headers, reportSection.table.rows);
    }

    const totalPages = doc.getNumberOfPages();
    for (let page = 1; page <= totalPages; page += 1) {
      doc.setPage(page);
      doc.setFontSize(7);
      doc.setTextColor(120, 130, 138);
      doc.text('Unknown controls are not treated as secure; findings are based on the displayed evidence.', margin, pageHeight - 7);
      doc.text(`${page}/${totalPages}`, pageWidth - margin, pageHeight - 7, { align: 'right' });
    }
    doc.save(`IPsec_Security_Report_${scenario.id}_${reportType.toLowerCase()}.pdf`);
  };

  const generateMarkdownReport = () => formatAssessmentMarkdown(reportType, scenario, reportSections);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-stone-950/55 p-4 backdrop-blur-sm animate-fade-in">
      <div className="report-canvas flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-stone-300 shadow-[0_28px_80px_rgba(28,25,23,0.42)]">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-stone-200 bg-white p-4 sm:p-5">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-teal-700 text-white shadow-md shadow-teal-900/20">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-stone-900">Security assessment report</h2>
                <span className="rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[10px] font-bold tracking-wide text-amber-800">EVIDENCE-BOUND</span>
              </div>
              <p className="text-xs text-stone-500">
                Packet evidence, rule-engine findings, and optional AI narrative
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View Switcher */}
            <div className="inline-flex rounded-lg border border-stone-300 bg-stone-100 p-0.5">
              <button
                id="btn-report-exec"
                onClick={() => setReportType('EXECUTIVE')}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                  reportType === 'EXECUTIVE'
                    ? 'bg-stone-900 text-white shadow-sm'
                    : 'text-stone-500 hover:bg-white hover:text-stone-900'
                }`}
              >
                Executive
              </button>
              <button
                id="btn-report-tech"
                onClick={() => setReportType('TECHNICAL')}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                  reportType === 'TECHNICAL'
                    ? 'bg-stone-900 text-white shadow-sm'
                    : 'text-stone-500 hover:bg-white hover:text-stone-900'
                }`}
              >
                Technical
              </button>
              {scenario.gatewayTelemetry && (
                <button
                  id="btn-report-combined"
                  onClick={() => setReportType('COMBINED')}
                  className={`px-3 py-1 text-xs font-semibold rounded-md transition-colors cursor-pointer flex items-center gap-1 ${
                    reportType === 'COMBINED'
                      ? 'bg-stone-900 text-white shadow-sm'
                      : 'text-stone-500 hover:bg-white hover:text-stone-900'
                  }`}
                >
                  <Wifi className="w-3 h-3" />
                  <span>Mode 3 Combined</span>
                </button>
              )}
            </div>

            <button
              onClick={onClose}
              className="ml-2 flex h-8 w-8 items-center justify-center rounded-lg bg-stone-100 text-stone-500 transition-colors hover:bg-stone-200 hover:text-stone-900 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="report-canvas flex-1 space-y-6 overflow-y-auto p-6 text-xs text-stone-700">
          {reportType === 'COMBINED' && scenario.gatewayTelemetry ? (
            /* Mode 3 Combined Analysis View */
            <div className="space-y-6">
              <CombinedAnalysisPanel
                sa={scenario.sa}
                gatewayTelemetry={scenario.gatewayTelemetry}
                correlation={scenario.correlation}
                packetCount={scenario.packets.length}
              />
            </div>
          ) : reportType === 'EXECUTIVE' ? (
            /* Executive Report View */
            <div className="space-y-6">
              
              {/* Executive assessment brief */}
              <section className="overflow-hidden rounded-2xl border border-stone-300 bg-white shadow-[0_12px_30px_rgba(68,64,60,0.08)]">
                <div className="grid lg:grid-cols-[205px_1fr]">
                  <div className="flex flex-col items-center justify-center border-b border-teal-950/30 bg-[#163733] p-5 lg:border-b-0 lg:border-r">
                    <div
                      className="grid h-28 w-28 place-items-center rounded-full p-2"
                      style={{ background: `conic-gradient(${scorecard.rating === 'Not Rated' ? '#a8a29e' : scorecard.totalScore >= 70 ? '#5eead4' : '#fbbf24'} ${scorecard.totalScore}%, #315650 0)` }}
                    >
                      <div className="grid h-full w-full place-items-center rounded-full bg-[#0d2521] text-center">
                        <div><div className="text-3xl font-black leading-none text-white">{scorecard.totalScore}</div><div className="mt-1 text-[10px] font-semibold uppercase tracking-wider text-teal-100/55">security score / 100</div></div>
                      </div>
                    </div>
                    <span className={`mt-3 rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-wider ${scorecard.rating === 'Not Rated' ? 'border-stone-500 bg-stone-700 text-stone-100' : scorecard.totalScore >= 70 ? 'border-teal-300 bg-teal-100 text-teal-900' : 'border-amber-300 bg-amber-100 text-amber-950'}`}>
                      {scorecard.rating} posture
                    </span>
                  </div>

                  <div className="p-5">
                    <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-teal-700">Executive assessment brief</p>
                        <h3 className="mt-1 text-xl font-bold text-stone-900">{scenario.name}</h3>
                        <p className="mt-1 max-w-2xl text-xs leading-relaxed text-stone-500">{scenario.description}</p>
                      </div>
                      <span className="w-fit rounded-md border border-stone-300 bg-stone-100 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-stone-700">{scorecard.assessmentStatus}</span>
                    </div>
                    <div className="mt-5 grid gap-2 sm:grid-cols-4">
                      <div className="rounded-lg border border-stone-200 bg-stone-50 p-3"><p className="text-[10px] font-bold uppercase tracking-wider text-stone-500">Evidence coverage</p><p className="mt-1 text-base font-bold text-stone-900">{scorecard.evidenceCoveragePercent}%</p><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-stone-200"><div className="h-full rounded-full bg-teal-600" style={{ width: `${scorecard.evidenceCoveragePercent}%` }} /></div></div>
                      <div className="rounded-lg border border-stone-200 bg-stone-50 p-3"><p className="text-[10px] font-bold uppercase tracking-wider text-stone-500">Risk score</p><p className="mt-1 text-base font-bold text-stone-900">{snapshot.riskScore === null ? 'Not rated' : `${snapshot.riskScore}/100`}</p><p className="mt-1 text-[10px] text-stone-500">Observed penalties</p></div>
                      <div className="rounded-lg border border-stone-200 bg-stone-50 p-3"><p className="text-[10px] font-bold uppercase tracking-wider text-stone-500">AI confidence</p><p className="mt-1 text-base font-bold text-stone-900">{snapshot.aiConfidenceScore === null ? 'Unavailable' : `${snapshot.aiConfidenceScore}%`}</p><p className="mt-1 text-[10px] text-stone-500">{snapshot.aiConfidenceModels} crypto models</p></div>
                      <div className="rounded-lg border border-stone-200 bg-stone-50 p-3"><p className="text-[10px] font-bold uppercase tracking-wider text-stone-500">Packet evidence</p><p className="mt-1 text-base font-bold text-stone-900">{scenario.packets.length} packets</p><p className="mt-1 text-[10px] text-stone-500">{scenario.sa.ikeVersion} · {scenario.sa.operationalMode}</p></div>
                    </div>
                  </div>
                </div>
              </section>

              <div className="grid gap-3 lg:grid-cols-[1.35fr_0.65fr]">
                <section className="rounded-xl border border-stone-200 bg-white p-4">
                  <h4 className="flex items-center gap-2 text-sm font-bold text-stone-900"><ShieldCheck className="h-4 w-4 text-teal-600" /> Analyst reading</h4>
                  <p className="mt-2 leading-relaxed text-stone-600">This IPsec capture is assessed for <strong className="text-stone-900">{scenario.organization}</strong>. The score reflects observed configuration evidence only: {scorecard.assessmentStatus !== 'COMPLETE' ? 'the assessment remains partial, so unobserved controls are neither presumed secure nor reported as vulnerabilities.' : scorecard.findings.some((finding) => finding.severity === 'Critical' || finding.severity === 'High') ? 'high-risk configuration findings require review before this deployment is trusted.' : 'no high-risk finding was identified in the assessed fields.'}</p>
                </section>
                <aside className="rounded-xl border border-amber-200 bg-amber-50 p-4">
                  <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-amber-800">Traffic inference</p>
                  <p className="mt-2 text-sm font-bold text-stone-900">{prediction.predictedClass} <span className="text-xs font-medium text-amber-800">· {snapshot.trafficMatchScore === null ? 'insufficient evidence' : `${snapshot.trafficMatchScore}% relative pattern match`}</span></p>
                  <p className="mt-2 leading-relaxed text-amber-950/75">Estimated from packet size and timing. ESP payloads remain encrypted; this is not decrypted content or confirmed ground truth.</p>
                </aside>
              </div>

              <div className="rounded-xl border border-violet-200 bg-violet-50/70 p-4">
                <div className="flex items-start justify-between gap-3"><div><div className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-violet-700" /><h4 className="text-sm font-bold text-violet-950">AI report narrative</h4><span className="rounded bg-white px-1.5 py-0.5 text-[10px] font-semibold text-violet-700 ring-1 ring-violet-200">OPTIONAL</span></div><p className="mt-1 text-xs text-violet-950/65">Creates readable executive and technical prose from the report evidence. It cannot change the score, findings, or packet evidence.</p></div><button onClick={handleGenerateAiNarrative} disabled={aiLoading} className="shrink-0 rounded-lg bg-violet-700 px-3 py-1.5 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-violet-800 disabled:opacity-60">{aiLoading ? 'Generating…' : aiNarrative ? 'Refresh narrative' : 'Generate narrative'}</button></div>
                {aiError && <div className="mt-3 rounded-lg border border-amber-300 bg-amber-50 p-3"><p className="text-xs font-semibold text-amber-900">AI narrative unavailable</p><p className="mt-1 text-xs leading-relaxed text-amber-900/75">{aiError}</p></div>}
                {aiNarrative && <div className="mt-3 space-y-2 border-t border-violet-200 pt-3"><p className="text-xs font-semibold text-violet-900">Generated by {aiNarrative.source} · {aiNarrative.model}</p><p className="text-sm leading-relaxed text-stone-700">{aiNarrative.narrative.executive_summary}</p><details className="rounded-lg bg-white p-3 text-xs text-stone-600 ring-1 ring-violet-100"><summary className="cursor-pointer font-semibold text-stone-800">Technical interpretation</summary><p className="mt-2 leading-relaxed">{aiNarrative.narrative.technical_interpretation}</p></details></div>}
              </div>

              {/* Executive Recommendations List */}
              <div className="space-y-3">
                <h4 className="text-sm font-bold uppercase tracking-wider text-stone-900">
                  Prioritized Action Items
                </h4>
                <div className="space-y-2">
                  {scorecard.findings
                    .filter((f) => f.penalty > 0)
                    .map((f, i) => (
                      <div key={i} className="flex items-start gap-3 rounded-lg border border-stone-200 bg-white p-3 shadow-[0_2px_8px_rgba(68,64,60,0.04)]">
                        <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-amber-300 bg-amber-100 text-[10px] font-bold text-amber-900">
                          {i + 1}
                        </span>
                        <div>
                          <div className="font-bold text-stone-900">{f.threatName}</div>
                          <div className="mt-0.5 text-stone-500">{f.remediation}</div>
                        </div>
                      </div>
                    ))}
                  {snapshot.threats.length === 0 && (
                    <div className="rounded-lg border border-teal-200 bg-teal-50 p-3 font-semibold text-teal-800">
                      No observed configuration risk was scored. Review evidence gaps before making a compliance conclusion.
                    </div>
                  )}
                  {snapshot.evidenceGaps.length > 0 && (
                    <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-amber-900">
                      {snapshot.evidenceGaps.length} control{snapshot.evidenceGaps.length === 1 ? '' : 's'} need more capture or gateway evidence. These are not confirmed vulnerabilities.
                    </div>
                  )}
                </div>
              </div>

            </div>
          ) : (
            /* Technical Report View */
            <div className="space-y-6 font-mono text-xs text-stone-700">
              
              <div className="space-y-2 rounded-xl border border-teal-900 bg-[#163733] p-4 text-teal-50 shadow-[0_8px_18px_rgba(19,78,74,0.16)]">
                <div className="font-bold text-teal-300">[PROTOCOL AUDIT RECORD]</div>
                <div>Target Gateway: {scenario.packets[0]?.destIp || 'Not observed'}</div>
                <div>Initiator SPI: {scenario.sa.initiatorSpi}</div>
                <div>Responder SPI: {scenario.sa.responderSpi}</div>
                <div>Key Lifetime Window: {scenario.sa.keyLifetimeSeconds === null ? 'Not observed' : `${scenario.sa.keyLifetimeSeconds}s`}</div>
                <div>Replay Protection: {scenario.sa.replayProtection === null ? 'Not observed' : scenario.sa.replayProtection ? `ENABLED${scenario.sa.replayWindowSize ? ` (Window ${scenario.sa.replayWindowSize})` : ''}` : 'DISABLED'}</div>
              </div>

              <div className="grid gap-2 sm:grid-cols-3">
                <div className="rounded-lg border border-stone-200 bg-white p-3"><div className="text-stone-500">Security / observed risk</div><div className="mt-1 font-bold text-stone-900">{scorecard.totalScore}/100 · {snapshot.riskScore === null ? 'Not rated' : `${snapshot.riskScore}/100`}</div><div className="text-stone-500">Evidence coverage {scorecard.evidenceCoveragePercent}%</div></div>
                <div className="rounded-lg border border-stone-200 bg-white p-3"><div className="text-stone-500">AI confidence score</div><div className="mt-1 font-bold text-stone-900">{snapshot.aiConfidenceScore === null ? 'Unavailable' : `${snapshot.aiConfidenceScore}%`}</div><div className="text-stone-500">Mean across {snapshot.aiConfidenceModels} trained crypto models</div></div>
                <div className="rounded-lg border border-stone-200 bg-white p-3"><div className="text-stone-500">Metadata inference</div><div className="mt-1 font-bold text-stone-900">{prediction.predictedClass}</div><div className="text-stone-500">{snapshot.trafficMatchScore === null ? 'Insufficient ESP evidence' : `${snapshot.trafficMatchScore}% relative pattern match`}</div></div>
              </div>

              <div className="rounded-lg border border-violet-200 bg-violet-50 p-3">
                <div className="font-bold text-violet-950">AI technical interpretation</div>
                <p className="mt-1 text-violet-950/65">{aiLoading ? 'Generating from the report evidence…' : aiNarrative?.narrative.technical_interpretation || 'The deterministic technical report is ready. External AI prose is unavailable or still pending.'}</p>
              </div>

              {/* Technical Specifications */}
              <div>
                <h4 className="mb-2 font-sans font-bold text-stone-900">
                  Negotiated Security Association Transforms
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="rounded-lg border border-stone-200 bg-white p-2.5">
                    <div className="text-[10px] text-stone-500">IKE Version</div>
                    <div className="mt-1 font-bold text-stone-900">{scenario.sa.ikeVersion}</div>
                  </div>
                  <div className="rounded-lg border border-stone-200 bg-white p-2.5">
                    <div className="text-[10px] text-stone-500">Cipher</div>
                    <div className="mt-1 truncate font-bold text-stone-900">{scenario.sa.encryptionAlgorithm}</div>
                  </div>
                  <div className="rounded-lg border border-stone-200 bg-white p-2.5">
                    <div className="text-[10px] text-stone-500">DH Group</div>
                    <div className="mt-1 font-bold text-stone-900">{scenario.sa.dhGroup}</div>
                  </div>
                  <div className="rounded-lg border border-stone-200 bg-white p-2.5">
                    <div className="text-[10px] text-stone-500">PFS Status</div>
                    <div className="mt-1 font-bold text-stone-900">
                      {scenario.sa.pfsEnabled === null ? 'Not observed' : scenario.sa.pfsEnabled ? 'Enabled' : 'Disabled'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Raw Findings Data Table */}
              <div>
                <h4 className="mb-2 font-sans font-bold text-stone-900">Threat Matrix and Evidence Gaps</h4>
                <div className="overflow-x-auto rounded-lg border border-stone-200 bg-white">
                  <table className="w-full text-left">
                    <thead className="border-b border-stone-200 bg-stone-100 text-[10px] uppercase text-stone-500">
                      <tr>
                        <th className="p-2.5">Parameter</th>
                        <th className="p-2.5">Detected Value</th>
                        <th className="p-2.5">Severity</th>
                        <th className="p-2.5">Risk / evidence</th>
                        <th className="p-2.5">Score impact</th>
                        <th className="p-2.5">Remediation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-stone-100">
                      {scorecard.findings.map((f, i) => (
                        <tr key={i} className="hover:bg-amber-50/50">
                          <td className="p-2.5 font-bold text-stone-800">{f.parameter}</td>
                          <td className="p-2.5 text-stone-700">{f.detectedValue}</td>
                          <td className="p-2.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              f.severity === 'Critical' ? 'bg-rose-100 text-rose-800' : (f.severity === 'Pass' ? 'bg-teal-100 text-teal-800' : 'bg-amber-100 text-amber-900')
                            }`}>
                              {f.severity}
                            </span>
                          </td>
                          <td className="p-2.5 text-stone-500">{f.threatName}</td>
                          <td className="p-2.5 text-stone-700">{f.penalty > 0 ? `-${f.penalty}` : '0'}</td>
                          <td className="p-2.5 text-stone-700">{f.remediation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

        </div>

        {/* Modal Footer Controls */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-stone-200 bg-white p-4">
          <div className="text-xs text-stone-500">
            Exportable report format conforming to NTRO Deliverable E.
          </div>

          <div className="flex items-center gap-2">
            <button onClick={handleGenerateAiNarrative} disabled={aiLoading} className="inline-flex items-center gap-1.5 rounded-lg bg-violet-700 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-violet-800 disabled:opacity-60 cursor-pointer"><Sparkles className="w-3.5 h-3.5" /><span>{aiLoading ? 'Generating AI…' : 'AI Narrative'}</span></button>
            <button
              id="btn-download-json"
              onClick={handleDownloadJson}
              className="inline-flex items-center gap-1.5 rounded-lg border border-stone-300 bg-white px-3 py-1.5 text-xs font-semibold text-stone-700 transition-colors hover:bg-stone-100 cursor-pointer"
            >
              <FileJson className="w-3.5 h-3.5 text-amber-600" />
              <span>Export JSON</span>
            </button>

            <button
              id="btn-download-pdf"
              onClick={handleDownloadPdf}
              className="inline-flex items-center gap-1.5 rounded-lg border border-stone-300 bg-white px-3 py-1.5 text-xs font-semibold text-stone-700 transition-colors hover:bg-stone-100 cursor-pointer"
            >
              <FileDown className="w-3.5 h-3.5 text-teal-600" />
              <span>Download PDF</span>
            </button>

            <button
              id="btn-copy-report"
              onClick={handleCopyMarkdown}
              className="inline-flex items-center gap-1.5 rounded-lg border border-stone-300 bg-white px-3 py-1.5 text-xs font-semibold text-stone-700 transition-colors hover:bg-stone-100 cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-teal-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied Markdown!' : 'Copy Markdown'}</span>
            </button>

            <button
              id="btn-download-report"
              onClick={handleDownloadMarkdown}
              className="inline-flex items-center gap-1.5 rounded-lg bg-teal-700 px-3 py-1.5 text-xs font-semibold text-white shadow-sm shadow-teal-900/20 transition-colors hover:bg-teal-800 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .MD Report</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
