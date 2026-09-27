import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { GatewayAiReport, GatewaySecurityReport } from './gatewayClient';

type RGB = [number, number, number];
type GatewayRecord = Record<string, unknown>;

const palette: Record<string, RGB> = {
  ink: [27, 47, 59],
  teal: [13, 111, 107],
  blue: [43, 105, 145],
  text: [47, 59, 68],
  muted: [103, 116, 125],
  border: [218, 225, 229],
  pale: [246, 249, 250],
  critical: [166, 48, 54],
  high: [190, 91, 43],
  medium: [177, 127, 32],
  low: [47, 111, 129],
  pass: [40, 121, 88],
};

const severityColors: Record<string, RGB> = {
  Critical: palette.critical,
  High: palette.high,
  Medium: palette.medium,
  Low: palette.low,
  Pass: palette.pass,
};

const displayValue = (value: unknown, fallback = 'Not reported'): string => {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

export function downloadGatewayReportPdf(
  report: GatewaySecurityReport,
  aiReport: GatewayAiReport | null,
): void {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;
  let y = 20;
  const score = report.securityAssessment.score;
  const findings = report.securityAssessment.findings;
  const severityCounts = report.securityAssessment.charts.findingSeverityCounts;
  const aiFindingNotes = new Map((aiReport?.narrative.finding_notes ?? []).map((note) => [note.id, note.why_it_matters]));
  const aiRecommendationNotes = new Map((aiReport?.narrative.recommendation_notes ?? []).map((note) => [note.id, note.note]));

  doc.setProperties({
    title: `Gateway Security Assessment - ${report.gateway.display_name}`,
    subject: 'Point-in-time IPsec gateway security assessment',
    author: 'VPN Analyzer',
  });

  const ensureSpace = (height: number) => {
    if (y + height > pageHeight - 19) {
      doc.addPage();
      y = 21;
    }
  };

  const section = (title: string) => {
    ensureSpace(13);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10.5);
    doc.setTextColor(...palette.ink);
    doc.text(title, margin, y);
    doc.setDrawColor(...palette.border);
    doc.setLineWidth(0.35);
    doc.line(margin, y + 2, pageWidth - margin, y + 2);
    y += 9;
  };

  const paragraph = (text: string, size = 8.5) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(size);
    doc.setTextColor(...palette.text);
    const lines = doc.splitTextToSize(text, contentWidth);
    const height = lines.length * 4.2 + 3;
    ensureSpace(height);
    doc.text(lines, margin, y);
    y += height;
  };

  const callout = (label: string, text: string, accent: RGB = palette.teal) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    const lines = doc.splitTextToSize(text, contentWidth - 12);
    const height = lines.length * 4.2 + 13;
    ensureSpace(height);
    doc.setFillColor(...palette.pale);
    doc.setDrawColor(...palette.border);
    doc.roundedRect(margin, y, contentWidth, height, 1.5, 1.5, 'FD');
    doc.setFillColor(...accent);
    doc.rect(margin, y, 1.5, height, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(...accent);
    doc.text(label.toUpperCase(), margin + 6, y + 5);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(...palette.text);
    doc.text(lines, margin + 6, y + 10);
    y += height + 5;
  };

  const table = (
    headers: string[],
    rows: string[][],
    columnWidths: number[],
  ) => {
    ensureSpace(20);
    autoTable(doc, {
      startY: y,
      head: [headers],
      body: rows.length ? rows : [['No records available', ...headers.slice(1).map(() => '')]],
      margin: { left: margin, right: margin, top: 20, bottom: 19 },
      styles: {
        font: 'helvetica',
        fontSize: 7.2,
        cellPadding: 2.1,
        overflow: 'linebreak',
        valign: 'top',
        textColor: palette.text,
        lineColor: palette.border,
        lineWidth: 0.15,
      },
      headStyles: { fillColor: palette.ink, textColor: 255, fontStyle: 'bold' },
      alternateRowStyles: { fillColor: palette.pale },
      columnStyles: Object.fromEntries(columnWidths.map((cellWidth, index) => [index, { cellWidth }])),
      rowPageBreak: 'avoid',
    });
    y = ((doc as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY ?? y + 12) + 7;
  };

  const findingRows = findings.map((finding, index) => {
    const note = aiFindingNotes.get(`F${index + 1}`);
    return [
      {
        content: finding.severity,
        styles: {
          fillColor: severityColors[finding.severity] ?? palette.muted,
          textColor: 255,
          fontStyle: 'bold' as const,
        },
      },
      `${finding.category}\nObserved: ${finding.value || 'Not determinable'}`,
      finding.detail,
      note || (aiReport ? 'No additional interpretation returned.' : 'AI interpretation not generated; see verified assessment.'),
    ];
  });

  const rowCount = (severity: string) => severityCounts[severity] ?? 0;
  const criticalCount = rowCount('Critical');
  const highCount = rowCount('High');

  doc.setFillColor(...palette.ink);
  doc.rect(0, 0, pageWidth, 48, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(120, 213, 202);
  doc.text('VPN SECURITY ASSESSMENT', margin, 13);
  doc.setFontSize(20);
  doc.setTextColor(255, 255, 255);
  doc.text('Gateway Security Report', margin, 25);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(221, 232, 237);
  doc.text(report.gateway.display_name, margin, 34);
  doc.setFontSize(8);
  doc.text(`${report.gateway.gateway_type} - ${report.telemetry.adapter}`, margin, 41);

  y = 56;
  doc.setFillColor(...palette.pale);
  doc.setDrawColor(...palette.border);
  doc.roundedRect(margin, y, contentWidth, 25, 1.5, 1.5, 'FD');
  const metadata = [
    ['Gateway ID', report.gateway.gateway_id],
    ['Gateway status', report.gateway.status],
    ['Report generated (UTC)', report.reportGeneratedAt],
    ['Telemetry collected (UTC)', report.telemetry.collectedAt || 'Not reported'],
  ];
  metadata.forEach(([label, value], index) => {
    const column = index % 2;
    const row = Math.floor(index / 2);
    const x = margin + 5 + column * (contentWidth / 2);
    const cellY = y + 7 + row * 10;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(...palette.muted);
    doc.text(label.toUpperCase(), x, cellY);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(...palette.ink);
    doc.text(doc.splitTextToSize(value, contentWidth / 2 - 10)[0] || '', x, cellY + 3.5);
  });
  y += 32;

  const metricGap = 3;
  const metricWidth = (contentWidth - metricGap * 3) / 4;
  const metrics = [
    { label: 'Verified score', value: `${score.value}/100`, detail: score.rating, color: palette.teal },
    { label: 'Evidence coverage', value: `${score.evidenceCoveragePercent}%`, detail: score.status, color: palette.blue },
    { label: 'Critical findings', value: String(criticalCount), detail: 'Deterministic', color: palette.critical },
    { label: 'High findings', value: String(highCount), detail: 'Deterministic', color: palette.high },
  ];
  metrics.forEach((metric, index) => {
    const x = margin + index * (metricWidth + metricGap);
    doc.setFillColor(255, 255, 255);
    doc.setDrawColor(...palette.border);
    doc.roundedRect(x, y, metricWidth, 24, 1.5, 1.5, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.3);
    doc.setTextColor(...palette.muted);
    doc.text(metric.label.toUpperCase(), x + 3, y + 5);
    doc.setFontSize(12);
    doc.setTextColor(...metric.color);
    doc.text(metric.value, x + 3, y + 13.5);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(...palette.muted);
    doc.text(doc.splitTextToSize(metric.detail, metricWidth - 6)[0] || '', x + 3, y + 20);
  });
  y += 31;

  section('1. Executive Summary');
  const executiveSummary = aiReport?.narrative.executive_summary
    ?? `At ${report.reportGeneratedAt} UTC, this ${report.gateway.status.toLowerCase()} gateway assessment recorded a verified score of ${score.value}/100 with ${score.evidenceCoveragePercent}% evidence coverage. It contains ${criticalCount} Critical and ${highCount} High finding(s). Unknown controls remain not determinable and are not treated as passing.`;
  callout(aiReport ? 'AI-assisted summary' : 'Deterministic summary', executiveSummary, palette.teal);

  section('Posture and Evidence Charts');
  const drawPercentBar = (label: string, value: number, color: RGB) => {
    ensureSpace(11);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(...palette.text);
    doc.text(label, margin, y + 3);
    doc.setFont('helvetica', 'bold');
    doc.text(`${value}%`, pageWidth - margin, y + 3, { align: 'right' });
    doc.setFillColor(...palette.border);
    doc.roundedRect(margin, y + 5, contentWidth, 3, 1, 1, 'F');
    doc.setFillColor(...color);
    doc.roundedRect(margin, y + 5, contentWidth * Math.max(0, Math.min(100, value)) / 100, 3, 1, 1, 'F');
    y += 12;
  };
  drawPercentBar('Verified security score', score.value, palette.teal);
  drawPercentBar('Evidence coverage', score.evidenceCoveragePercent, palette.blue);

  const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Pass'];
  const maxSeverity = Math.max(1, ...severityOrder.map(rowCount));
  const labelWidth = 24;
  const countWidth = 12;
  const severityBarWidth = contentWidth - labelWidth - countWidth;
  severityOrder.forEach((severity) => {
    ensureSpace(8);
    const count = rowCount(severity);
    const color = severityColors[severity] ?? palette.muted;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(...palette.text);
    doc.text(severity, margin, y + 3);
    doc.setFillColor(...palette.pale);
    doc.rect(margin + labelWidth, y, severityBarWidth, 3.5, 'F');
    if (count > 0) {
      doc.setFillColor(...color);
      doc.rect(margin + labelWidth, y, severityBarWidth * count / maxSeverity, 3.5, 'F');
    }
    doc.setFont('helvetica', 'bold');
    doc.text(String(count), pageWidth - margin, y + 3, { align: 'right' });
    y += 7;
  });

  doc.addPage();
  y = 21;
  section('2. Prioritized Security Findings');
  if (aiReport?.narrative.technical_interpretation) {
    callout('AI-assisted technical interpretation', aiReport.narrative.technical_interpretation, palette.blue);
  }
  autoTable(doc, {
    startY: y,
    head: [['Severity', 'Finding and observed value', 'Verified assessment', 'Why it matters (AI-assisted)']],
    body: findingRows.length ? findingRows : [['None', 'No conclusive findings available', 'Review evidence and limitations.', '']],
    margin: { left: margin, right: margin, top: 20, bottom: 19 },
    styles: {
      font: 'helvetica',
      fontSize: 7,
      cellPadding: 2.1,
      overflow: 'linebreak',
      valign: 'top',
      textColor: palette.text,
      lineColor: palette.border,
      lineWidth: 0.15,
    },
    headStyles: { fillColor: palette.ink, textColor: 255, fontStyle: 'bold' },
    alternateRowStyles: { fillColor: palette.pale },
    columnStyles: {
      0: { cellWidth: 20 },
      1: { cellWidth: 43 },
      2: { cellWidth: 60 },
      3: { cellWidth: contentWidth - 123 },
    },
    rowPageBreak: 'avoid',
  });
  y = ((doc as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY ?? y + 12) + 8;

  section('3. Remediation Plan');
  table(
    ['Setting', 'Observed', 'Recommended', 'Deterministic basis', 'AI explanation'],
    report.securityAssessment.configurationRecommendations.map((item) => [
      item.setting,
      item.current,
      item.recommended,
      item.basis,
      aiRecommendationNotes.get(item.id) ?? (aiReport ? 'No additional explanation returned.' : 'AI note not generated; deterministic basis follows.'),
    ]),
    [28, 27, 34, 48, contentWidth - 137],
  );

  doc.addPage();
  y = 21;
  section('4. Observed IKE Security Associations');
  table(
    ['SA', 'Version', 'Encryption', 'Integrity', 'PRF', 'DH group'],
    report.telemetry.ikeRecords.map((ike, index) => [
      displayValue(ike.name, `IKE SA ${index + 1}`),
      displayValue(ike.version),
      displayValue(ike.encr),
      displayValue(ike.integ),
      displayValue(ike.prf),
      displayValue(ike.dh),
    ]),
    [32, 21, 35, 34, 31, contentWidth - 153],
  );

  section('5. Observed Child SA / ESP Evidence');
  table(
    ['Child SA / mode', 'SPI in / out', 'Encryption / integrity', 'DH / PFS', 'Replay / ESN', 'Timers / traffic'],
    report.telemetry.childRecords.map((child: GatewayRecord, index) => [
      `${displayValue(child.name, `Child SA ${index + 1}`)}\n${displayValue(child.protocol, 'ESP')} / ${displayValue(child.mode)}`,
      `${displayValue(child.inbound_spi ?? child.spi)} / ${displayValue(child.outbound_spi)}`,
      `${displayValue(child.encr)} / ${displayValue(child.integ)}`,
      `${displayValue(child.dh)} / ${displayValue(child.pfs)}`,
      `Replay: ${displayValue(child.replay_window_in)} / ${displayValue(child.replay_window_out)}\nESN: ${displayValue(child.esn_in ?? child.esn)} / ${displayValue(child.esn_out ?? child.esn)}`,
      `Rekey / expiry: ${displayValue(child.rekey_time)} / ${displayValue(child.life_time)} s\nIn: ${displayValue(child.packets_in, '0')} pkts, ${displayValue(child.bytes_in, '0')} B\nOut: ${displayValue(child.packets_out, '0')} pkts, ${displayValue(child.bytes_out, '0')} B`,
    ]),
    [32, 25, 35, 23, 34, contentWidth - 149],
  );

  section('6. Scope, Methodology, and Limitations');
  paragraph(`Scope: ${report.gateway.display_name} (${report.gateway.gateway_id}), using the latest gateway telemetry snapshot available at ${report.reportGeneratedAt} UTC. The snapshot reports ${report.gateway.active_ike_sa_count} active IKE SA(s) and ${report.gateway.active_child_sa_count} active Child SA(s).`);
  paragraph(`Method: ${score.method} Deterministic checks score observed controls; missing or unmatched evidence remains not determinable and is not treated as a pass. AI-generated text explains supplied data only and does not alter findings, scores, or recommendations.`);
  report.securityAssessment.limitations.forEach((limitation) => paragraph(`- ${limitation}`, 8));
  paragraph('This is a point-in-time technical assessment, not a penetration test, compliance attestation, or certification.', 8);

  section('7. Reference Guidance');
  paragraph('NIST SP 800-77 Rev. 1, Guide to IPsec VPNs (June 2020). https://doi.org/10.6028/NIST.SP.800-77r1', 7.5);
  paragraph('NIST SP 800-115, Technical Guide to Information Security Testing and Assessment (September 2008). https://doi.org/10.6028/NIST.SP.800-115', 7.5);

  const pageCount = doc.getNumberOfPages();
  for (let page = 1; page <= pageCount; page += 1) {
    doc.setPage(page);
    if (page > 1) {
      doc.setFillColor(...palette.ink);
      doc.rect(0, 0, pageWidth, 15, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7);
      doc.setTextColor(255, 255, 255);
      doc.text('GATEWAY SECURITY ASSESSMENT', margin, 9);
      doc.setFont('helvetica', 'normal');
      doc.text(report.gateway.gateway_id, pageWidth - margin, 9, { align: 'right' });
    }
    doc.setDrawColor(...palette.border);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 14, pageWidth - margin, pageHeight - 14);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(...palette.muted);
    doc.text('Observed findings and scores are deterministic; AI text is explanatory only.', margin, pageHeight - 8);
    doc.text(`Page ${page} of ${pageCount}`, pageWidth - margin, pageHeight - 8, { align: 'right' });
  }

  const safeGatewayId = report.gateway.gateway_id.replace(/[^a-zA-Z0-9_-]/g, '_') || 'gateway';
  doc.save(`gateway_security_assessment_${safeGatewayId}.pdf`);
}