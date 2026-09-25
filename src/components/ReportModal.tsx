import React, { useState } from 'react';
import { X, Download, Printer, Copy, Check, ShieldCheck, ShieldAlert, FileText } from 'lucide-react';
import { AiPrediction, IkeSecurityAssociation, SecurityScorecard, VpnCaptureScenario } from '../types';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  scenario: VpnCaptureScenario;
  scorecard: SecurityScorecard;
  prediction: AiPrediction;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  scenario,
  scorecard,
  prediction,
}) => {
  const [reportType, setReportType] = useState<'EXECUTIVE' | 'TECHNICAL'>('EXECUTIVE');
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

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

  const generateMarkdownReport = () => {
    return `# NTRO IPsec Security Assessment Report: ${scenario.name}
**Report Type:** ${reportType === 'EXECUTIVE' ? 'Executive Leadership Summary' : 'Detailed Technical Protocol Audit'}
**Target Organization:** ${scenario.organization}
**Generated Date:** ${new Date().toISOString()}

---

## 1. Overall Security Scorecard
- **Security Score:** ${scorecard.totalScore} / 100 (${scorecard.rating.toUpperCase()})
- **NIST SP 800-77 Rev. 1 Status:** ${scorecard.complianceNist ? 'COMPLIANT' : 'NON-COMPLIANT'}
- **RFC 8221 Cryptographic Status:** ${scorecard.complianceRfc8221 ? 'COMPLIANT' : 'NON-COMPLIANT'}
- **NSA CNSA Suite Status:** ${scorecard.complianceNsaCnsa ? 'COMPLIANT' : 'NON-COMPLIANT'}

---

## 2. Inferred Traffic & AI Classification
- **Predicted Payload Activity:** ${prediction.predictedClass}
- **AI Model Confidence:** ${prediction.confidenceScore}%
- **Entropy:** ${scenario.features.calculatedEntropy} / 8.00 bits (Verified encrypted payload)

---

## 3. Cryptographic Parameters
- **IKE Version:** ${scenario.sa.ikeVersion}
- **Operating Mode:** ${scenario.sa.operationalMode} (${scenario.sa.ipVersion})
- **Symmetric Cipher:** ${scenario.sa.encryptionAlgorithm} (${scenario.sa.encryptionKeyBits}-bit)
- **Integrity / Hash:** ${scenario.sa.authIntegrityAlgorithm}
- **Diffie-Hellman Group:** ${scenario.sa.dhGroup} (${scenario.sa.dhBits}-bit)
- **Perfect Forward Secrecy (PFS):** ${scenario.sa.pfsEnabled ? 'ENABLED' : 'DISABLED (CRITICAL VULNERABILITY)'}
- **Key Lifetime:** ${scenario.sa.keyLifetimeSeconds / 3600} hours
- **Replay Protection:** ${scenario.sa.replayProtection ? 'ENABLED' : 'DISABLED'}

---

## 4. Key Findings & Remediation Plan
${scorecard.findings
  .filter((f) => f.severity !== 'Pass')
  .map(
    (f) => `### [${f.severity.toUpperCase()}] ${f.parameter}: ${f.threatName}
- **Detected:** ${f.detectedValue}
- **Standard Requirement:** ${f.recommendedValue}
- **Threat:** ${f.description}
- **Action Required:** ${f.remediation}
`
  )
  .join('\n')}
`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center text-white">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                Automated Security Assessment Report
              </h2>
              <p className="text-xs text-slate-400">
                Official NTRO Protocol Analyzer Security Verification Document
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View Switcher */}
            <div className="inline-flex rounded-lg bg-slate-800 p-0.5 border border-slate-700">
              <button
                id="btn-report-exec"
                onClick={() => setReportType('EXECUTIVE')}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                  reportType === 'EXECUTIVE'
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Executive Report
              </button>
              <button
                id="btn-report-tech"
                onClick={() => setReportType('TECHNICAL')}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                  reportType === 'TECHNICAL'
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Technical Report
              </button>
            </div>

            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition-colors cursor-pointer ml-2"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-slate-300 text-xs">
          
          {reportType === 'EXECUTIVE' ? (
            /* Executive Report View */
            <div className="space-y-6">
              
              {/* Executive Banner */}
              <div className="p-5 rounded-xl bg-slate-800/60 border border-slate-700/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <span className="text-[11px] font-bold text-blue-400 uppercase tracking-wider">
                    Executive Threat &amp; Compliance Verdict
                  </span>
                  <h3 className="text-lg font-bold text-white mt-0.5">
                    {scenario.name}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Deployment Context: {scenario.description}
                  </p>
                </div>

                <div className="text-right shrink-0">
                  <div className="text-2xl font-black text-white">
                    {scorecard.totalScore} <span className="text-sm font-normal text-slate-400">/ 100</span>
                  </div>
                  <span className={`inline-block px-2.5 py-0.5 rounded text-xs font-bold uppercase mt-1 ${
                    scorecard.totalScore >= 70 ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
                  }`}>
                    {scorecard.rating} Posture
                  </span>
                </div>
              </div>

              {/* Plain-Language Story & Risk Summary */}
              <div className="space-y-2">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                  Plain-Language Assessment &amp; Operational Impact
                </h4>
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2.5 leading-relaxed">
                  <p>
                    From an external network perspective, this tunnel displays an active and healthy connection. However, automated deep-inspection of the initial negotiation parameters reveals that{' '}
                    {scorecard.totalScore < 60
                      ? 'critical legacy choices leave this tunnel severely compromised.'
                      : 'the cryptographic suite follows modern standards with robust defense.'}
                  </p>
                  <p>
                    <strong>AI Inferred Workload:</strong> Even though raw payloads are unreadable due to ESP encapsulation, machine learning models determined with <strong>{prediction.confidenceScore}% confidence</strong> that this tunnel is transmitting <strong>{prediction.predictedClass}</strong> based on statistical framing characteristics.
                  </p>
                </div>
              </div>

              {/* Executive Recommendations List */}
              <div className="space-y-3">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                  Prioritized Action Items
                </h4>
                <div className="space-y-2">
                  {scorecard.findings
                    .filter((f) => f.severity !== 'Pass')
                    .map((f, i) => (
                      <div key={i} className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 flex items-start gap-3">
                        <span className="w-5 h-5 rounded-full bg-rose-950 text-rose-400 border border-rose-800 flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                          {i + 1}
                        </span>
                        <div>
                          <div className="font-bold text-white">{f.threatName}</div>
                          <div className="text-slate-400 mt-0.5">{f.remediation}</div>
                        </div>
                      </div>
                    ))}
                  {scorecard.findings.filter((f) => f.severity !== 'Pass').length === 0 && (
                    <div className="text-emerald-400 font-semibold p-3 bg-emerald-950/30 rounded-lg border border-emerald-900">
                      ✓ No immediate executive interventions required. Deployment meets defense standard requirements.
                    </div>
                  )}
                </div>
              </div>

            </div>
          ) : (
            /* Technical Report View */
            <div className="space-y-6 font-mono text-xs">
              
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-emerald-400 font-bold">[PROTOCOL AUDIT RECORD]</div>
                <div>Target Gateway: {scenario.packets[0]?.destIp || '10.0.0.1'}</div>
                <div>Initiator SPI: {scenario.sa.initiatorSpi}</div>
                <div>Responder SPI: {scenario.sa.responderSpi}</div>
                <div>Key Lifetime Window: {scenario.sa.keyLifetimeSeconds}s</div>
                <div>Replay Protection: {scenario.sa.replayProtection ? 'ENABLED (Window 64)' : 'DISABLED (FAIL)'}</div>
              </div>

              {/* Technical Specifications */}
              <div>
                <h4 className="font-bold text-white mb-2 font-sans">
                  Negotiated Security Association Transforms
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700">
                    <div className="text-[10px] text-slate-400">IKE Version</div>
                    <div className="font-bold text-white mt-1">{scenario.sa.ikeVersion}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700">
                    <div className="text-[10px] text-slate-400">Cipher</div>
                    <div className="font-bold text-white mt-1 truncate">{scenario.sa.encryptionAlgorithm}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700">
                    <div className="text-[10px] text-slate-400">DH Group</div>
                    <div className="font-bold text-white mt-1">{scenario.sa.dhGroup}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700">
                    <div className="text-[10px] text-slate-400">PFS Status</div>
                    <div className={`font-bold mt-1 ${scenario.sa.pfsEnabled ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {scenario.sa.pfsEnabled ? 'ENABLED' : 'DISABLED'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Technical CVE Table */}
              <div>
                <h4 className="font-bold text-white mb-2 font-sans">
                  Vulnerability Dissection &amp; RFC Compliance Failures
                </h4>
                <div className="border border-slate-800 rounded-lg overflow-hidden font-sans">
                  <table className="w-full text-left">
                    <thead className="bg-slate-800 text-[11px] text-slate-400">
                      <tr>
                        <th className="p-2.5">Parameter</th>
                        <th className="p-2.5">Detected</th>
                        <th className="p-2.5">Severity</th>
                        <th className="p-2.5">Vulnerability Reference</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {scorecard.findings.map((f) => (
                        <tr key={f.id} className="text-xs">
                          <td className="p-2.5 text-white font-medium">{f.parameter}</td>
                          <td className="p-2.5 font-mono text-slate-300">{f.detectedValue}</td>
                          <td className="p-2.5">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              f.severity === 'Critical' ? 'bg-rose-950 text-rose-300' : (f.severity === 'Pass' ? 'bg-emerald-950 text-emerald-300' : 'bg-amber-950 text-amber-300')
                            }`}>
                              {f.severity}
                            </span>
                          </td>
                          <td className="p-2.5 text-slate-400">{f.threatName}</td>
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
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs text-slate-400">
            Exportable report format conforming to NTRO Deliverable E.
          </div>

          <div className="flex items-center gap-2">
            <button
              id="btn-copy-report"
              onClick={handleCopyMarkdown}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied Markdown!' : 'Copy Markdown'}</span>
            </button>

            <button
              id="btn-download-report"
              onClick={handleDownloadMarkdown}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition-colors cursor-pointer"
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
