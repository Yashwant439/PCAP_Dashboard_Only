import React from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle2, XCircle, Wrench, ExternalLink } from 'lucide-react';
import { BackendCaptureAnalysis, SecurityScorecard, IkeSecurityAssociation } from '../types';
import { EvidenceSecurityAssessment } from './EvidenceSecurityAssessment';

interface SecurityAssessmentProps {
  scorecard: SecurityScorecard;
  sa: IkeSecurityAssociation;
  backendAnalysis?: BackendCaptureAnalysis;
  onSelectPacket?: (packetId: number) => void;
}

export const SecurityAssessment: React.FC<SecurityAssessmentProps> = ({
  scorecard,
  sa,
  backendAnalysis,
  onSelectPacket,
}) => {
  if (backendAnalysis?.security) {
    return <EvidenceSecurityAssessment assessment={backendAnalysis.security} onSelectPacket={onSelectPacket} />;
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      case 'High':
        return 'bg-orange-950 text-orange-300 border-orange-800';
      case 'Medium':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'Low':
        return 'bg-blue-950 text-blue-300 border-blue-800';
      default:
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'Critical':
      case 'High':
        return <XCircle className="w-4 h-4 text-rose-400 shrink-0" />;
      case 'Medium':
      case 'Low':
        return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
      default:
        return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
    }
  };

  return (
    <div className="space-y-5">
      {backendAnalysis && (
        <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/70 text-xs text-amber-200">
          The evidence-backed backend assessment is shown above. This compatibility policy panel still uses the legacy local scorecard and is not authoritative for fields marked not observable by the backend.
        </div>
      )}
      
      {/* 1. Cryptographic Compliance & Security Association Audit */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              <span>Cryptographic Parameter Audit &amp; Compliance Matrix</span>
            </h3>
            <p className="text-xs text-slate-400">
              Evaluated against NIST SP 800-77 Rev. 1, RFC 8221, and NSA Commercial National Security Algorithm (CNSA)
            </p>
          </div>

          <div className="text-xs font-mono font-bold text-slate-300">
            Total Penalty: <span className="text-rose-400">-{100 - scorecard.totalScore} pts</span>
          </div>
        </div>

        {/* Findings Table */}
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-800/60 text-[11px] uppercase tracking-wider text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th className="py-2.5 px-3">Security Parameter</th>
                <th className="py-2.5 px-3">Detected Configuration</th>
                <th className="py-2.5 px-3">Standard Recommendation</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3 text-right">Score Impact</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {scorecard.findings.map((f) => (
                <tr key={f.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-3 font-medium text-white flex items-center gap-2">
                    {getSeverityIcon(f.severity)}
                    <span>{f.parameter}</span>
                  </td>
                  <td className="py-3 px-3 font-mono font-semibold text-slate-200">
                    {f.detectedValue}
                  </td>
                  <td className="py-3 px-3 text-slate-400 font-medium">
                    {f.recommendedValue}
                  </td>
                  <td className="py-3 px-3">
                    <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right font-mono font-bold">
                    {f.penalty > 0 ? (
                      <span className="text-rose-400">-{f.penalty}</span>
                    ) : (
                      <span className="text-emerald-400">0 (Safe)</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 2. Threat Matrix & CVE Mapping */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="pb-3 border-b border-slate-800">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span>Identified Threat Vectors &amp; Attack Exploitation Analysis</span>
          </h3>
          <p className="text-xs text-slate-400">
            Real-world security implications of detected misconfigurations
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          {scorecard.findings
            .filter((f) => f.severity !== 'Pass')
            .map((f) => (
              <div key={f.id} className="p-3.5 rounded-lg bg-slate-800/50 border border-slate-700/70 text-xs">
                <div className="flex items-start justify-between gap-2">
                  <div className="font-bold text-white flex items-center gap-1.5">
                    <span className="text-rose-400">⚠</span>
                    <span>{f.threatName}</span>
                  </div>
                  {f.cveReference && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-800 shrink-0">
                      {f.cveReference}
                    </span>
                  )}
                </div>

                <p className="text-slate-300 mt-2 leading-relaxed">
                  {f.description}
                </p>

                <div className="mt-3 pt-2.5 border-t border-slate-700/60 flex items-start gap-1.5 text-emerald-300">
                  <Wrench className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-emerald-400 font-semibold">Remediation:</strong>{' '}
                    <span className="text-slate-300">{f.remediation}</span>
                  </div>
                </div>
              </div>
            ))}

          {scorecard.findings.filter((f) => f.severity !== 'Pass').length === 0 && (
            <div className="col-span-2 p-6 rounded-lg bg-emerald-950/30 border border-emerald-800/60 text-center">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              <div className="text-sm font-bold text-white">Zero Critical Vulnerabilities Detected</div>
              <p className="text-xs text-emerald-300/80 mt-1 max-w-lg mx-auto">
                This tunnel satisfies all baseline requirements for NSA CNSA and NIST SP 800-77 Rev 1 cryptographic security.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* 3. Recommended Hardening Snippet (strongSwan / IPsec) */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Wrench className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">
              Automated Configuration Fix (strongSwan swanctl.conf)
            </h3>
          </div>
          <span className="text-xs text-slate-400">RFC 8221 &amp; CNSA Hardened</span>
        </div>

        <pre className="mt-3.5 p-3.5 bg-slate-950 rounded-lg text-xs font-mono text-emerald-400 overflow-x-auto border border-slate-800">
{`connections {
  hardened-vpn {
    version = 2
    local_addrs  = ${sa.ipVersion === 'IPv6' ? '2001:db8:100::1' : '198.51.100.2'}
    remote_addrs = ${sa.ipVersion === 'IPv6' ? '2001:db8:200::2' : '203.0.113.50'}
    
    # Phase 1: Hardened IKE SA (AES-256-GCM + SHA384 + DH Group 19 ECDH)
    proposals = aes256gcm16-sha384-ecp256, aes256gcm16-sha384-modp2048
    rekey_time = 3600s
    
    children {
      child-sa {
        # Phase 2: Hardened ESP Child SA with PFS (Perfect Forward Secrecy)
        esp_proposals = aes256gcm16-ecp256, aes256gcm16-modp2048
        mode = tunnel
        rekey_time = 1800s
        esn = yes  # Extended Sequence Numbers for replay protection
        dpd_action = restart
      }
    }
  }
}`}
        </pre>
      </div>

    </div>
  );
};
