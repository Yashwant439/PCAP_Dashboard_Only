import React, { useState } from 'react';
import { ChevronDown, ChevronUp, FileSearch, ShieldCheck } from 'lucide-react';
import { IkeSecurityAssociation } from '../../types';
import { ConfidenceIndicator, SourceBadge } from './WorkstationTools';

const readable = (value: unknown) => value === null || value === undefined || value === '' ? 'Not observed' : String(value);

export const CaptureProfile = ({ sa, technical }: { sa: IkeSecurityAssociation; technical: boolean }) => {
  const [open, setOpen] = useState(true);
  const fields: Array<[string, unknown, string]> = [
    ['IKE version', sa.ikeVersion, 'ikeVersion'], ['VPN mode', sa.operationalMode, 'operationalMode'], ['IP version', sa.ipVersion, 'ipVersion'],
    ['Encryption', sa.encryptionAlgorithm, 'encryptionAlgorithm'], ['Integrity', sa.authIntegrityAlgorithm, 'authIntegrityAlgorithm'], ['DH group', sa.dhGroup, 'dhGroup'],
    ['PFS', sa.pfsEnabled === null ? null : sa.pfsEnabled ? 'Enabled' : 'Disabled', 'pfsEnabled'], ['Replay protection', sa.replayProtection === null ? null : sa.replayProtection ? 'Enabled' : 'Disabled', 'replayProtection'], ['Key lifetime', sa.keyLifetimeSeconds === null ? null : `${sa.keyLifetimeSeconds / 3600} hours`, 'keyLifetimeSeconds'],
  ];
  return <section className="surface overflow-hidden"><button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between p-4 text-left hover:bg-slate-50"><span className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-blue-600" /><span><span className="block text-sm font-semibold text-slate-900">VPN profile</span><span className="block text-xs text-slate-500">Negotiation facts, evidence source, and confidence</span></span></span>{open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}</button>{open && <div className="border-t border-slate-200"><div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3">{fields.map(([label, value, key]) => { const evidence = sa.fieldEvidence?.[key]; return <div key={key} className="border-b border-r border-slate-100 p-4"><div className="flex items-center justify-between gap-2"><span className="text-xs text-slate-500">{label}</span><SourceBadge source={evidence?.source || (value === null ? 'UNKNOWN' : 'PCAP_OBSERVED')} /></div><div className="mt-1 text-sm font-semibold text-slate-900">{readable(value)}</div>{technical && evidence && <div className="mt-2"><ConfidenceIndicator value={evidence.confidence} source="Evidence confidence" /><p className="mt-2 text-[11px] text-slate-500">{evidence.evidence}</p></div>}</div>; })}</div>{technical && <div className="flex items-center gap-2 bg-slate-50 px-4 py-3 text-xs text-slate-500"><FileSearch className="h-4 w-4 text-slate-400" />Unknown values mean the needed field was not visible in the capture; they are not assumed safe or unsafe.</div>}</div>}</section>;
};
