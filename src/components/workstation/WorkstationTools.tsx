import React, { useEffect, useState } from 'react';
import { CheckCircle2, Command, HelpCircle, Moon, ServerCog, Sun, X } from 'lucide-react';

export type ThemePreference = 'light' | 'dark' | 'system';

export function useThemePreference() {
  const [theme, setTheme] = useState<ThemePreference>(() => (localStorage.getItem('vpn-theme') as ThemePreference) || 'system');
  useEffect(() => {
    const query = window.matchMedia('(prefers-color-scheme: dark)');
    const apply = () => document.documentElement.dataset.theme = theme === 'system' ? (query.matches ? 'dark' : 'light') : theme;
    apply(); query.addEventListener('change', apply); localStorage.setItem('vpn-theme', theme);
    return () => query.removeEventListener('change', apply);
  }, [theme]);
  return { theme, setTheme };
}

export const SourceBadge = ({ source = 'UNKNOWN' }: { source?: string }) => {
  const label = source.replaceAll('_', ' ');
  const style = source.includes('ML') ? 'bg-violet-50 text-violet-700 border-violet-200' : source.includes('TELEMETRY') ? 'bg-cyan-50 text-cyan-700 border-cyan-200' : source.includes('OBSERVED') ? 'bg-blue-50 text-blue-700 border-blue-200' : source.includes('RULE') || source.includes('DERIVED') ? 'bg-slate-100 text-slate-700 border-slate-200' : 'bg-slate-100 text-slate-600 border-slate-200';
  return <span title={`Source: ${label}`} className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-bold tracking-wide ${style}`}>{label}</span>;
};

export const ConfidenceIndicator = ({ value, source = 'Evidence' }: { value: number | null | undefined; source?: string }) => {
  if (value === null || value === undefined) return <span className="text-xs text-slate-500">Confidence: not available</span>;
  const percent = value <= 1 ? Math.round(value * 100) : Math.round(value);
  const bounded = Math.max(0, Math.min(100, percent));
  return <div className="min-w-32"><div className="flex justify-between text-[11px] text-slate-500"><span>{source}</span><span>{bounded}%</span></div><div className="mt-1 h-1.5 overflow-hidden rounded bg-slate-200"><div className="h-full rounded bg-blue-600" style={{ width: `${bounded}%` }} /></div></div>;
};

export const StatusDrawer = ({ open, onClose }: { open: boolean; onClose: () => void }) => {
  if (!open) return null;
  const rows = [['Browser parser', 'Available', 'Local fallback'], ['Scapy service', 'Optional', '127.0.0.1:8765'], ['Gateway API', 'Optional', '127.0.0.1:8770'], ['ML models', 'Via Scapy', 'Used when the Scapy service parses an upload'], ['Security rules', 'Loaded', 'Browser rule engine'], ['Report engine', 'Available', 'Browser PDF']];
  return <div className="fixed inset-0 z-50 bg-slate-950/35" role="presentation" onMouseDown={onClose}><aside role="dialog" aria-modal="true" aria-label="System status" onMouseDown={e => e.stopPropagation()} className="animate-drawer absolute right-0 top-0 h-full w-full max-w-md border-l border-slate-200 bg-white p-6 shadow-2xl"><div className="flex items-center justify-between"><div><p className="text-xs font-bold uppercase tracking-widest text-blue-600">System status</p><h2 className="mt-1 text-lg font-bold text-slate-900">Analysis services</h2></div><button onClick={onClose} aria-label="Close status drawer" className="rounded p-2 hover:bg-slate-100"><X className="h-4 w-4" /></button></div><p className="mt-3 text-sm text-slate-500">Statuses describe locally configured subsystems; optional services are not reported as online unless the browser actually reaches them.</p><div className="mt-6 divide-y divide-slate-200 border-y border-slate-200">{rows.map(([name, status, detail]) => <div key={name} className="flex items-center gap-3 py-3"><ServerCog className="h-4 w-4 text-slate-400" /><div className="min-w-0 flex-1"><div className="text-sm font-medium text-slate-800">{name}</div><div className="text-xs text-slate-500">{detail}</div></div><span className="text-xs font-medium text-slate-600">{status}</span></div>)}</div></aside></div>;
};

export const CommandPalette = ({ open, onClose, onAction }: { open: boolean; onClose: () => void; onAction: (action: string) => void }) => {
  const [query, setQuery] = useState('');
  useEffect(() => { if (open) setQuery(''); }, [open]);
  if (!open) return null;
  const actions = [['upload', 'Upload PCAP', 'Start a capture analysis'], ['analysis', 'Open analysis', 'View the current capture'], ['report', 'Generate report', 'Preview and download a PDF'], ['gateways', 'Open gateways', 'Manage telemetry and correlation'], ['testbed', 'Open testbed', 'Create a controlled lab capture'], ['theme', 'Toggle theme', 'Switch light and dark appearance'], ['help', 'Open help', 'Keyboard shortcuts and terminology']].filter(([, title, text]) => `${title} ${text}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="fixed inset-0 z-50 flex items-start justify-center bg-slate-950/35 px-4 pt-[15vh]" onMouseDown={onClose}><div role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={e => e.stopPropagation()} className="w-full max-w-xl overflow-hidden rounded-xl border border-slate-200 bg-white shadow-2xl"><div className="flex items-center gap-2 border-b border-slate-200 px-4"><Command className="h-4 w-4 text-slate-400" /><input autoFocus value={query} onChange={e => setQuery(e.target.value)} placeholder="Search commands…" className="h-12 flex-1 bg-transparent text-sm text-slate-900 outline-none" /><kbd className="text-[10px] text-slate-400">ESC</kbd></div><div className="p-2">{actions.map(([id, title, text]) => <button key={id} onClick={() => { onAction(id); onClose(); }} className="flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left hover:bg-slate-50"><span><span className="block text-sm font-medium text-slate-800">{title}</span><span className="text-xs text-slate-500">{text}</span></span><span className="text-xs text-slate-400">↵</span></button>)}</div></div></div>;
};

export const ThemeMenu = ({ theme, setTheme }: { theme: ThemePreference; setTheme: (value: ThemePreference) => void }) => <div className="flex items-center rounded-lg border border-slate-200 bg-white p-0.5" aria-label="Color theme">{(['light', 'dark', 'system'] as ThemePreference[]).map(item => <button key={item} onClick={() => setTheme(item)} title={`${item} theme`} className={`rounded-md p-1.5 ${theme === item ? 'bg-slate-100 text-blue-700' : 'text-slate-500 hover:bg-slate-50'}`}>{item === 'light' ? <Sun className="h-3.5 w-3.5" /> : item === 'dark' ? <Moon className="h-3.5 w-3.5" /> : <HelpCircle className="h-3.5 w-3.5" />}</button>)}</div>;

export const PipelineStepper = ({ active, stage = 0 }: { active: boolean; stage?: number }) => {
  if (!active) return null;
  const stages = ['Validating capture', 'Analyzing packet evidence', 'Preparing security assessment', 'Opening workspace'];
  return <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/35 p-4"><div className="w-full max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-2xl" role="status" aria-live="polite"><p className="text-xs font-bold uppercase tracking-widest text-blue-600">Capture analysis</p><h2 className="mt-1 text-lg font-bold text-slate-900">Tracing packet evidence</h2><p className="mt-1 text-sm text-slate-500">Only completed work is marked complete. If Scapy is unavailable, the browser parser is loaded on demand.</p><ol className="mt-6 space-y-3">{stages.map((name, index) => { const complete = index < stage; const current = index === stage; return <li key={name} className="flex items-center gap-3 text-sm"><span className={`grid h-6 w-6 place-items-center rounded-full text-xs ${complete ? 'bg-emerald-100 text-emerald-700' : current ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-400'}`}>{complete ? <CheckCircle2 className="h-4 w-4" /> : current ? '…' : index + 1}</span><span className={current ? 'font-medium text-slate-900' : 'text-slate-600'}>{name}</span></li>; })}</ol></div></div>;
};
