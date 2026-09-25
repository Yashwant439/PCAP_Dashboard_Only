import React from 'react';
import { Shield, FileText, Download, Sliders, Cpu, Plus } from 'lucide-react';
import { VpnCaptureScenario } from '../types';

interface HeaderProps {
  scenarios: VpnCaptureScenario[];
  selectedScenario: VpnCaptureScenario | null;
  onSelectScenario: (scenario: VpnCaptureScenario) => void;
  onOpenReport: () => void;
  onOpenTestbed: () => void;
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onClearTraces?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  scenarios,
  selectedScenario,
  onSelectScenario,
  onOpenReport,
  onOpenTestbed,
  onFileUpload,
  onClearTraces,
}) => {
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  return (
    <header className="bg-slate-900 text-slate-100 border-b border-slate-800 sticky top-0 z-30 shadow-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3.5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          
          {/* Title & Branding */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center shadow-md shadow-blue-500/20 text-white shrink-0">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-lg font-bold tracking-tight text-white">
                  AI-Powered IPsec Protocol Analyzer
                </h1>
                <span className="text-xs px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 font-medium">
                  NTRO PS 26160
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Automated Cryptographic Security Assessment &amp; Encrypted ESP Traffic Classifier
              </p>
            </div>
          </div>

          {/* Controls & Modals */}
          <div className="flex items-center flex-wrap gap-2">
            {/* Testbed Generator */}
            <button
              id="btn-open-testbed"
              onClick={onOpenTestbed}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 text-slate-200 border border-slate-700 hover:bg-slate-750 hover:border-slate-600 transition-colors cursor-pointer"
            >
              <Sliders className="w-3.5 h-3.5 text-blue-400" />
              <span>VPN Testbed Lab</span>
            </button>

            {/* Security Report */}
            <button
              id="btn-open-report"
              disabled={!selectedScenario}
              onClick={onOpenReport}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg shadow-sm transition-colors cursor-pointer ${
                selectedScenario
                  ? 'bg-blue-600 hover:bg-blue-500 text-white'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Audit Reports</span>
            </button>

            {/* Upload PCAP / PCAPNG */}
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => {
                onFileUpload(e);
                e.target.value = '';
              }}
              accept=".pcap,.pcapng,.cap,.json,application/vnd.tcpdump.pcap,application/vnd.tcpdump.pcapng,application/pcapng"
              className="hidden"
            />
            <button
              id="btn-upload-pcap"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 rotate-180" />
              <span>Upload .PCAP / .PCAPNG</span>
            </button>
          </div>
        </div>

        {/* Traces Bar */}
        <div className="mt-3.5 pt-3 border-t border-slate-800 flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center gap-2 text-slate-400">
            <Cpu className="w-3.5 h-3.5 text-blue-400" />
            <span className="font-semibold uppercase tracking-wider text-[11px] text-slate-400">
              Loaded Traces ({scenarios.length}):
            </span>
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 max-w-full">
            {scenarios.length === 0 ? (
              <span className="text-slate-400 italic text-[11px]">
                No files loaded yet. Upload a real .pcap or create one in the Testbed Lab.
              </span>
            ) : (
              <>
                {scenarios.map((s) => {
                  const isSelected = selectedScenario?.id === s.id;
                  return (
                    <button
                      key={s.id}
                      id={`scenario-tab-${s.id}`}
                      onClick={() => onSelectScenario(s)}
                      className={`px-3 py-1 rounded-md text-xs whitespace-nowrap transition-all cursor-pointer font-medium ${
                        isSelected
                          ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/30'
                          : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white border border-slate-700/60'
                      }`}
                    >
                      {s.name}
                    </button>
                  );
                })}
                {onClearTraces && scenarios.length > 0 && (
                  <button
                    onClick={onClearTraces}
                    className="text-xs text-rose-400 hover:text-rose-300 ml-2 px-2 py-0.5 rounded hover:bg-rose-950/40 transition-colors"
                  >
                    Clear All
                  </button>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
