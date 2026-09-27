import React from 'react';
import { Info, Cpu, ShieldCheck, Lock, Activity, Award } from 'lucide-react';
import { AiPrediction, EspTrafficFeatures, MLPredictions } from '../types';

interface AiTrafficAnalysisProps {
  features: EspTrafficFeatures;
  prediction: AiPrediction;
  mlPredictions?: MLPredictions | null;
  mlWarning?: string | null;
}

const TARGET_DISPLAY_NAMES: Record<string, string> = {
  encryption: 'Encryption Algorithm',
  hash: 'Integrity / Hash Function',
  dh_group: 'Diffie-Hellman Key Exchange',
  pfs_group: 'Perfect Forward Secrecy (PFS)',
};

const CLASS_HUMAN_NAMES: Record<string, string> = {
  AES256: 'AES-256',
  AES128: 'AES-128',
  SHA256: 'SHA-256',
  SHA384: 'SHA-384',
  DH14: 'DH Group 14 (MODP 2048-bit)',
  DH15: 'DH Group 15 (MODP 3072-bit)',
  NOPFS: 'Disabled (No PFS)',
  PFS14: 'Enabled (DH Group 14)',
  PFS15: 'Enabled (DH Group 15)',
};

export const AiTrafficAnalysis: React.FC<AiTrafficAnalysisProps> = ({
  features,
  prediction,
  mlPredictions,
  mlWarning,
}) => {
  const getConfidenceBadge = (confidence: number | null) => {
    if (confidence === null) return { label: 'UNKNOWN', cls: 'bg-slate-100 text-slate-600 border-slate-200' };
    if (confidence >= 0.8) return { label: `HIGH (${(confidence * 100).toFixed(1)}%)`, cls: 'bg-emerald-50 text-emerald-700 border-emerald-200 font-bold' };
    if (confidence >= 0.55) return { label: `MEDIUM (${(confidence * 100).toFixed(1)}%)`, cls: 'bg-amber-50 text-amber-700 border-amber-200 font-bold' };
    return { label: `LOW (${(confidence * 100).toFixed(1)}%)`, cls: 'bg-rose-50 text-rose-700 border-rose-200 font-bold' };
  };

  return (
    <div className="space-y-6">

      {/* Section Info Banner */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 flex items-start gap-3">
        <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
        <div className="text-xs text-blue-800 leading-relaxed">
          <strong>How inference works:</strong> When the ML service is available, trained models estimate cryptographic parameters from 18 capture features. Workload labels use a separate rule-based ESP shape baseline. Neither method decrypts payloads or confirms application identity.
        </div>
      </div>

      {/* ─── NEW ML CRYPTOGRAPHIC PARAMETER INFERENCE SECTION ─── */}
      {mlPredictions ? (
        <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
          <div className="p-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-2">
            <div>
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-blue-600" />
                <h3 className="text-sm font-bold text-slate-900">
                  ML Cryptographic Parameter Predictions (Unknown PCAP Pipeline)
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-semibold">
                  ML INFERRED
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Multi-target Random Forest models trained on 18 extracted packet &amp; flow features
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
              <span>Models Loaded: <strong className="text-slate-900">4 / 4</strong></span>
              <span>·</span>
              <span>Features: <strong className="text-slate-900">18</strong></span>
            </div>
          </div>

          <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {(['encryption', 'hash', 'dh_group', 'pfs_group'] as const).map((targetKey) => {
              const res = mlPredictions[targetKey];
              if (!res) return null;
              const badge = getConfidenceBadge(res.confidence);
              const predictedLabel = CLASS_HUMAN_NAMES[res.prediction] || res.prediction;

              return (
                <div key={targetKey} className="bg-slate-50 border border-slate-200 rounded-lg p-3.5 space-y-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className="text-[11px] font-semibold text-slate-500">
                        {TARGET_DISPLAY_NAMES[targetKey]}
                      </span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${badge.cls}`}>
                        {badge.label}
                      </span>
                    </div>

                    <div className="text-sm font-bold text-slate-900 font-mono mt-1 truncate" title={predictedLabel}>
                      {predictedLabel}
                    </div>
                  </div>

                  {/* Probabilities Breakdown */}
                  <div className="space-y-1.5 pt-2 border-t border-slate-200">
                    <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400 block">
                      Class Probabilities:
                    </span>
                    {Object.entries(res.probabilities || {}).map(([clsName, prob]) => {
                      const isWinner = clsName === res.prediction;
                      const percentage = (prob * 100).toFixed(1);
                      return (
                        <div key={clsName} className="space-y-0.5">
                          <div className="flex justify-between text-[11px] font-mono">
                            <span className={isWinner ? 'font-bold text-slate-900' : 'text-slate-500'}>
                              {CLASS_HUMAN_NAMES[clsName] || clsName}
                            </span>
                            <span className={isWinner ? 'font-bold text-blue-700' : 'text-slate-500'}>
                              {percentage}%
                            </span>
                          </div>
                          <div className="w-full bg-slate-200 rounded-full h-1 overflow-hidden">
                            <div
                              className={`h-1 rounded-full transition-all duration-300 ${
                                isWinner ? 'bg-blue-600' : 'bg-slate-400'
                              }`}
                              style={{ width: `${Math.max(prob * 100, 2)}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : mlWarning ? (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-800">
          <strong>ML Notice:</strong> {mlWarning}
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Classification Results */}
        <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
          <div className="p-4 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Workload Traffic Classification</h3>
              <p className="text-xs text-slate-500">ESP shape heuristic · relative scores</p>
            </div>
            <div className="text-right">
              <span className="text-xs font-medium text-slate-500 block">Top prediction</span>
              <span className="text-sm font-bold text-slate-900">{prediction.predictedClass}</span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs table-compact">
              <thead>
                <tr>
                  <th>Traffic Class</th>
                  <th>Relative score</th>
                  <th className="w-40">Distribution</th>
                </tr>
              </thead>
              <tbody>
                {prediction.probabilities.map((item) => {
                  const isTop = item.category === prediction.predictedClass;
                  return (
                    <tr key={item.category} className={isTop ? 'bg-blue-50' : 'hover:bg-slate-50'}>
                      <td className={`font-medium ${isTop ? 'text-blue-800' : 'text-slate-700'}`}>
                        <span className={isTop ? 'font-bold' : ''}>{item.category}</span>
                      </td>
                      <td className="font-mono font-semibold text-slate-900">{item.probability}%</td>
                      <td>
                        <div className="w-full bg-slate-200 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-1.5 rounded-full transition-all duration-300 ${isTop ? 'bg-blue-600' : 'bg-slate-400'}`}
                            style={{ width: `${Math.max(item.probability, 2)}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="px-4 py-3 bg-slate-50 border-t border-slate-200 flex items-center justify-between text-xs">
            <span className="text-slate-500">Traffic pattern match</span>
            <span className="font-mono font-bold text-slate-900">{prediction.confidenceScore}%</span>
          </div>
        </div>

        {/* Extracted Flow Features */}
        <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
          <div className="p-4 border-b border-slate-200">
            <h3 className="text-sm font-semibold text-slate-900">Extracted ESP Flow Features</h3>
            <p className="text-xs text-slate-500">Statistical shape evidence for workload pattern matching</p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs table-compact">
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="text-slate-600">Payload Entropy (bits)</td>
                  <td className="font-mono font-semibold text-slate-900">{features.calculatedEntropy?.toFixed(4) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Avg Packet Length (bytes)</td>
                  <td className="font-mono font-semibold text-slate-900">{features.meanPacketLength?.toFixed(1) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Std Dev Packet Length</td>
                  <td className="font-mono font-semibold text-slate-900">{features.stdPacketLength?.toFixed(1) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Mean Inter-Arrival Time (ms)</td>
                  <td className="font-mono font-semibold text-slate-900">{features.meanInterArrivalTimeMs?.toFixed(2) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Flow Duration (ms)</td>
                  <td className="font-mono font-semibold text-slate-900">{features.flowDurationMs?.toFixed(1) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">ESP Packet Count</td>
                  <td className="font-mono font-semibold text-slate-900">{features.packetCount ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Burst Ratio</td>
                  <td className="font-mono font-semibold text-slate-900">{features.burstRatio?.toFixed(2) ?? 'N/A'}</td>
                </tr>
                <tr>
                  <td className="text-slate-600">Flow Symmetry Ratio</td>
                  <td className="font-mono font-semibold text-slate-900">{features.flowSymmetry?.toFixed(3) ?? 'N/A'}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
};
