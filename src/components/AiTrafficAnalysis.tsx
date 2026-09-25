import React from 'react';
import { Cpu, Activity, Info, BarChart2, Zap, HelpCircle } from 'lucide-react';
import { AiPrediction, EspTrafficFeatures } from '../types';

interface AiTrafficAnalysisProps {
  features: EspTrafficFeatures;
  prediction: AiPrediction;
}

export const AiTrafficAnalysis: React.FC<AiTrafficAnalysisProps> = ({
  features,
  prediction,
}) => {
  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-purple-950/80 border border-purple-800 flex items-center justify-center text-purple-400">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span>AI Encrypted Traffic Fingerprinting (ESP Payload)</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-semibold">
                Supervised Random Forest / Shape Analysis
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Inferring application protocols hidden inside opaque ciphertext without decryption
            </p>
          </div>
        </div>

        {/* Confidence Badge */}
        <div className="flex items-center gap-2 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700/60 self-start sm:self-auto">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-xs text-slate-300">Model Confidence:</span>
          <span className="text-xs font-bold text-emerald-400">
            {prediction.confidenceScore}%
          </span>
        </div>
      </div>

      {/* Honest Architecture Explainer Banner */}
      <div className="mt-4 p-3 bg-blue-950/30 border border-blue-900/50 rounded-lg text-xs text-blue-200 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-blue-300 font-semibold">Where Real AI Operates (NTRO Assessment Core):</strong>{' '}
          Reading algorithm names from the IKE handshake is <em>deterministic parsing</em>. In contrast, ESP packets are cryptographically unreadable. The machine learning model analyzes the statistical "shape"—packet length distributions, inter-arrival time (IAT), burst cadence, and flow symmetry—to infer user activity without breaking the encryption.
        </div>
      </div>

      {/* Main Grid: Probability Distributions & Extracted Flow Features */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mt-5">
        
        {/* Left: Probabilities */}
        <div className="lg:col-span-6 space-y-3.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <BarChart2 className="w-3.5 h-3.5 text-purple-400" />
              Class Probabilities
            </span>
            <span className="text-[11px] text-slate-500">Softmax Normalized</span>
          </div>

          <div className="space-y-2.5">
            {prediction.probabilities.map((item) => {
              const isTop = item.category === prediction.predictedClass;
              return (
                <div
                  key={item.category}
                  className={`p-2.5 rounded-lg border transition-all ${
                    isTop
                      ? 'bg-purple-950/40 border-purple-700/80 text-white'
                      : 'bg-slate-800/40 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex justify-between text-xs font-medium mb-1.5">
                    <span className="flex items-center gap-1.5">
                      {isTop && <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />}
                      <span className={isTop ? 'font-bold text-purple-200' : ''}>{item.category}</span>
                    </span>
                    <span className={`font-mono font-bold ${isTop ? 'text-purple-300' : 'text-slate-400'}`}>
                      {item.probability}%
                    </span>
                  </div>
                  
                  <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className={`h-1.5 rounded-full transition-all duration-500 ${
                        isTop ? 'bg-gradient-to-r from-purple-500 to-blue-500' : 'bg-slate-600'
                      }`}
                      style={{ width: `${Math.max(item.probability, 2)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Feature Extraction Vectors */}
        <div className="lg:col-span-6 space-y-3.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-400" />
              Extracted Statistical Shape Vector
            </span>
            <span className="text-[11px] text-slate-500">{features.packetCount} packets sampled</span>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            
            <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60">
              <div className="text-[11px] text-slate-400">Mean Packet Length</div>
              <div className="text-base font-bold text-white mt-0.5">
                {features.meanPacketLength} <span className="text-xs font-normal text-slate-400">bytes</span>
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">Range: {features.minPacketLength} - {features.maxPacketLength}b</div>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60">
              <div className="text-[11px] text-slate-400">Length Std. Deviation</div>
              <div className="text-base font-bold text-white mt-0.5">
                ±{features.stdPacketLength} <span className="text-xs font-normal text-slate-400">bytes</span>
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">
                {features.stdPacketLength < 50 ? 'Low variance (Uniform stream)' : 'High variance (Variable data)'}
              </div>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60">
              <div className="text-[11px] text-slate-400">Inter-Arrival Time (IAT)</div>
              <div className="text-base font-bold text-white mt-0.5">
                {features.meanInterArrivalTimeMs.toFixed(1)} <span className="text-xs font-normal text-slate-400">ms</span>
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">Packet spacing cadence</div>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60">
              <div className="text-[11px] text-slate-400">Shannon Entropy</div>
              <div className="text-base font-bold text-emerald-400 mt-0.5">
                {features.calculatedEntropy} <span className="text-xs font-normal text-slate-400">/ 8.00</span>
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">Verified High Ciphertext</div>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60">
              <div className="text-[11px] text-slate-400">Burst Index</div>
              <div className="text-base font-bold text-white mt-0.5">
                {(features.burstRatio * 100).toFixed(0)}%
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">Continuous vs Idle Gaps</div>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60">
              <div className="text-[11px] text-slate-400">Flow Symmetry</div>
              <div className="text-base font-bold text-white mt-0.5">
                {(features.flowSymmetry * 100).toFixed(0)}%
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">Uplink / Downlink balance</div>
            </div>

          </div>
        </div>

      </div>

      {/* Feature Attribution Explainer */}
      <div className="mt-5 pt-4 border-t border-slate-800">
        <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
          <HelpCircle className="w-3.5 h-3.5 text-blue-400" />
          AI Decision Rationale &amp; Feature Attribution
        </h4>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {prediction.primaryFeatures.map((feat, idx) => (
            <div key={idx} className="bg-slate-800/40 border border-slate-800 p-2.5 rounded-lg text-xs">
              <div className="flex items-center justify-between text-slate-400">
                <span className="font-medium text-slate-300">{feat.name}</span>
                <span className="text-[10px] font-semibold text-blue-300 bg-blue-950 px-1.5 py-0.5 rounded">
                  {feat.value}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                {feat.explanation}
              </p>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
};
