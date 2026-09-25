import { BackendCaptureAnalysis, MLAnalysisResult, MLAnalysisStage } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export async function analyzeCaptureWithBackend(file: File): Promise<BackendCaptureAnalysis> {
  const formData = new FormData();
  formData.append('file', file);

  const uploadResponse = await fetch(`${API_BASE_URL}/api/captures`, {
    method: 'POST',
    body: formData,
  });
  if (!uploadResponse.ok) {
    throw new Error(`Backend upload failed (${uploadResponse.status}).`);
  }

  const capture = await uploadResponse.json() as { capture_id?: string };
  if (!capture.capture_id) {
    throw new Error('Backend upload returned no capture ID.');
  }

  const jobResponse = await fetch(`${API_BASE_URL}/api/captures/${capture.capture_id}/analyze`, {
    method: 'POST',
  });
  if (!jobResponse.ok) {
    throw new Error(`Backend analysis job failed (${jobResponse.status}).`);
  }
  const job = await jobResponse.json() as { job_id?: string; status?: string; message?: string };
  if (!job.job_id) {
    throw new Error('Backend analysis job returned no job ID.');
  }

  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (job.status === 'COMPLETED') break;
    if (job.status === 'FAILED') {
      throw new Error(job.message || 'Backend analysis failed.');
    }
    await new Promise((resolve) => window.setTimeout(resolve, 100));
    const statusResponse = await fetch(`${API_BASE_URL}/api/analyze/${job.job_id}`);
    if (!statusResponse.ok) {
      throw new Error(`Backend analysis status failed (${statusResponse.status}).`);
    }
    Object.assign(job, await statusResponse.json());
  }
  if (job.status !== 'COMPLETED') {
    throw new Error('Backend analysis timed out.');
  }

  const analysisResponse = await fetch(`${API_BASE_URL}/api/captures/${capture.capture_id}/analysis`);
  if (!analysisResponse.ok) {
    throw new Error(`Backend analysis failed (${analysisResponse.status}).`);
  }
  return await analysisResponse.json() as BackendCaptureAnalysis;
}


// ============================================================
// ML ANALYSIS PIPELINE
// ============================================================

export interface MLAnalysisCallbacks {
  onStageChange: (stage: MLAnalysisStage) => void;
}

export async function runMLAnalysis(
  file: File,
  callbacks: MLAnalysisCallbacks,
): Promise<MLAnalysisResult> {
  const { onStageChange } = callbacks;

  onStageChange('UPLOADING');

  const formData = new FormData();
  formData.append('file', file);

  onStageChange('EXTRACTING');

  const response = await fetch(`${API_BASE_URL}/api/ml-analyze`, {
    method: 'POST',
    body: formData,
  });

  onStageChange('INFERRING');

  if (!response.ok) {
    let errorDetail: { code?: string; message?: string; details?: string } = {};
    try {
      const errBody = await response.json() as { detail?: typeof errorDetail };
      errorDetail = errBody.detail || {};
    } catch {
      // ignore parse failure
    }
    const code = errorDetail.code || 'UNKNOWN_ERROR';
    const message = errorDetail.message || `Request failed with status ${response.status}`;
    const details = errorDetail.details || '';
    throw Object.assign(new Error(message), { code, details });
  }

  onStageChange('ASSESSING');
  const result = await response.json() as MLAnalysisResult;
  onStageChange('COMPLETED');
  return result;
}

export async function checkMLHealth(): Promise<{ ok: boolean; message: string }> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/ml-health`);
    if (!response.ok) return { ok: false, message: `HTTP ${response.status}` };
    const data = await response.json() as { status?: string };
    return { ok: data.status === 'ok', message: data.status || 'unknown' };
  } catch (err) {
    return { ok: false, message: err instanceof Error ? err.message : 'Unreachable' };
  }
}