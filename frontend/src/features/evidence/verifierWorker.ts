import { verifyEvidenceBundle } from './verifierCore';
import type { EvidenceBundle, VerificationReport, VerificationTrustAnchors } from './types';

export interface VerifierWorkerInput {
  id: string;
  type: 'VERIFY';
  bundle: EvidenceBundle;
  trustAnchors: VerificationTrustAnchors;
}

export interface VerifierWorkerOutput {
  id: string;
  report?: VerificationReport;
  error?: string;
}

self.onmessage = (e: MessageEvent<VerifierWorkerInput>) => {
  const { id, type, bundle, trustAnchors } = e.data;
  if (type === 'VERIFY') {
    try {
      const report = verifyEvidenceBundle(bundle, trustAnchors);
      const output: VerifierWorkerOutput = { id, report };
      self.postMessage(output);
    } catch (err) {
      const output: VerifierWorkerOutput = {
        id,
        error: err instanceof Error ? err.message : String(err),
      };
      self.postMessage(output);
    }
  }
};
