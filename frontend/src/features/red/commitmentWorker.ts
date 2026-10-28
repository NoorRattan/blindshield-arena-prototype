import { computeCommitment, sha256Digest } from '../../lib/crypto';
import type { Digest } from '../../lib/schemas';
import { getUtf8ByteCount, estimateTokenCount } from './byteUtils';

export interface CommitmentWorkerInput {
  id: string;
  domain: string;
  payloadText: string;
  nonce: string;
}

export interface CommitmentWorkerOutput {
  id: string;
  payloadDigest: Digest;
  commitment: Digest;
  byteCount: number;
  charCount: number;
  tokenEstimate: number;
  error?: string;
}

self.onmessage = (e: MessageEvent<CommitmentWorkerInput>) => {
  const { id, domain, payloadText, nonce } = e.data;
  try {
    const byteCount = getUtf8ByteCount(payloadText);
    const charCount = payloadText.length;
    const tokenEstimate = estimateTokenCount(byteCount);

    const payloadDigest = sha256Digest(payloadText);
    const commitment = computeCommitment(domain, payloadText, nonce);

    const result: CommitmentWorkerOutput = {
      id,
      payloadDigest,
      commitment,
      byteCount,
      charCount,
      tokenEstimate,
    };
    self.postMessage(result);
  } catch (err) {
    self.postMessage({
      id,
      payloadDigest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' as Digest,
      commitment: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' as Digest,
      byteCount: 0,
      charCount: 0,
      tokenEstimate: 0,
      error: err instanceof Error ? err.message : String(err),
    });
  }
};
