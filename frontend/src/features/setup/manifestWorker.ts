import canonicalize from 'canonicalize';
import { sha256Hex } from '../../lib/crypto';

export interface ManifestWorkerInput {
  type: 'CANONICALIZE_AND_DIGEST';
  id: string;
  payload: unknown;
}

export interface ManifestWorkerOutput {
  id: string;
  canonicalJson: string;
  digest: string; // sha256:...
  byteLength: number;
  error?: string;
}

self.onmessage = (e: MessageEvent<ManifestWorkerInput>) => {
  const { id, payload } = e.data;
  try {
    const canonical = canonicalize(payload) ?? '{}';
    const utf8Bytes = new TextEncoder().encode(canonical);
    const hex = sha256Hex(utf8Bytes);
    const result: ManifestWorkerOutput = {
      id,
      canonicalJson: canonical,
      digest: `sha256:${hex}`,
      byteLength: utf8Bytes.length,
    };
    self.postMessage(result);
  } catch (err) {
    self.postMessage({
      id,
      canonicalJson: '',
      digest: '',
      byteLength: 0,
      error: err instanceof Error ? err.message : String(err),
    });
  }
};
