import { useEffect, useRef, useState } from 'react';
import { canonicalJson, sha256Digest } from '../../../lib/crypto';
import type { ManifestWorkerInput, ManifestWorkerOutput } from '../manifestWorker';

export interface UseManifestCanonicalizerResult {
  canonicalJson: string;
  digest: string;
  byteLength: number;
  isComputing: boolean;
  error: string | null;
}

export function useManifestCanonicalizer(payload: unknown): UseManifestCanonicalizerResult {
  const [result, setResult] = useState<UseManifestCanonicalizerResult>(() => {
    try {
      const canonical = canonicalJson(payload);
      const digest = sha256Digest(canonical);
      const byteLength = new TextEncoder().encode(canonical).length;
      return {
        canonicalJson: canonical,
        digest,
        byteLength,
        isComputing: false,
        error: null,
      };
    } catch (err) {
      return {
        canonicalJson: '',
        digest: '',
        byteLength: 0,
        isComputing: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  const workerRef = useRef<Worker | null>(null);
  const msgIdRef = useRef<number>(0);

  useEffect(() => {
    // Check if Web Worker is supported in environment (e.g. browser vs JSDOM)
    let isWorkerSupported = false;
    try {
      if (typeof window !== 'undefined' && typeof Worker !== 'undefined') {
        if (!workerRef.current) {
          workerRef.current = new Worker(
            new URL('../manifestWorker.ts', import.meta.url),
            { type: 'module' }
          );
        }
        isWorkerSupported = true;
      }
    } catch {
      isWorkerSupported = false;
    }

    const currentMsgId = ++msgIdRef.current;

    if (!isWorkerSupported || !workerRef.current) {
      // Synchronous fallback (guarantees Vitest and non-worker environments work)
      try {
        const canonical = canonicalJson(payload);
        const digest = sha256Digest(canonical);
        const byteLength = new TextEncoder().encode(canonical).length;
        setResult({
          canonicalJson: canonical,
          digest,
          byteLength,
          isComputing: false,
          error: null,
        });
      } catch (err) {
        setResult((prev) => ({
          ...prev,
          isComputing: false,
          error: err instanceof Error ? err.message : String(err),
        }));
      }
      return;
    }

    // Set computing status
    setResult((prev) => ({ ...prev, isComputing: true }));

    const handleMessage = (e: MessageEvent<ManifestWorkerOutput>) => {
      if (e.data.id === String(currentMsgId)) {
        if (e.data.error) {
          setResult((prev) => ({
            ...prev,
            isComputing: false,
            error: e.data.error ?? null,
          }));
        } else {
          setResult({
            canonicalJson: e.data.canonicalJson,
            digest: e.data.digest,
            byteLength: e.data.byteLength,
            isComputing: false,
            error: null,
          });
        }
      }
    };

    const worker = workerRef.current;
    worker.addEventListener('message', handleMessage);

    const message: ManifestWorkerInput = {
      type: 'CANONICALIZE_AND_DIGEST',
      id: String(currentMsgId),
      payload,
    };
    worker.postMessage(message);

    return () => {
      worker.removeEventListener('message', handleMessage);
    };
  }, [payload]);

  // Clean up worker on unmount
  useEffect(() => {
    return () => {
      if (workerRef.current) {
        workerRef.current.terminate();
        workerRef.current = null;
      }
    };
  }, []);

  return result;
}

/**
 * Utility to format canonical JSON with formatted indents while preserving byte equality on strip
 */
export function formatJsonLines(canonicalStr: string): string[] {
  if (!canonicalStr) return [];
  try {
    const parsed = JSON.parse(canonicalStr);
    return JSON.stringify(parsed, null, 2).split('\n');
  } catch {
    return canonicalStr.split('\n');
  }
}
