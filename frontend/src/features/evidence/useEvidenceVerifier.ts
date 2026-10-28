import { useCallback, useEffect, useRef, useState } from 'react';
import { verifyEvidenceBundle } from './verifierCore';
import type { EvidenceBundle, VerificationReport, VerificationTrustAnchors } from './types';
import type { VerifierWorkerInput, VerifierWorkerOutput } from './verifierWorker';

export function useEvidenceVerifier() {
  const [isVerifying, setIsVerifying] = useState(false);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const workerRef = useRef<Worker | null>(null);
  const pendingRequests = useRef<
    Map<
      string,
      {
        resolve: (report: VerificationReport) => void;
        reject: (error: Error) => void;
      }
    >
  >(new Map());

  // Initialize Worker if supported in environment
  useEffect(() => {
    let worker: Worker | null = null;
    try {
      if (typeof Worker !== 'undefined') {
        worker = new Worker(new URL('./verifierWorker.ts', import.meta.url), {
          type: 'module',
        });
        worker.onmessage = (e: MessageEvent<VerifierWorkerOutput>) => {
          const { id, report: resReport, error: resError } = e.data;
          const handler = pendingRequests.current.get(id);
          if (handler) {
            pendingRequests.current.delete(id);
            if (resReport) {
              setReport(resReport);
              setIsVerifying(false);
              handler.resolve(resReport);
            } else {
              const err = new Error(resError || 'Verification failed');
              setError(err.message);
              setIsVerifying(false);
              handler.reject(err);
            }
          }
        };
        worker.onerror = (err) => {
          setIsVerifying(false);
          setError(err.message || 'Worker error');
        };
        workerRef.current = worker;
      }
    } catch {
      workerRef.current = null;
    }

    return () => {
      worker?.terminate();
      workerRef.current = null;
    };
  }, []);

  const verify = useCallback(
    async (
      bundle: EvidenceBundle,
      trustAnchors: VerificationTrustAnchors
    ): Promise<VerificationReport> => {
      setIsVerifying(true);
      setError(null);

      // If Web Worker is available, dispatch off-thread
      if (workerRef.current) {
        return new Promise<VerificationReport>((resolve, reject) => {
          const id = `ver_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
          pendingRequests.current.set(id, { resolve, reject });
          const input: VerifierWorkerInput = {
            id,
            type: 'VERIFY',
            bundle,
            trustAnchors,
          };
          workerRef.current?.postMessage(input);
        });
      }

      // Synchronous fallback (test environment or non-worker browser)
      try {
        const syncReport = verifyEvidenceBundle(bundle, trustAnchors);
        setReport(syncReport);
        setIsVerifying(false);
        return syncReport;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg);
        setIsVerifying(false);
        throw err;
      }
    },
    []
  );

  const reset = useCallback(() => {
    setReport(null);
    setError(null);
    setIsVerifying(false);
  }, []);

  return {
    verify,
    isVerifying,
    report,
    error,
    reset,
  };
}
