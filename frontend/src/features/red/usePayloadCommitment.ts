import { useEffect, useRef, useState } from 'react';
import { computeCommitment, sha256Digest } from '../../lib/crypto';
import type { Digest } from '../../lib/schemas';
import {
  getUtf8ByteCount,
  estimateTokenCount,
  MAX_PAYLOAD_TEXT_BYTES,
  MAX_PAYLOAD_BODY_BYTES,
} from './byteUtils';
import type { CommitmentWorkerInput, CommitmentWorkerOutput } from './commitmentWorker';

export interface PayloadCommitmentResult {
  payloadDigest: Digest;
  commitment: Digest;
  byteCount: number;
  charCount: number;
  tokenEstimate: number;
  isOverTextLimit: boolean;
  isOverBodyLimit: boolean;
  isComputing: boolean;
  error: string | null;
}

/**
 * Synchronous computation fallback for unit tests and environments without Web Worker support.
 */
export function computePayloadCommitmentSync(
  domain: string,
  payloadText: string,
  nonce: string
): PayloadCommitmentResult {
  try {
    const byteCount = getUtf8ByteCount(payloadText);
    const charCount = payloadText.length;
    const tokenEstimate = estimateTokenCount(byteCount);

    const payloadDigest = sha256Digest(payloadText);
    const commitment = computeCommitment(domain, payloadText, nonce);

    return {
      payloadDigest,
      commitment,
      byteCount,
      charCount,
      tokenEstimate,
      isOverTextLimit: byteCount > MAX_PAYLOAD_TEXT_BYTES,
      isOverBodyLimit: byteCount > MAX_PAYLOAD_BODY_BYTES,
      isComputing: false,
      error: null,
    };
  } catch (err) {
    return {
      payloadDigest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' as Digest,
      commitment: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' as Digest,
      byteCount: 0,
      charCount: 0,
      tokenEstimate: 0,
      isOverTextLimit: false,
      isOverBodyLimit: false,
      isComputing: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * React hook that offloads domain-separated commitment and SHA-256 payload digest
 * computation to a background Web Worker, ensuring main thread 60fps responsiveness
 * even on maximum 64 KiB text payloads.
 */
export function usePayloadCommitment(
  domain: string,
  payloadText: string,
  nonce: string
): PayloadCommitmentResult {
  const [result, setResult] = useState<PayloadCommitmentResult>(() =>
    computePayloadCommitmentSync(domain, payloadText, nonce)
  );

  const workerRef = useRef<Worker | null>(null);
  const msgIdRef = useRef<number>(0);

  useEffect(() => {
    let isWorkerSupported = false;
    try {
      if (typeof window !== 'undefined' && typeof Worker !== 'undefined') {
        if (!workerRef.current) {
          workerRef.current = new Worker(
            new URL('./commitmentWorker.ts', import.meta.url),
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
      setResult(computePayloadCommitmentSync(domain, payloadText, nonce));
      return;
    }

    setResult((prev) => ({ ...prev, isComputing: true }));

    const handleMessage = (e: MessageEvent<CommitmentWorkerOutput>) => {
      if (e.data.id === String(currentMsgId)) {
        if (e.data.error) {
          setResult((prev) => ({
            ...prev,
            isComputing: false,
            error: e.data.error ?? null,
          }));
        } else {
          setResult({
            payloadDigest: e.data.payloadDigest,
            commitment: e.data.commitment,
            byteCount: e.data.byteCount,
            charCount: e.data.charCount,
            tokenEstimate: e.data.tokenEstimate,
            isOverTextLimit: e.data.byteCount > MAX_PAYLOAD_TEXT_BYTES,
            isOverBodyLimit: e.data.byteCount > MAX_PAYLOAD_BODY_BYTES,
            isComputing: false,
            error: null,
          });
        }
      }
    };

    const worker = workerRef.current;
    worker.addEventListener('message', handleMessage);

    const message: CommitmentWorkerInput = {
      id: String(currentMsgId),
      domain,
      payloadText,
      nonce,
    };
    worker.postMessage(message);

    return () => {
      worker.removeEventListener('message', handleMessage);
    };
  }, [domain, payloadText, nonce]);

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
