import React, { useState, useId } from 'react';
import {
  Send,
  RefreshCw,
  KeyRound,
  FileCode,
  FileText,
  AlertOctagon,
  Loader2,
  Shield,
  Layers,
} from 'lucide-react';
import { Panel } from '../../components/Panel';
import { Digest } from '../../components/Digest';
import {
  formatByteCount,
  generateSecretNonce,
  MAX_PAYLOAD_TEXT_BYTES,
  MAX_PAYLOAD_BODY_BYTES,
} from './byteUtils';
import {
  usePayloadCommitment,
  computePayloadCommitmentSync,
} from './usePayloadCommitment';
import { ReceiptCard } from './ReceiptCard';
import { DevConflictDrawer, PRESET_ATTACKS } from './DevConflictDrawer';
import { arenaClient } from '../../lib/api/client';
import type { AttackReceipt, Epoch, SubmitAttackRequest } from '../../lib/schemas';

export interface PayloadWorkshopProps {
  experimentId: string;
  domain: string;
  epoch: Epoch;
  onAttackSubmitted?: (receipt: AttackReceipt) => void;
  className?: string;
}

export const PayloadWorkshop: React.FC<PayloadWorkshopProps> = ({
  experimentId,
  domain,
  epoch,
  onAttackSubmitted,
  className = '',
}) => {
  const textareaId = useId();
  const errorRegionId = useId();
  const counterId = useId();

  // Mode: Plain Text vs Automated Script
  const [inputMode, setInputMode] = useState<'text' | 'script'>('text');

  // Active in-memory attack payload (never persisted to localStorage)
  const [payloadText, setPayloadText] = useState<string>(PRESET_ATTACKS.JAILBREAK);

  // Secret Nonce generated via crypto.getRandomValues
  const [nonce, setNonce] = useState<string>(() => generateSecretNonce());

  // Idempotency Key (Scope: domain + experiment + epoch + action + idempotencyKey)
  const [idempotencyKey, setIdempotencyKey] = useState<string>(
    () => `idemp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
  );

  // Web Worker-backed live commitment & UTF-8 byte counter
  const {
    payloadDigest,
    commitment,
    byteCount,
    charCount,
    tokenEstimate,
    isOverTextLimit,
    isComputing,
    error: workerError,
  } = usePayloadCommitment(domain, payloadText, nonce);

  // Submission & Receipt State (Invariant 2: No optimistic UI)
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [lastReceipt, setLastReceipt] = useState<AttackReceipt | null>(null);
  const [submissionError, setSubmissionError] = useState<string | null>(null);

  // Dev Drawer test results
  const [lastTestResult, setLastTestResult] = useState<{
    type: 'success' | 'conflict' | 'info';
    title: string;
    message: string;
  } | null>(null);

  // Regenerate nonce
  const handleRegenerateNonce = () => {
    setNonce(generateSecretNonce());
  };

  // Regenerate idempotency key
  const handleRegenerateIdempotencyKey = () => {
    setIdempotencyKey(`idemp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
    setSubmissionError(null);
  };

  // Primary Submission to Broker
  const handleSubmitPayload = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!payloadText.trim() || isOverTextLimit || isSubmitting) return;

    setIsSubmitting(true);
    setSubmissionError(null);

    try {
      const req: SubmitAttackRequest = {
        text_artifact: payloadText,
        commitment,
        nonce,
      };

      const receipt = await arenaClient.submitAttack(
        experimentId,
        req,
        idempotencyKey,
        epoch,
        'red'
      );

      setLastReceipt(receipt);
      onAttackSubmitted?.(receipt);
      setLastTestResult({
        type: 'success',
        title: 'PAYLOAD SUBMITTED & COMMITTED',
        message: `Broker issued ${receipt.receipt_id} for turn ${receipt.turn}`,
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setSubmissionError(errMsg);
      setLastTestResult({
        type: 'conflict',
        title: 'SUBMISSION REJECTED',
        message: errMsg,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Dev Action: Replay Idempotency
  const handleReplayIdempotency = async () => {
    setIsSubmitting(true);
    setSubmissionError(null);

    try {
      const req: SubmitAttackRequest = {
        text_artifact: payloadText,
        commitment,
        nonce,
      };

      const receipt = await arenaClient.submitAttack(
        experimentId,
        req,
        idempotencyKey,
        epoch,
        'red'
      );

      setLastReceipt(receipt);
      setLastTestResult({
        type: 'success',
        title: 'IDEMPOTENT REPLAY VERIFIED',
        message: `Re-submission with identical key returned existing receipt ${receipt.receipt_id} without re-execution (Turn ${receipt.turn}).`,
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setSubmissionError(errMsg);
      setLastTestResult({
        type: 'conflict',
        title: 'REPLAY FAILED',
        message: errMsg,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Dev Action: Trigger 409 Conflict
  const handleTriggerConflict = async () => {
    setIsSubmitting(true);
    setSubmissionError(null);

    try {
      // Modify payload text slightly while keeping identical idempotencyKey
      const conflictingText = `${payloadText} [ALTERED_${Date.now()}]`;
      const conflictingCommitment = computePayloadCommitmentSync(domain, conflictingText, nonce).commitment;

      const req: SubmitAttackRequest = {
        text_artifact: conflictingText,
        commitment: conflictingCommitment,
        nonce,
      };

      await arenaClient.submitAttack(
        experimentId,
        req,
        idempotencyKey,
        epoch,
        'red'
      );

      setLastTestResult({
        type: 'info',
        title: 'UNEXPECTED ACCEPTANCE',
        message: 'Conflict was expected but request succeeded.',
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setSubmissionError(errMsg);
      setLastTestResult({
        type: 'conflict',
        title: '409 CONFLICT DEMONSTRATED',
        message: `Broker correctly rejected modified body under same key: ${errMsg}`,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Dev Action: Load Oversized Payload
  const handleLoadOversized = () => {
    const huge = 'A'.repeat(MAX_PAYLOAD_TEXT_BYTES + 64);
    setPayloadText(huge);
    setLastReceipt(null);
    setLastTestResult({
      type: 'conflict',
      title: 'OVERSIZED BUFFER LOADED',
      message: `Payload text size (${(MAX_PAYLOAD_TEXT_BYTES + 64).toLocaleString()} bytes) exceeds wire limit (${MAX_PAYLOAD_TEXT_BYTES.toLocaleString()} bytes). Submit blocked client-side.`,
    });
  };

  // Load Preset
  const handleLoadPreset = (preset: string) => {
    setPayloadText(preset);
    setLastReceipt(null);
    setSubmissionError(null);
  };

  const percentUsed = Math.min(100, Math.round((byteCount / MAX_PAYLOAD_TEXT_BYTES) * 100));

  return (
    <div className={`space-y-6 ${className}`}>
      {/* LEFT PANEL: PAYLOAD COMMITMENT WORKSHOP */}
      <Panel
        label="01 — PAYLOAD COMMITMENT WORKSHOP"
        meta={`DOMAIN: ${domain} · EPOCH 0${epoch}`}
        className="bg-s1"
      >
        <form onSubmit={handleSubmitPayload} className="space-y-5">
          {/* Input Mode Selector */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-bd pb-3">
            <div className="flex items-center gap-1.5 rounded-[2px] border border-bd bg-s2 p-0.5">
              <button
                type="button"
                onClick={() => setInputMode('text')}
                className={`flex items-center gap-1.5 rounded-[2px] px-3 py-1 font-mono text-xs font-medium transition-colors ${
                  inputMode === 'text'
                    ? 'bg-cy/20 text-cy border border-cy/40'
                    : 'text-mut hover:text-tx'
                }`}
              >
                <FileText className="h-3.5 w-3.5" aria-hidden="true" />
                <span>PLAIN TEXT</span>
              </button>
              <button
                type="button"
                onClick={() => setInputMode('script')}
                className={`flex items-center gap-1.5 rounded-[2px] px-3 py-1 font-mono text-xs font-medium transition-colors ${
                  inputMode === 'script'
                    ? 'bg-cy/20 text-cy border border-cy/40'
                    : 'text-mut hover:text-tx'
                }`}
              >
                <FileCode className="h-3.5 w-3.5" aria-hidden="true" />
                <span>AUTOMATED SCRIPT</span>
              </button>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs text-mut">
              <Layers className="h-3.5 w-3.5 text-cy" aria-hidden="true" />
              <span>LIMIT: {formatByteCount(MAX_PAYLOAD_TEXT_BYTES)} TEXT / {formatByteCount(MAX_PAYLOAD_BODY_BYTES)} BODY</span>
            </div>
          </div>

          {/* Textarea Field with accessible labeling */}
          <div>
            <div className="flex items-center justify-between">
              <label
                htmlFor={textareaId}
                className="font-mono text-xs font-medium tracking-wide text-tx uppercase"
              >
                ADVERSARIAL ATTACK PAYLOAD
              </label>
              <span id={counterId} className="font-mono text-xs text-mut">
                {charCount.toLocaleString()} chars · <span className="text-tx font-medium">{formatByteCount(byteCount)}</span> ({percentUsed}%)
              </span>
            </div>

            <div className="mt-2 relative">
              <textarea
                id={textareaId}
                rows={7}
                value={payloadText}
                onChange={(e) => setPayloadText(e.target.value)}
                aria-describedby={`${counterId} ${errorRegionId}`}
                aria-invalid={isOverTextLimit}
                placeholder="Enter adversarial probe, prompt injection string, or evasion payload..."
                className={`w-full rounded-[2px] border bg-s2 p-3 font-mono text-xs leading-relaxed text-tx placeholder-mut/50 focus:outline-none focus:ring-2 focus:ring-cy ${
                  isOverTextLimit ? 'border-bad ring-1 ring-bad' : 'border-bd'
                }`}
              />

              {/* Progress bar showing byte consumption */}
              <div
                className="absolute bottom-1 left-1 right-1 h-0.5 bg-bd overflow-hidden"
                aria-hidden="true"
              >
                <div
                  className={`h-full transition-all duration-150 ${
                    isOverTextLimit
                      ? 'bg-bad'
                      : percentUsed > 85
                        ? 'bg-am'
                        : 'bg-cy'
                  }`}
                  style={{ width: `${percentUsed}%` }}
                />
              </div>
            </div>

            {/* Live Error and Stats Region */}
            <div
              id={errorRegionId}
              role="alert"
              aria-live="polite"
              className="mt-2 min-h-[22px] flex flex-wrap items-center justify-between text-xs font-mono"
            >
              {isOverTextLimit ? (
                <div className="flex items-center gap-1.5 text-bad">
                  <AlertOctagon className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>PAYLOAD EXCEEDS 65,536 BYTE LIMIT ({formatByteCount(byteCount)}). SUBMISSION BLOCKED.</span>
                </div>
              ) : workerError ? (
                <div className="flex items-center gap-1.5 text-bad">
                  <AlertOctagon className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>WORKER ERROR: {workerError}</span>
                </div>
              ) : (
                <div className="text-mut flex items-center gap-2">
                  <span>UTF-8 BYTE COUNT: <span className="text-tx">{byteCount.toLocaleString()} B</span></span>
                  <span>·</span>
                  <span>TOKEN ESTIMATE: <span className="text-tx">~{tokenEstimate} tokens</span> <span className="rounded bg-s2 border border-bd px-1 py-0.2 text-[10px] text-mut uppercase">ESTIMATE</span></span>
                </div>
              )}
            </div>
          </div>

          {/* Secret Nonce Field */}
          <div className="rounded-[2px] border border-bd bg-s2 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5">
                <KeyRound className="h-4 w-4 text-am" aria-hidden="true" />
                <span className="font-mono text-xs font-medium text-tx uppercase">
                  SECRET NONCE (128-BIT ENTROPY)
                </span>
              </div>
              <button
                type="button"
                onClick={handleRegenerateNonce}
                className="flex items-center gap-1 font-mono text-xs text-cy hover:text-tx focus:ring-1 focus:ring-cy focus:outline-none"
              >
                <RefreshCw className="h-3 w-3" aria-hidden="true" />
                <span>REGENERATE NONCE</span>
              </button>
            </div>
            <div className="mt-2 flex items-center justify-between rounded-[2px] border border-bd bg-bg px-3 py-1.5 font-mono text-xs text-tx break-all">
              <span>{nonce}</span>
              <span className="ml-2 shrink-0 text-[10px] text-mut">crypto.getRandomValues</span>
            </div>
            <p className="mt-1.5 text-[11px] text-mut">
              Salts the commitment to prevent dictionary attacks or rainbow-table inversion on short inputs.
            </p>
          </div>

          {/* Computed Hashes & Commitment */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-[2px] border border-bd bg-s2 p-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-mut uppercase">BARE PAYLOAD HASH</span>
                <span className="font-mono text-[10px] text-mut">SHA-256</span>
              </div>
              <div className="mt-2">
                <Digest hash={payloadDigest} />
              </div>
              <p className="mt-1 text-[11px] text-mut">
                Plaintext hash. Never matches domain commitment.
              </p>
            </div>

            <div className="rounded-[2px] border border-bd bg-s2 p-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1">
                  <Shield className="h-3.5 w-3.5 text-ok" aria-hidden="true" />
                  <span className="font-mono text-xs font-medium text-tx uppercase">SEALED COMMITMENT</span>
                </div>
                {isComputing ? (
                  <span className="font-mono text-[10px] text-cy animate-pulse">COMPUTING...</span>
                ) : (
                  <span className="font-mono text-[10px] text-ok">WORKER VERIFIED</span>
                )}
              </div>
              <div className="mt-2">
                <Digest hash={commitment} />
              </div>
              <p className="mt-1 text-[11px] text-mut">
                SHA-256(domain ‖ payload ‖ nonce).
              </p>
            </div>
          </div>

          {/* Idempotency Key Row */}
          <div className="rounded-[2px] border border-bd bg-s2 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-xs font-medium text-tx uppercase">
                IDEMPOTENCY KEY (DEDUPLICATION SCOPE)
              </span>
              <button
                type="button"
                onClick={handleRegenerateIdempotencyKey}
                className="flex items-center gap-1 font-mono text-xs text-cy hover:text-tx focus:ring-1 focus:ring-cy focus:outline-none"
              >
                <RefreshCw className="h-3 w-3" aria-hidden="true" />
                <span>NEW KEY</span>
              </button>
            </div>
            <div className="mt-2 flex items-center justify-between rounded-[2px] border border-bd bg-bg px-3 py-1.5 font-mono text-xs text-tx">
              <span className="break-all">{idempotencyKey}</span>
              <span className="ml-2 shrink-0 text-[10px] text-mut">HEADER: Idempotency-Key</span>
            </div>
          </div>

          {/* Submission Error Banner */}
          {submissionError && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-[2px] border border-bad/50 bg-bad/10 p-3 text-xs text-bad"
            >
              <AlertOctagon className="mt-0.5 h-4 w-4 shrink-0 text-bad" aria-hidden="true" />
              <div>
                <div className="font-mono font-semibold uppercase">SUBMISSION FAILED</div>
                <div className="mt-0.5 font-mono text-[11px]">{submissionError}</div>
              </div>
            </div>
          )}

          {/* Submit Action Button */}
          <div>
            <button
              type="submit"
              onClick={handleSubmitPayload}
              disabled={!payloadText.trim() || isOverTextLimit || isSubmitting}
              className="flex w-full items-center justify-center gap-2 rounded-[2px] border border-cy bg-cy/20 px-4 py-3 font-mono text-sm font-semibold tracking-wider text-cy transition-all hover:bg-cy/30 disabled:cursor-not-allowed disabled:border-bd disabled:bg-s2 disabled:text-mut focus:ring-2 focus:ring-cy focus:outline-none"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin text-cy" aria-hidden="true" />
                  <span>COMMITTING PAYLOAD TO BROKER...</span>
                </>
              ) : (
                <>
                  <Send className="h-4 w-4 text-cy" aria-hidden="true" />
                  <span>SUBMIT PAYLOAD TO BROKER</span>
                </>
              )}
            </button>
          </div>
        </form>
      </Panel>

      {/* Confirmed Receipt Card (Displayed only after broker confirmation) */}
      {lastReceipt && (
        <ReceiptCard
          receipt={lastReceipt}
          onDismiss={() => setLastReceipt(null)}
        />
      )}

      {/* Dev Idempotency & Conflict Testing Drawer */}
      <DevConflictDrawer
        onReplayIdempotency={handleReplayIdempotency}
        onTriggerConflict={handleTriggerConflict}
        onLoadOversized={handleLoadOversized}
        onLoadPreset={handleLoadPreset}
        isSubmitting={isSubmitting}
        lastTestResult={lastTestResult}
      />
    </div>
  );
};
