import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { AlertCircle, RefreshCw, KeyRound, Lock } from 'lucide-react';
import { PageHeader } from '../../components/PageHeader';
import { ErrorState } from '../../components/ErrorState';
import { ResidualRiskPanel } from '../../components/ResidualRiskPanel';
import { useArenaStore } from '../../state/useArenaStore';
import { arenaClient } from '../../lib/api/client';
import { EpochSchema, DigestSchema } from '../../lib/schemas';
import type {
  SetupFormData,
  SetupFieldErrors,
  ManifestDraftPayload,
  PreflightReport,
  SetupReceipt,
} from './types';
import { SetupWizard } from './components/SetupWizard';
import { ManifestPreviewPanel } from './components/ManifestPreviewPanel';
import { PreflightScannerPanel } from './components/PreflightScannerPanel';
import { ReceiptCard } from './components/ReceiptCard';

const INITIAL_FORM_DATA: SetupFormData = {
  domain: 'BAYORA-PILOT-01',
  epoch: 1,
  target_model: 'llama-3-8b-instruct-q4',
  inference_engine: 'vllm-v0.6.2',
  target_deadline_ms: 30000,
  output_max_tokens: 256,
  defense_image_digest: 'sha256:7f3a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  defense_mode: 'INPUT',
  defense_deadline_ms: 1000,
  prefix_cache_salt: 'server-assigned secret [embargoed]',
  body_max_bytes: 70000,
  text_max_bytes: 65536,
  queue_depth: 4,
  assurance_lane: 'shared_host_gvisor',
  dataset_catalog_id: 'JBB_HARMFUL_BENIGN_V1',
  interaction_mode: 'INTERACTIVE',
  disclosure_policy: 'SEALED_BATCH',
  budget_profile_id: 'DEMO_500_TURNS_BUDGET',
};

export const SetupPage: React.FC = () => {
  const role = useArenaStore((state) => state.role);
  const activeEpoch = useArenaStore((state) => state.epoch);

  const [formData, setFormData] = useState<SetupFormData>(INITIAL_FORM_DATA);
  const [errors, setErrors] = useState<SetupFieldErrors>({});
  const [receipt, setReceipt] = useState<SetupReceipt | null>(null);

  const [preflightReport, setPreflightReport] = useState<PreflightReport | null>(null);
  const [isScanningPreflight, setIsScanningPreflight] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [submitError, setSubmitError] = useState<{
    code: string;
    message: string;
    recovery: string;
  } | null>(null);

  // Fetch initial preflight scan on mount if operator
  const runPreflightScan = useCallback(async () => {
    setIsScanningPreflight(true);
    setSubmitError(null);
    try {
      const report = await arenaClient.runPreflight(role);
      setPreflightReport(report);
    } catch (err) {
      setSubmitError({
        code: 'AUDIT_UNAVAILABLE',
        message: err instanceof Error ? err.message : 'Preflight scan failed',
        recovery: 'Verify host gVisor daemon and witness reachability.',
      });
    } finally {
      setIsScanningPreflight(false);
    }
  }, [role]);

  useEffect(() => {
    if (role === 'operator') {
      runPreflightScan();
    }
  }, [role, runPreflightScan]);

  const handleFormChange = (updates: Partial<SetupFormData>) => {
    setFormData((prev) => ({ ...prev, ...updates }));
    // Clear field-specific error when modified
    setErrors((prev) => {
      const copy = { ...prev };
      Object.keys(updates).forEach((k) => delete copy[k as keyof SetupFormData]);
      return copy;
    });
  };

  const validateStep = (stepIndex: number): boolean => {
    const newErrors: SetupFieldErrors = {};

    if (stepIndex === 0) {
      // Step 1: Domain & Epoch
      if (!formData.domain || !formData.domain.trim()) {
        newErrors.domain = 'Domain identifier is required';
      } else if (!/^[A-Z0-9-]+$/.test(formData.domain)) {
        newErrors.domain = 'Domain must be uppercase alphanumeric with hyphens (e.g. BAYORA-PILOT-01)';
      }

      // Invariant 5: Epoch must be an exact positive integer
      const rawEpoch = formData.epoch;
      if (typeof rawEpoch === 'boolean' || typeof rawEpoch === 'string' || isNaN(Number(rawEpoch))) {
        newErrors.epoch = 'Epoch must be an exact positive integer (e.g. 1, 2, 3)';
      } else {
        const parsed = EpochSchema.safeParse(rawEpoch);
        if (!parsed.success) {
          newErrors.epoch = 'Epoch must be an exact positive integer (e.g. 1, 2, 3)';
        }
      }
    } else if (stepIndex === 1) {
      // Step 2: Target Inference
      if (!formData.target_model) newErrors.target_model = 'Target model is required';
      if (!formData.inference_engine) newErrors.inference_engine = 'Inference engine is required';
      if (!formData.target_deadline_ms || formData.target_deadline_ms < 1000) {
        newErrors.target_deadline_ms = 'Target deadline must be at least 1,000 ms';
      }
      if (!formData.output_max_tokens || formData.output_max_tokens < 1) {
        newErrors.output_max_tokens = 'Max output tokens must be at least 1';
      }
    } else if (stepIndex === 2) {
      // Step 3: Blue Defense
      if (!formData.defense_image_digest) {
        newErrors.defense_image_digest = 'Defense image digest is required';
      } else {
        const digestParse = DigestSchema.safeParse(formData.defense_image_digest);
        if (!digestParse.success) {
          newErrors.defense_image_digest = 'Must be formatted as sha256:<64 hex chars>';
        }
      }
      if (!formData.defense_deadline_ms || formData.defense_deadline_ms < 100) {
        newErrors.defense_deadline_ms = 'Defense deadline must be at least 100 ms';
      }
    } else if (stepIndex === 3) {
      // Step 4: Red Constraints
      if (!formData.body_max_bytes || formData.body_max_bytes < 1024) {
        newErrors.body_max_bytes = 'Body limit must be at least 1,024 bytes';
      }
      if (!formData.text_max_bytes || formData.text_max_bytes < 1024) {
        newErrors.text_max_bytes = 'Text limit must be at least 1,024 bytes';
      }
      if (!formData.queue_depth || formData.queue_depth < 1) {
        newErrors.queue_depth = 'Queue depth must be at least 1 slot';
      }
    }

    setErrors((prev) => ({ ...prev, ...newErrors }));
    return Object.keys(newErrors).length === 0;
  };

  // Compile canonical manifest draft
  const manifestDraft: ManifestDraftPayload = useMemo(() => {
    const validEpoch =
      typeof formData.epoch === 'number' && Number.isInteger(formData.epoch) && formData.epoch > 0
        ? formData.epoch
        : 1;

    return {
      protocol_version: 'arena.v2',
      domain: formData.domain || 'UNTITLED-DOMAIN',
      epoch: validEpoch,
      interaction_mode: formData.interaction_mode,
      profile: formData.disclosure_policy,
      assurance_lane: formData.assurance_lane,
      dataset_catalog_id: formData.dataset_catalog_id,
      budget_profile_id: formData.budget_profile_id,
      target_inference: {
        model: formData.target_model,
        engine: formData.inference_engine,
        deadline_ms: formData.target_deadline_ms,
        output_max_tokens: formData.output_max_tokens,
      },
      blue_defense: {
        image_digest: formData.defense_image_digest || 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
        defense_mode: formData.defense_mode,
        deadline_ms: formData.defense_deadline_ms,
        prefix_cache_salt: 'server-assigned secret [embargoed]',
      },
      red_constraints: {
        body_max_bytes: formData.body_max_bytes,
        text_max_bytes: formData.text_max_bytes,
        queue_depth: formData.queue_depth,
      },
    };
  }, [formData]);

  // Submit and register with witness
  const handleRegister = async () => {
    // 1. Validate all steps
    let allValid = true;
    for (let i = 0; i < 5; i++) {
      if (!validateStep(i)) {
        allValid = false;
      }
    }
    if (!allValid) return;

    // 2. Validate preflight pass
    if (preflightReport?.overall_status !== 'PASS') {
      setSubmitError({
        code: 'AUDIT_UNAVAILABLE',
        message: 'Preflight verification has not passed. Registration is prohibited.',
        recovery: 'Resolve host isolation failures and re-run preflight scan.',
      });
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const res = await arenaClient.createExperiment(
        {
          domain: formData.domain,
          epoch: typeof formData.epoch === 'number' ? formData.epoch : 1,
          profile: formData.disclosure_policy,
          interaction_mode: formData.interaction_mode,
          defense_mode: formData.defense_mode,
          dataset_catalog_id: formData.dataset_catalog_id,
          budget_profile_id: formData.budget_profile_id,
          assurance_lane: formData.assurance_lane,
          limits: {
            body_max_bytes: formData.body_max_bytes,
            text_max_bytes: formData.text_max_bytes,
            output_max_tokens: formData.output_max_tokens,
            defense_deadline_ms: formData.defense_deadline_ms,
            target_deadline_ms: formData.target_deadline_ms,
          },
          versions: {
            target_model: formData.target_model,
            defense_runtime: formData.defense_image_digest,
            broker: 'bayora-broker-v2.1',
            recorder: 'bayora-recorder-v1.8',
          },
          manifest_draft: manifestDraft as unknown as Record<string, unknown>,
        },
        undefined,
        role
      );

      setReceipt({
        receipt_id: res.witness_receipt ?? `rcpt_wit_${Date.now()}`,
        experiment_id: res.experiment_id,
        manifest_digest: res.manifest_digest,
        epoch: res.epoch,
        domain: formData.domain,
        timestamp_utc: res.created_at ?? new Date().toISOString(),
        state: res.state,
      });
    } catch (err: unknown) {
      const apiErr = err as { code?: string; message?: string };
      const code = apiErr.code ?? 'AUDIT_UNAVAILABLE';
      let recovery = 'Check host witness connectivity and verify that all preflight constraints are satisfied.';
      if (code === 'VERSION_MISMATCH' || code === 'STALE_EPOCH') {
        recovery = 'Declared epoch rejected by witness. Anchor version mismatch. Increment epoch to continue.';
      } else if (code === 'AUDIT_UNAVAILABLE') {
        recovery = 'Witness signing authority temporarily unavailable. Ledger anchor offline. Try again shortly.';
      }
      setSubmitError({
        code,
        message: apiErr.message ?? 'Registration rejected by witness.',
        recovery,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Role Gate: Non-operators receive an explicit UNAUTHORIZED ErrorState (Invariant 3)
  if (role !== 'operator') {
    return (
      <div className="space-y-6">
        <PageHeader
          docId="DOC-EXP-SETUP"
          title="EXPERIMENT SETUP & CANONICAL MANIFEST COMPOSER"
          epoch={activeEpoch}
          status="RESTRICTED ACCESS"
          breadcrumb="BAYORA // SETUP // RESTRICTED"
        />

        <div className="max-w-2xl mx-auto py-8">
          <ErrorState
            code="UNAUTHORIZED"
            title="OPERATOR PRIVILEGES REQUIRED"
            message={`Experiment setup, canonical manifest authoring, and preflight registration are restricted to the operator role. Your current active role is "${role.toUpperCase()}". Switch to operator role in the top bar to access this console.`}
            onRetry={() => useArenaStore.getState().setRole('operator')}
            retryLabel="SWITCH TO OPERATOR ROLE"
          />
        </div>
      </div>
    );
  }

  const isPreflightPass = preflightReport?.overall_status === 'PASS';
  const hasErrors = Object.keys(errors).length > 0;
  const isSignDisabled = !isPreflightPass || isScanningPreflight || isSubmitting || hasErrors;

  return (
    <div className="space-y-8">
      {/* Top Document Header */}
      <PageHeader
        docId="DOC-EXP-SETUP"
        title="EXPERIMENT SETUP & CANONICAL MANIFEST COMPOSER"
        epoch={typeof formData.epoch === 'number' ? formData.epoch : activeEpoch}
        status="OPERATOR READY"
        breadcrumb="BAYORA // SETUP // MANIFEST"
      />

      {/* Main 12-Column Grid: Wizard Left (cols 1-6), Manifest Preview Right (cols 7-12) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Setup Wizard OR Receipt Card upon completion */}
        <div className="lg:col-span-6 space-y-6">
          {receipt ? (
            <ReceiptCard
              receipt={receipt}
              onReset={() => {
                setReceipt(null);
                setFormData(INITIAL_FORM_DATA);
                setErrors({});
                runPreflightScan();
              }}
            />
          ) : (
            <SetupWizard
              formData={formData}
              errors={errors}
              onChange={handleFormChange}
              onValidateStep={validateStep}
              onAllStepsValidated={() => {
                // Focus on Preflight or Sign button
                const btn = document.getElementById('sign-register-button');
                btn?.focus();
              }}
            />
          )}
        </div>

        {/* Right Column: Canonical Manifest Preview (RFC 8785) with Live Digest */}
        <div className="lg:col-span-6">
          <ManifestPreviewPanel manifestDraft={manifestDraft} />
        </div>
      </div>

      {/* Preflight Scanner Panel */}
      <div className="pt-2">
        <PreflightScannerPanel
          report={preflightReport}
          isScanning={isScanningPreflight}
          onRunScan={runPreflightScan}
        />
      </div>

      {/* Registration Action Bar */}
      {!receipt && (
        <div className="p-5 bg-s1 border border-bd rounded-[2px] space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-xs uppercase tracking-wider font-bold text-tx">
                  Manifest Witness Registration Gate
                </span>
                {isPreflightPass ? (
                  <span className="font-mono text-[10px] text-ok bg-ok/10 border border-ok/30 px-2 py-0.5 rounded-[2px] font-bold">
                    PREFLIGHT CLEARED
                  </span>
                ) : (
                  <span className="font-mono text-[10px] text-bad bg-bad/10 border border-bad/30 px-2 py-0.5 rounded-[2px] font-bold">
                    PREFLIGHT BLOCKED
                  </span>
                )}
              </div>
              <p className="font-sans text-xs text-mut">
                Signing commits the canonical manifest digest to the witness ledger with an initial terminal checkpoint.
              </p>
            </div>

            <button
              id="sign-register-button"
              type="button"
              onClick={handleRegister}
              disabled={isSignDisabled}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 bg-cy text-[#080B10] font-mono text-xs uppercase tracking-wider font-bold rounded-[2px] hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed transition-all focus:outline-none focus:ring-2 focus:ring-cy focus:ring-offset-2 focus:ring-offset-bg shrink-0 shadow-sm"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>SIGNING & REGISTERING WITH WITNESS...</span>
                </>
              ) : (
                <>
                  <KeyRound className="w-4 h-4" />
                  <span>SIGN & REGISTER WITH WITNESS</span>
                </>
              )}
            </button>
          </div>

          {/* Submission Failure Alert with Recovery Guidance */}
          {submitError && (
            <div className="p-4 bg-bad/10 border border-bad/40 rounded-[2px] space-y-1 font-mono text-xs text-bad">
              <div className="flex items-center gap-2 font-bold">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>REGISTRATION ERROR [{submitError.code}]: {submitError.message}</span>
              </div>
              <p className="font-sans text-xs text-tx pl-6">
                <strong>Recovery:</strong> {submitError.recovery}
              </p>
            </div>
          )}

          {/* Disclaimers & Invariant 2 note */}
          <div className="pt-3 border-t border-bd flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] text-mut">
            <span className="flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-cy" />
              NO OPTIMISTIC UI · RECEIPT ISSUED ONLY AFTER WITNESS COMMITMENT
            </span>
            <span>PREFIX-CACHE SALT EMBARGOED WITHIN TRUSTED BROKER</span>
          </div>
        </div>
      )}

      {/* Residual Risk Panel (Q-005) with NOT VERIFIED status */}
      <div className="pt-2">
        <ResidualRiskPanel evidenceStatusOverride="NOT VERIFIED" />
      </div>
    </div>
  );
};
