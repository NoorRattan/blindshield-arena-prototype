import React, { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, Info } from 'lucide-react';
import { PageHeader } from '../../components/PageHeader';
import { ResidualRiskPanel } from '../../components/ResidualRiskPanel';
import { SimulatedDataTag } from '../../components/SimulatedDataTag';
import { arenaClient } from '../../lib/api/client';
import { useArenaStore } from '../../state/useArenaStore';
import { DEMO_KEYS } from '../../lib/crypto';
import type { ArenaEvent, Digest, Epoch } from '../../lib/schemas';
import { appendEventToLedger, createSignedCheckpoint, verifyEventChain } from '../../lib/mock/ledger';
import { applyTamper } from './verifierCore';
import { useEvidenceVerifier } from './useEvidenceVerifier';
import { TrustAnchorsPanel } from './TrustAnchorsPanel';
import { BundleImportDropzone } from './BundleImportDropzone';
import { VerificationChecklistPanel } from './VerificationChecklistPanel';
import { EvidenceChainView } from './EvidenceChainView';
import { TamperPlaygroundPanel } from './TamperPlaygroundPanel';
import type { EvidenceBundle, TamperType, VerificationTrustAnchors } from './types';

export const EvidencePage: React.FC = () => {
  const connectionMode = useArenaStore((state) => state.connectionMode);
  const isLive = connectionMode === 'live';

  // State
  const [bundle, setBundle] = useState<EvidenceBundle | null>(null);
  const [untamperedBundle, setUntamperedBundle] = useState<EvidenceBundle | null>(null);
  const [anchors, setAnchors] = useState<VerificationTrustAnchors>({
    publicKeyHex: isLive ? '' : DEMO_KEYS.PUBLIC_KEY_HEX,
    isPinned: !isLive,
    expectedDomain: isLive ? '' : 'BAYORA-EVAL-04',
    expectedExperimentId: isLive ? '' : 'exp_released_04',
    expectedEpoch: (isLive ? 1 : 5) as Epoch,
    expectedManifestDigest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' as Digest,
    witnessedTerminalCheckpointReceipt: '',
  });

  const [activeTamper, setActiveTamper] = useState<{
    type: TamperType;
    description: string;
    expectedFailureCode: string;
    expectedFailingSeq?: number;
  } | null>(null);

  const [selectedSeq, setSelectedSeq] = useState<number | undefined>(undefined);

  // Offline Verifier Web Worker Hook
  const { verify, isVerifying, report } = useEvidenceVerifier();

  // Load Released Epoch 04 Mock Bundle on mount
  const loadReleasedMockBundle = useCallback(async () => {
    try {
      const raw = await arenaClient.getEvidenceBundle('exp_released_04', 'auditor');
      const loaded: EvidenceBundle = {
        metadata: raw.metadata,
        ledger: raw.ledger as ArenaEvent[],
        checkpoint: raw.checkpoint,
      };

      const initialAnchors: VerificationTrustAnchors = {
        publicKeyHex: DEMO_KEYS.PUBLIC_KEY_HEX,
        isPinned: true,
        expectedDomain: loaded.metadata.domain,
        expectedExperimentId: loaded.metadata.experiment_id,
        expectedEpoch: loaded.metadata.epoch,
        expectedManifestDigest: loaded.checkpoint.manifest_digest,
        witnessedTerminalCheckpointReceipt: loaded.checkpoint.witness_receipt,
      };

      setBundle(loaded);
      setUntamperedBundle(loaded);
      setAnchors(initialAnchors);
      setActiveTamper(null);
      setSelectedSeq(undefined);

      // Trigger verification
      verify(loaded, initialAnchors);
    } catch (err) {
      console.error('Failed to load released evidence bundle:', err);
    }
  }, [verify]);

  // Load large 1,500 event bundle for 60fps performance validation
  const loadLargeBundlePreset = useCallback(() => {
    if (!untamperedBundle) return;
    const largeLedger: ArenaEvent[] = [...untamperedBundle.ledger];

    // Append synthesized events up to 1,500
    const startSeq = largeLedger.length + 1;
    const lastEvent = largeLedger[largeLedger.length - 1];
    let currentMono = lastEvent ? lastEvent.mono_ms : 10000;
    const lastDate = lastEvent ? new Date(lastEvent.ts_utc).getTime() : Date.now();

    for (let seq = startSeq; seq <= 1500; seq++) {
      currentMono += 200;
      appendEventToLedger(largeLedger, {
        experiment: untamperedBundle.metadata.experiment_id,
        epoch: untamperedBundle.metadata.epoch,
        actor: seq % 2 === 0 ? 'blue' : 'red',
        action: seq % 2 === 0 ? 'defense_evaluated' : 'payload_streamed',
        outcome: 'ok',
        artifacts: [untamperedBundle.checkpoint.manifest_digest],
        versions: untamperedBundle.metadata.manifest.versions,
        ts_utc: new Date(lastDate + (seq - startSeq + 1) * 1000).toISOString(),
        mono_ms: currentMono,
      });
    }

    const chainResult = verifyEventChain(largeLedger);
    const finalDigest = chainResult.finalDigest as Digest;
    const checkpoint = createSignedCheckpoint({
      experiment: untamperedBundle.metadata.experiment_id,
      epoch: untamperedBundle.metadata.epoch,
      count: largeLedger.length,
      final_digest: finalDigest,
      manifest_digest: untamperedBundle.checkpoint.manifest_digest,
    });

    const largeBundle: EvidenceBundle = {
      metadata: {
        ...untamperedBundle.metadata,
        events_count: largeLedger.length,
        checkpoint,
      },
      ledger: largeLedger,
      checkpoint,
    };

    setBundle(largeBundle);
    setUntamperedBundle(largeBundle);
    setActiveTamper(null);
    setSelectedSeq(undefined);

    const updatedAnchors = {
      ...anchors,
      witnessedTerminalCheckpointReceipt: checkpoint.witness_receipt,
    };
    setAnchors(updatedAnchors);
    verify(largeBundle, updatedAnchors);
  }, [untamperedBundle, anchors, verify]);

  useEffect(() => {
    if (connectionMode !== 'live') {
      loadReleasedMockBundle();
    }
  }, [loadReleasedMockBundle, connectionMode]);

  // Handle Tamper Mutation
  const handleApplyTamper = (type: TamperType) => {
    if (!untamperedBundle) return;
    const { mutatedBundle, description, expectedFailureCode, expectedFailingSeq } = applyTamper(
      untamperedBundle,
      type
    );

    setBundle(mutatedBundle);
    setActiveTamper({
      type,
      description,
      expectedFailureCode,
      expectedFailingSeq,
    });
    setSelectedSeq(expectedFailingSeq);

    // Re-verify immediately
    verify(mutatedBundle, anchors);
  };

  const handleResetTamper = () => {
    if (!untamperedBundle) return;
    setBundle(untamperedBundle);
    setActiveTamper(null);
    setSelectedSeq(undefined);
    verify(untamperedBundle, anchors);
  };

  const handleManualVerify = () => {
    if (bundle) {
      verify(bundle, anchors);
    }
  };

  const handleAnchorsChange = (updated: VerificationTrustAnchors) => {
    setAnchors(updated);
    if (bundle) {
      verify(bundle, updated);
    }
  };

  const handleBundleLoaded = (newBundle: EvidenceBundle) => {
    setBundle(newBundle);
    setUntamperedBundle(newBundle);
    setActiveTamper(null);
    setSelectedSeq(undefined);

    // Auto-populate anchors with pinned mode active
    const newAnchors: VerificationTrustAnchors = {
      publicKeyHex: isLive ? (anchors.publicKeyHex || '') : (anchors.publicKeyHex || DEMO_KEYS.PUBLIC_KEY_HEX),
      isPinned: anchors.isPinned,
      expectedDomain: newBundle.metadata.domain,
      expectedExperimentId: newBundle.metadata.experiment_id,
      expectedEpoch: newBundle.metadata.epoch,
      expectedManifestDigest: newBundle.checkpoint.manifest_digest,
      witnessedTerminalCheckpointReceipt: newBundle.checkpoint.witness_receipt,
    };
    setAnchors(newAnchors);
    verify(newBundle, newAnchors);
  };

  return (
    <div className="space-y-6 pb-12 font-sans">
      {/* Doc Page Header */}
      <PageHeader
        docId="DOC-EVID-06"
        title="EVIDENCE INSPECTOR & OFFLINE VERIFIER"
        epoch={anchors.expectedEpoch}
        timestamp="OFFLINE WORKER"
        status={
          <div className="flex items-center gap-2">
            {connectionMode === 'simulated' ? (
              <SimulatedDataTag />
            ) : (
              <span className="font-mono text-[10px] text-ok border border-ok/30 px-1.5 py-0.5">LIVE</span>
            )}
            <span>CRYPTOGRAPHICALLY PINNED</span>
          </div>
        }
      />

      {connectionMode === 'simulated' && (
        <SimulatedDataTag
          variant="banner"
          message="SIMULATED EVIDENCE BUNDLE · Inspecting local mock ledger (exp_released_04) with demo keys"
        />
      )}

      {connectionMode === 'live' && (
        <div className="p-3 bg-am/10 border border-am/40 rounded-[2px] font-mono text-xs text-am flex items-center justify-between">
          <span><strong>LIVE TRUST PINNING REQUIRED:</strong> To verify live backend evidence, enter your external witness public key (64 hex characters) in the Trust Anchors panel. The built-in demo key is untrusted in live mode per Invariant 6.</span>
        </div>
      )}

      {/* Assurance Disclaimer / Banner */}
      <div className="p-3 bg-s2 border border-bd rounded-[2px] text-xs font-mono flex items-center justify-between text-mut">
        <div className="flex items-center gap-2">
          <ShieldCheck size={14} className="text-cy" />
          <span className="text-tx font-medium">AUDITOR &amp; JUDGE CONSOLE:</span>
          <span>Zero-network offline verification engine powered by Web Workers &amp; noble ed25519/sha256.</span>
        </div>
        <div className="text-[11px] text-cy font-semibold tracking-wider">
          PROTOCOL ARENA.V2
        </div>
      </div>

      {/* Main 12-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column (cols 1–5): Trust Anchors, Drop Zone & Checklist */}
        <div className="lg:col-span-5 space-y-6">
          <TrustAnchorsPanel
            anchors={anchors}
            onChange={handleAnchorsChange}
            bundleKeyHex={bundle?.checkpoint.key_id}
          />

          <BundleImportDropzone
            currentBundle={bundle}
            onBundleLoaded={handleBundleLoaded}
            onLoadMockPreset={loadReleasedMockBundle}
            onLoadLargeMockPreset={loadLargeBundlePreset}
          />

          <VerificationChecklistPanel
            report={report}
            isVerifying={isVerifying}
            onRunVerify={handleManualVerify}
            onSelectBlock={(seq) => setSelectedSeq(seq)}
          />
        </div>

        {/* Right Column (cols 6–12): 3D/2D Hash Chain View */}
        <div className="lg:col-span-7">
          <div className="lg:sticky lg:top-20">
            <EvidenceChainView
              ledger={bundle?.ledger || []}
              brokenIndex={report?.broken_index}
              selectedSeq={selectedSeq}
              onSelectEvent={(ev) => setSelectedSeq(ev.seq)}
            />
          </div>
        </div>
      </div>

      {/* Bottom: Tamper Playground Panel */}
      <div className="pt-2">
        <TamperPlaygroundPanel
          onApplyTamper={handleApplyTamper}
          onResetTamper={handleResetTamper}
          activeTamper={activeTamper}
        />
      </div>

      {/* Standing Disclaimer & Residual Risk Panel */}
      <div className="space-y-4 pt-4 border-t border-bd">
        {/* Standing Disclaimer */}
        <div className="p-3 bg-s1 border border-bd rounded-[2px] flex items-start gap-2.5 text-xs text-mut font-mono">
          <Info size={14} className="text-cy shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-tx">Standing Verification Disclaimer: </span>
            Consistent with a trusted recorded history. Does not prove the recorder was honest, every event was captured, or the model is safe. VALID_WITHIN_PROFILE means mandatory checks for the declared assurance profile completed.
          </div>
        </div>

        {/* Residual Risk Panel */}
        <ResidualRiskPanel />
      </div>
    </div>
  );
};
