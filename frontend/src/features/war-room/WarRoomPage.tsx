import React, { useState, useEffect, useMemo } from 'react';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { WarRoomTopBar } from './WarRoomTopBar';
import { FailureInjectionPanel } from './FailureInjectionPanel';
import { PipelineWaterfall } from './PipelineWaterfall';
import { TelemetryGauges } from './TelemetryGauges';
import { RoleObservabilityPreview } from './RoleObservabilityPreview';
import { LiveAuditLog } from './LiveAuditLog';
import { useToast } from '../../components/Toast';
import { useArenaStore } from '../../state/useArenaStore';
import { arenaClient } from '../../lib/api/client';
import { useQueryClient } from '@tanstack/react-query';
import {
  useExperimentStatus,
  useFeedback,
  useExperimentEvents,
  useQuarantineExperiment,
  useTriggerReWitness,
} from '../../lib/api/hooks';
import type { FailureMode } from '../../lib/mock/sse';
import type { StatusValue } from '../../components/StatusPill';

export const WarRoomPage: React.FC = () => {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const activeEpoch = useArenaStore((s) => s.epoch);
  const failureMode = useArenaStore((s) => s.failureMode);
  const setStoreFailureMode = useArenaStore((s) => s.setFailureMode);

  // Active running experiment
  const experimentId = 'exp_running_01';

  // API hooks
  const {
    data: status,
    isLoading: isStatusLoading,
  } = useExperimentStatus(experimentId);

  const {
    data: feedback,
  } = useFeedback(experimentId);

  const {
    events,
    streamStatus,
    error: sseError,
  } = useExperimentEvents(experimentId);

  const quarantineMutation = useQuarantineExperiment();
  const reWitnessMutation = useTriggerReWitness();

  // Screen reader accessible announcement state
  const [liveAnnouncement, setLiveAnnouncement] = useState('');

  // Handle Failure Mode changes
  const handleSetFailureMode = (mode: FailureMode) => {
    arenaClient.setFailureMode(mode);
    setStoreFailureMode(mode);
    queryClient.invalidateQueries({ queryKey: ['experiment', experimentId] });
    queryClient.invalidateQueries({ queryKey: ['experiments'] });

    if (mode === 'defense_timeout') {
      setLiveAnnouncement('Failure mode injected: Defense timeout at 1002ms. Attempt invalidated.');
    } else if (mode === 'recorder_down') {
      setLiveAnnouncement('Failure mode injected: Recorder storage down. Audit unavailable.');
    } else if (mode === 'stale_epoch') {
      setLiveAnnouncement('Failure mode injected: Stale epoch emitted. Rejected by host.');
    } else if (mode === 'witness_lag') {
      setLiveAnnouncement('Failure mode injected: Witness anchor lagging.');
    } else {
      setLiveAnnouncement('Failure mode reset to nominal.');
    }
  };

  // Handle Quarantine Action
  const handleQuarantine = (reason: string) => {
    quarantineMutation.mutate(
      { experimentId, reason },
      {
        onSuccess: (receipt) => {
          // Invariant 2: Toast only on server receipt
          showToast({
            title: 'DOMAIN QUARANTINED',
            message: `Epoch ${activeEpoch} transitioned to INVALID (${receipt.reason}). Receipt sealed.`,
            variant: 'warning',
          });
          setLiveAnnouncement(`Domain quarantined: ${receipt.reason}. Lifecycle transitioned to INVALID.`);
        },
        onError: (err) => {
          showToast({
            title: 'QUARANTINE FAILED',
            message: err instanceof Error ? err.message : 'Unknown error during quarantine',
            variant: 'error',
          });
        },
      }
    );
  };

  // Handle Re-Witness Action
  const handleTriggerReWitness = () => {
    reWitnessMutation.mutate(experimentId, {
      onSuccess: (receipt) => {
        showToast({
          title: 'RE-WITNESS CHECKPOINT GENERATED',
          message: `Witness receipt ${receipt.witness_receipt.slice(0, 16)}... Status: ${receipt.witness_status}`,
          variant: 'success',
        });
        setLiveAnnouncement(`Witness checkpoint signed: ${receipt.witness_status}`);
      },
      onError: (err) => {
        showToast({
          title: 'RE-WITNESS FAILED',
          message: err instanceof Error ? err.message : 'Failed to generate witness receipt',
          variant: 'error',
        });
      },
    });
  };

  // Latest attempt data
  const latestAttempt = useMemo(() => {
    if (!feedback || feedback.length === 0) return undefined;
    const last = feedback[feedback.length - 1];
    return {
      request_id: last.request_id,
      turn: last.turn,
      model_execution: last.model_execution ?? 'NOT_EVALUATED',
      scoring: last.scoring ?? 'NOT_EVALUATED',
      integrity: last.integrity ?? 'PENDING',
      latency_ms: last.latency_ms ?? {
        defense: last.latency_bucket_ms ?? 148,
        target: 614,
        total: (last.latency_bucket_ms ?? 148) + 614,
      },
    };
  }, [feedback]);

  // Track integrity changes for live announcement
  useEffect(() => {
    if (status?.integrity_status === 'INVALID') {
      setLiveAnnouncement(`Assurance integrity alert: ${status.invalid_reason || 'INVALID_STATE'}`);
    }
  }, [status?.integrity_status, status?.invalid_reason]);

  const lifecycleState = status?.state ?? 'RUNNING';
  const integrityStatus: StatusValue =
    failureMode === 'defense_timeout' || failureMode === 'recorder_down'
      ? 'INVALID'
      : (status?.integrity_status ?? 'VALID_WITHIN_PROFILE');

  const modelOutcome: StatusValue =
    failureMode === 'defense_timeout'
      ? 'NOT_EVALUATED'
      : (latestAttempt?.model_execution ?? 'EXECUTED');

  const witnessStatus =
    failureMode === 'witness_lag' ? 'LAGGING' : (status?.witness_status ?? 'SYNCED');

  return (
    <div className="container mx-auto px-4 py-6 max-w-7xl">
      {/* Screen reader live region for integrity state transitions (Accessibility requirement) */}
      <div
        aria-live="polite"
        aria-atomic="true"
        className="sr-only"
        data-testid="war-room-live-region"
      >
        {liveAnnouncement}
      </div>

      {/* Document Page Header */}
      <PageHeader
        docId="DOC-WAR-04"
        title="LIVE ARENA WAR ROOM"
        epoch={activeEpoch}
        timestamp={status?.updated_at}
        actions={
          <span className="font-mono text-xs text-mut uppercase">
            TARGET: <strong className="text-tx">{status?.target_model ?? 'Llama-3-8B-Q4'}</strong>
          </span>
        }
      />

      {isStatusLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-48 w-full" />
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <Skeleton className="lg:col-span-5 h-96" />
            <Skeleton className="lg:col-span-7 h-96" />
          </div>
        </div>
      ) : (
        <>
          {/* Top Bar: Arena metadata, epoch, lifecycle, DualVerdict & Quarantine controls */}
          <WarRoomTopBar
            experimentId={experimentId}
            domain={status?.domain ?? 'BAYORA-PROD-01'}
            epoch={activeEpoch}
            lifecycleState={lifecycleState}
            integrityStatus={integrityStatus}
            modelOutcome={modelOutcome}
            witnessStatus={witnessStatus}
            invalidReason={
              failureMode === 'defense_timeout'
                ? 'DEFENSE_DEADLINE_EXCEEDED (1,002ms)'
                : failureMode === 'recorder_down'
                  ? 'AUDIT_UNAVAILABLE (Storage Disconnected)'
                  : status?.invalid_reason
            }
            onQuarantine={handleQuarantine}
            onTriggerReWitness={handleTriggerReWitness}
            isQuarantining={quarantineMutation.isPending}
            isReWitnessing={reWitnessMutation.isPending}
          />

          {/* Demo Mode Failure Injection Matrix */}
          <FailureInjectionPanel
            currentMode={failureMode}
            onSetFailureMode={handleSetFailureMode}
          />

          {/* Row 1: 6-Stage Pipeline Waterfall with GSAP packet travel */}
          <PipelineWaterfall
            turn={status?.current_turn ?? 14}
            maxTurns={50}
            attempt={latestAttempt}
            failureMode={failureMode}
            isQuarantined={lifecycleState === 'INVALID'}
          />

          {/* Row 2: Gauges & Virtualised Live Audit Log */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 mb-4">
            {/* Row 2 Left: 7 Attribute Telemetry Gauges */}
            <div className="lg:col-span-5">
              <TelemetryGauges
                queueDepth={2}
                maxQueue={4}
                blueMemoryMb={512}
                maxMemoryMb={1024}
                ttftMs={342}
                tokensPerSec={28.4}
                circuitBreakerViolations={0}
                egressPacketsOut={0}
                activeNetworkRules="Default Deny (Enforced)"
                witnessWatermarkSeq={1402}
                witnessStatus={witnessStatus}
                failureMode={failureMode}
              />
            </div>

            {/* Row 2 Right: Virtualised Chained Audit Log (5,000 events capable, 60fps) */}
            <div className="lg:col-span-7">
              <LiveAuditLog
                events={events}
                streamStatus={streamStatus}
                error={sseError}
              />
            </div>
          </div>

          {/* Row 3: Role Observability Boundary Preview (Red vs Blue vs Operator) */}
          <RoleObservabilityPreview attempt={latestAttempt} />
        </>
      )}
    </div>
  );
};
