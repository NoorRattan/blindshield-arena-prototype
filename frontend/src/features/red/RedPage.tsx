import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Cpu, Layers } from 'lucide-react';
import { PageHeader } from '../../components/PageHeader';
import { StatusPill } from '../../components/StatusPill';
import { ErrorState } from '../../components/ErrorState';
import { useArenaStore } from '../../state/useArenaStore';
import { arenaClient } from '../../lib/api/client';
import { PayloadWorkshop } from './PayloadWorkshop';
import { TurnFeedbackLog } from './TurnFeedbackLog';
import type { AttackReceipt, Epoch } from '../../lib/schemas';

export const RedPage: React.FC = () => {
  const queryClient = useQueryClient();
  const currentRole = useArenaStore((state) => state.role);

  // Selected arena ID (default to running arena exp_running_01)
  const [selectedExperimentId, setSelectedExperimentId] = useState<string>('exp_running_01');

  // Query experiments list
  const { data: experiments = [] } = useQuery({
    queryKey: ['experiments', currentRole],
    queryFn: () => arenaClient.getExperiments(currentRole),
  });

  // Query status of selected experiment
  const {
    data: status,
    isLoading: isStatusLoading,
    error: statusError,
  } = useQuery({
    queryKey: ['experiment-status', selectedExperimentId, currentRole],
    queryFn: () => arenaClient.getExperimentStatus(selectedExperimentId, currentRole),
    enabled: Boolean(selectedExperimentId),
  });

  // Query turn feedback log
  const { data: feedback = [], isLoading: isFeedbackLoading } = useQuery({
    queryKey: ['feedback', selectedExperimentId, currentRole],
    queryFn: () => arenaClient.getFeedback(selectedExperimentId, currentRole),
    enabled: Boolean(selectedExperimentId),
  });

  // Refresh feedback when an attack is submitted
  const handleAttackSubmitted = (_receipt: AttackReceipt) => {
    queryClient.invalidateQueries({
      queryKey: ['feedback', selectedExperimentId, currentRole],
    });
    queryClient.invalidateQueries({
      queryKey: ['experiment-status', selectedExperimentId, currentRole],
    });
    queryClient.invalidateQueries({
      queryKey: ['experiments', currentRole],
    });
  };

  // Role Boundary Enforcement (Invariant 3 & Spec §5.6 Role Matrix)
  if (currentRole === 'blue' || currentRole === 'auditor') {
    return (
      <div className="space-y-6">
        <PageHeader
          docId="DOC-RED-05"
          title="RED TEAM OPERATIONAL PORTAL"
          description="ACCESS DENIED — ROLE BOUNDARY ENFORCED"
        />
        <ErrorState
          code="UNAUTHORIZED"
          title="ACCESS DENIED — ROLE BOUNDARY ENFORCED"
          message={`Role '${currentRole}' is prohibited from inspecting active offensive attack queues and uncommitted payloads. Switch role to 'red' or 'operator' using the role switcher in the navigation bar.`}
          className="my-8"
        />
      </div>
    );
  }

  if (isStatusLoading || !status) {
    return (
      <div className="space-y-6">
        <PageHeader
          docId="DOC-RED-05"
          title="RED TEAM OPERATIONAL PORTAL"
          description="ADVERSARIAL ATTACK SUBMISSION QUEUE // COMMITMENT WORKSHOP"
        />
        <div className="py-16 text-center font-mono text-xs text-mut animate-pulse">
          INITIALIZING SECURE SESSION & AUDIT BOUNDARIES...
        </div>
      </div>
    );
  }

  if (statusError) {
    return (
      <div className="space-y-6">
        <PageHeader
          docId="DOC-RED-05"
          title="RED TEAM OPERATIONAL PORTAL"
          description="SECURE SESSION TERMINATED"
        />
        <ErrorState
          code="NOT_FOUND"
          title="EXPERIMENT NOT FOUND"
          message={statusError instanceof Error ? statusError.message : String(statusError)}
        />
      </div>
    );
  }

  const identityLabel =
    currentRole === 'operator'
      ? 'operator-root-01 · mTLS verified (DEMO MODE)'
      : 'red-agent-01 · mTLS verified';

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        docId="DOC-RED-05"
        title="RED TEAM OPERATIONAL PORTAL"
        description="ADVERSARIAL ATTACK SUBMISSION QUEUE // COMMITMENT WORKSHOP"
        epoch={status.epoch}
      />

      {/* Top Identity & Arena Bar */}
      <div
        role="region"
        aria-label="Active Red Session Metadata"
        className="flex flex-wrap items-center justify-between gap-4 rounded-[2px] border border-bd bg-s1 px-4 py-3 text-xs"
      >
        {/* Left: Identity & Arena Selector */}
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-am" aria-hidden="true" />
            <span className="font-mono text-tx font-medium">{identityLabel}</span>
          </div>

          <div className="h-4 w-px bg-bd hidden sm:block" aria-hidden="true" />

          {/* Arena Switcher */}
          <div className="flex items-center gap-2">
            <label htmlFor="arena-select" className="font-mono text-mut uppercase text-[11px]">
              TARGET ARENA:
            </label>
            <select
              id="arena-select"
              value={selectedExperimentId}
              onChange={(e) => setSelectedExperimentId(e.target.value)}
              className="rounded-[2px] border border-bd bg-s2 px-2.5 py-1 font-mono text-xs text-tx focus:outline-none focus:ring-1 focus:ring-cy"
            >
              {experiments.map((exp) => (
                <option key={exp.experiment_id} value={exp.experiment_id}>
                  {exp.domain} ({exp.experiment_id} · {exp.profile})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Right: State & Limits Pill Bar */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5 font-mono text-xs">
            <Cpu className="h-3.5 w-3.5 text-mut" aria-hidden="true" />
            <span className="text-mut">TARGET:</span>
            <span className="text-tx font-medium">{status.target_model ?? 'Llama-3-8B-Instruct'}</span>
          </div>

          <div className="h-4 w-px bg-bd" aria-hidden="true" />

          <div className="flex items-center gap-1.5 font-mono text-xs">
            <Layers className="h-3.5 w-3.5 text-mut" aria-hidden="true" />
            <span className="text-mut">PROFILE:</span>
            <span className="text-cy font-medium">{status.profile}</span>
          </div>

          <StatusPill status={status.state} />
        </div>
      </div>

      {/* 12-Column Responsive Layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left: Payload Workshop (cols 1-7) */}
        <div className="lg:col-span-7">
          <PayloadWorkshop
            experimentId={selectedExperimentId}
            domain={status.domain}
            epoch={status.epoch as Epoch}
            onAttackSubmitted={handleAttackSubmitted}
          />
        </div>

        {/* Right: Turn History, Budget Gauge & Privacy Notice (cols 8-12) */}
        <div className="lg:col-span-5">
          <TurnFeedbackLog
            feedback={feedback}
            profile={status.profile}
            maxTurns={50}
            isLoading={isFeedbackLoading}
          />
        </div>
      </div>
    </div>
  );
};
