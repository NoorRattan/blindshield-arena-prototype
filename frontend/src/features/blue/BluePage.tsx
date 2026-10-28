import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Shield, Layers, Radio } from 'lucide-react';
import { PageHeader } from '../../components/PageHeader';
import { ErrorState } from '../../components/ErrorState';
import { SimulatedDataTag } from '../../components/SimulatedDataTag';
import { useArenaStore } from '../../state/useArenaStore';
import { arenaClient } from '../../lib/api/client';
import { DefenseArtifactPanel } from './DefenseArtifactPanel';
import { LiveRoundHealthMonitor } from './LiveRoundHealthMonitor';
import { ForensicWorkshopPanel } from './ForensicWorkshopPanel';

export const BluePage: React.FC = () => {
  const currentRole = useArenaStore((state) => state.role);
  const connectionMode = useArenaStore((state) => state.connectionMode);

  // Selected experiment for live monitoring (defaults to running arena)
  const [activeExpId, setActiveExpId] = useState<string>('exp_running_01');

  // Selected experiment for closed-round forensics (defaults to released arena)
  const [forensicExpId, setForensicExpId] = useState<string>('exp_released_04');

  // Query experiments list
  const { data: experiments = [], isLoading: isExpLoading } = useQuery({
    queryKey: ['experiments', currentRole],
    queryFn: () => arenaClient.getExperiments(currentRole),
  });

  // Query manifest of active experiment
  const { data: activeManifest } = useQuery({
    queryKey: ['manifest', activeExpId, currentRole],
    queryFn: () => arenaClient.getManifest(activeExpId, currentRole),
    enabled: currentRole === 'operator' || currentRole === 'auditor',
  });

  // Query defense artifact info for active experiment
  const {
    data: artifact,
    isLoading: isArtifactLoading,
    error: artifactError,
  } = useQuery({
    queryKey: ['defense-artifact', activeExpId, currentRole],
    queryFn: () => arenaClient.getDefenseArtifact(activeExpId, currentRole),
    enabled: currentRole !== 'red' && Boolean(activeExpId),
  });

  // Query sanitized feedback telemetry for live active round
  const {
    data: feedback = [],
    isLoading: isFeedbackLoading,
  } = useQuery({
    queryKey: ['feedback', activeExpId, currentRole],
    queryFn: () => arenaClient.getFeedback(activeExpId, currentRole),
    enabled: currentRole !== 'red' && Boolean(activeExpId),
  });

  // Query released forensics for the forensic workshop
  const {
    data: forensics,
    isLoading: isForensicsLoading,
  } = useQuery({
    queryKey: ['forensics', forensicExpId, currentRole],
    queryFn: () => arenaClient.getForensics(forensicExpId, currentRole),
    enabled: currentRole !== 'red' && Boolean(forensicExpId),
    retry: false,
  });

  // Role Boundary Enforcement (Invariant 3 & Spec §5.7 Acceptance: red hitting /blue denied)
  if (currentRole === 'red') {
    return (
      <div className="space-y-6">
        <PageHeader
          docId="DOC-BLUE-06"
          title="BLUE TEAM DEFENSIVE CONSOLE"
          description="ACCESS DENIED — ROLE BOUNDARY ENFORCED"
        />
        <ErrorState
          code="UNAUTHORIZED"
          title="ACCESS DENIED — DEFENDER TELEMETRY RESTRICTED"
          message="Offensive Red Team operators are strictly prohibited from viewing Blue Team defense artifacts, filter configurations, and post-round forensic decision logs. Switch role to 'blue', 'operator', or 'auditor' to access this console."
          className="my-8"
        />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Prominent Simulated Data Notice when operating in simulation mode */}
      {connectionMode === 'simulated' && (
        <SimulatedDataTag
          variant="banner"
          message="SIMULATED DATA: Blue defense artifact envelopes, readiness probes, and forensic workshop running in-memory demo mode."
        />
      )}

      {/* Page Header with distinct Blue/Cobalt styling */}
      <div className="space-y-3">
        <PageHeader
          docId="DOC-BLUE-06"
          title="BLUE TEAM DEFENSIVE CONSOLE"
          description="IMMUTABLE GUARDRAIL VAULT // BOUNDED COVERT-CHANNEL DEFENSIVE TELEMETRY // FORENSIC WORKSHOP"
          actions={<SimulatedDataTag />}
        />

        {/* Console Context Strip */}
        <div className="flex flex-wrap items-center justify-between gap-4 border border-bd bg-s2 px-4 py-2.5 font-mono text-xs">
          <div className="flex flex-wrap items-center gap-4">
            <span className="flex items-center gap-1.5 text-bl font-semibold">
              <Shield className="h-4 w-4" />
              DEFENSE CONSOLE
            </span>
            <span className="text-mut">|</span>
            <span className="flex items-center gap-1.5 text-tx">
              <Radio className="h-3.5 w-3.5 text-ok" />
              Active Arena: <span className="font-semibold text-cy">{activeExpId}</span>
            </span>
            <span className="text-mut">|</span>
            <span className="flex items-center gap-1.5 text-tx">
              <Layers className="h-3.5 w-3.5 text-mut" />
              Runtime: <span className="text-tx">gVisor Sandbox (profile: runsc-ptrace)</span>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="active-arena-select" className="text-mut text-[11px] uppercase">
              Switch Live Arena:
            </label>
            <select
              id="active-arena-select"
              value={activeExpId}
              onChange={(e) => setActiveExpId(e.target.value)}
              className="border border-bd bg-s1 px-2.5 py-1 text-xs text-tx focus:border-cy focus:outline-none"
            >
              {experiments.map((exp) => (
                <option key={exp.experiment_id} value={exp.experiment_id}>
                  {exp.domain} ({exp.state})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* S1: Defense Artifact Status & Readiness Probes */}
      {isArtifactLoading || !artifact ? (
        <div className="border border-bd bg-s1 p-8 text-center font-mono text-xs text-mut animate-pulse">
          INITIALIZING DEFENSE RUNTIME ENVELOPE &amp; READINESS PROBES...
        </div>
      ) : artifactError ? (
        <ErrorState
          code="NOT_FOUND"
          title="DEFENSE ARTIFACT NOT FOUND"
          message="Failed to load defense runtime envelope for the selected arena domain."
        />
      ) : (
        <DefenseArtifactPanel
          artifact={artifact}
          manifest={activeManifest}
        />
      )}

      {/* S2: Sanitized Live Round Health Monitor (Zero Payload Leakage) */}
      <LiveRoundHealthMonitor
        feedback={feedback}
        isLoading={isFeedbackLoading}
        isActiveRound={activeExpId === 'exp_running_01'}
        experimentId={activeExpId}
      />

      {/* S3: Closed-Round Forensic Workshop */}
      <ForensicWorkshopPanel
        experiments={experiments}
        currentRole={currentRole}
        selectedExperimentId={forensicExpId}
        onSelectExperimentId={setForensicExpId}
        forensics={forensics}
        isLoading={isForensicsLoading || isExpLoading}
      />
    </div>
  );
};
