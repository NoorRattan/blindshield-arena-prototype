import React, { useState } from 'react';
import { ShieldCheck, Cpu, HardDrive, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { Panel } from '../../components/Panel';
import { StatusPill } from '../../components/StatusPill';
import { Digest } from '../../components/Digest';
import type { DefenseArtifactInfo, Manifest } from '../../lib/schemas';

interface DefenseArtifactPanelProps {
  artifact: DefenseArtifactInfo;
  manifest?: Manifest;
  onVersionMismatchToggle?: (mismatch: boolean) => void;
  isVersionMismatched?: boolean;
}

export const DefenseArtifactPanel: React.FC<DefenseArtifactPanelProps> = ({
  artifact,
  manifest,
  onVersionMismatchToggle,
  isVersionMismatched = false,
}) => {
  const [internalMismatch, setInternalMismatch] = useState<boolean>(isVersionMismatched);

  const handleToggleMismatch = () => {
    const nextVal = !internalMismatch;
    setInternalMismatch(nextVal);
    onVersionMismatchToggle?.(nextVal);
  };

  const declaredVersion = manifest?.versions.defense_runtime ?? artifact.version;
  const activeVersion = internalMismatch ? `${artifact.version}-unwitnessed-dev` : declaredVersion;
  const isMismatch = internalMismatch || activeVersion !== declaredVersion;

  return (
    <div className="space-y-4">
      {/* VERSION_MISMATCH Alert Banner */}
      {isMismatch && (
        <div
          role="alert"
          aria-live="assertive"
          className="border border-bad bg-s2 p-4 text-xs font-mono"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-bad shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-bold text-bad uppercase tracking-wider">VERSION_MISMATCH</span>
                <span className="text-mut text-[11px]">— ACTIVE EPOCH INVALIDATED</span>
              </div>
              <p className="text-tx text-xs">
                Defense artifact version mismatch detected. Runtime container reported{' '}
                <span className="text-bad font-semibold">{activeVersion}</span>, but manifest pinned{' '}
                <span className="text-cy font-semibold">{declaredVersion}</span>. Per protocol invariant 5, all turns under this mismatch are invalidated.
              </p>
            </div>
          </div>
        </div>
      )}

      <Panel
        label="01 — DEFENSE ARTIFACT VAULT & ENVELOPE"
        meta="IMMUTABLE CONTAINER RUNTIME"
        className="p-5"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Artifact Identity & Envelope */}
          <div className="lg:col-span-7 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-bd pb-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-sm border border-bl/40 bg-s2 text-bl">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="font-mono text-sm font-semibold text-tx uppercase tracking-wider">
                      {artifact.name}
                    </h2>
                    <span className="border border-bl/30 bg-bl/10 px-1.5 py-0.5 font-mono text-[11px] text-bl">
                      {activeVersion}
                    </span>
                  </div>
                  <div className="mt-0.5 font-mono text-xs text-mut">
                    Execution Lane: <span className="text-tx">{artifact.runtime_lane}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <StatusPill
                  status={isMismatch ? 'INVALID' : 'VALID_WITHIN_PROFILE'}
                  label={isMismatch ? 'VERSION INVALIDATED' : 'FROZEN & SEALED'}
                />
              </div>
            </div>

            {/* Envelope & Digest Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="border border-bd bg-s2 p-3.5 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] uppercase tracking-wider text-mut">
                    Immutable Image Digest
                  </span>
                  <HardDrive className="h-3.5 w-3.5 text-mut" />
                </div>
                <Digest hash={artifact.digest} />
              </div>

              <div className="border border-bd bg-s2 p-3.5 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] uppercase tracking-wider text-mut">
                    Memory Envelope
                  </span>
                  <Cpu className="h-3.5 w-3.5 text-mut" />
                </div>
                <div className="font-mono text-sm font-semibold text-tx">
                  {artifact.memory_limit_mb.toLocaleString()} MB LIMIT
                </div>
                <div className="font-mono text-[11px] text-mut">
                  cgroup v2 isolation enforced
                </div>
              </div>
            </div>

            {/* Test Simulation Controls */}
            <div className="flex items-center justify-between pt-2 border-t border-bd text-xs font-mono">
              <span className="text-mut text-[11px]">
                TEST HARNESS: Simulate defense artifact version drift
              </span>
              <button
                type="button"
                onClick={handleToggleMismatch}
                aria-pressed={isMismatch}
                className="inline-flex items-center gap-1.5 border border-bd px-2.5 py-1 text-xs text-mut hover:border-bl hover:text-bl focus:outline-none focus:ring-1 focus:ring-cy transition-colors"
              >
                <RefreshCw className="h-3 w-3" />
                {isMismatch ? 'Restore Pinned Version' : 'Simulate Version Mismatch'}
              </button>
            </div>
          </div>

          {/* Right Column: Readiness Probes */}
          <div className="lg:col-span-5 border border-bd bg-s2 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-bd pb-2">
              <span className="font-mono text-xs font-semibold uppercase tracking-wider text-tx">
                Readiness Probes (4/4 PASS)
              </span>
              <span className="border border-ok/30 bg-ok/10 px-1.5 py-0.5 font-mono text-[10px] text-ok">
                SANDBOX ACTIVE
              </span>
            </div>

            <div className="space-y-2.5">
              {artifact.probes.map((probe) => (
                <div
                  key={probe.id}
                  className="border border-bd/60 bg-s1 p-2.5 space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-medium text-tx flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5 text-ok shrink-0" />
                      {probe.name}
                    </span>
                    <span className="font-mono text-[11px] text-mut">
                      {probe.latency_ms} ms
                    </span>
                  </div>
                  <p className="font-mono text-[11px] text-mut pl-5">
                    {probe.detail}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
};
