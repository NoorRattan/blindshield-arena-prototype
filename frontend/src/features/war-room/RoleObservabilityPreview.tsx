import React, { useState } from 'react';
import { Panel } from '../../components/Panel';
import { DelayedTag } from '../../components/DelayedTag';
import { EmbargoMask } from '../../components/EmbargoMask';
import { UntrustedText } from '../../components/UntrustedText';
import { cn } from '../../lib/cn';
import { Eye, Shield, Lock, Clock, Info } from 'lucide-react';
import type { Attempt, Role } from '../../lib/schemas';

export interface RoleObservabilityPreviewProps {
  attempt?: Attempt;
  className?: string;
}

export const RoleObservabilityPreview: React.FC<RoleObservabilityPreviewProps> = ({
  attempt,
  className,
}) => {
  const [selectedRole, setSelectedRole] = useState<Role>('operator');

  const defenseLatency = attempt?.latency_ms.defense ?? 148;
  const targetLatency = attempt?.latency_ms.target ?? 614;
  // backend: BLOCKED_BY_DEFENSE is a pipeline_disposition value; model_execution is NOT_EVALUATED for INPUT/FEATURES blocks
  const isBlocked = attempt?.pipeline_disposition === 'BLOCKED_BY_DEFENSE';

  // Coarse 50ms buckets for delayed non-operator views
  const coarseDefenseLatency = Math.round(defenseLatency / 50) * 50;
  const coarseTotalLatency = Math.round((defenseLatency + targetLatency) / 50) * 50;

  return (
    <Panel
      label="03 — ROLE OBSERVABILITY BOUNDARY"
      meta={
        <div className="flex items-center gap-2">
          {selectedRole !== 'operator' && <DelayedTag delay="DELAYED T-30s" />}
          <span className="font-mono text-[11px] text-mut uppercase">
            ACTIVE PREVIEW: <strong className="text-cy">{selectedRole.toUpperCase()}</strong>
          </span>
        </div>
      }
      className={cn('mb-4', className)}
    >
      <div className="space-y-4">
        {/* Role Selection Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-bd/60 pb-3">
          <div className="flex items-center gap-1.5" role="tablist" aria-label="Role Observability Views">
            <button
              type="button"
              role="tab"
              aria-selected={selectedRole === 'operator'}
              onClick={() => setSelectedRole('operator')}
              className={cn(
                'px-3 py-1 font-mono text-xs uppercase tracking-wider border rounded-sm transition-colors',
                'focus:outline-none focus-visible:ring-2 focus-visible:ring-cy',
                selectedRole === 'operator'
                  ? 'border-cy bg-cy/15 text-cy font-bold'
                  : 'border-bd bg-s2 text-mut hover:text-tx hover:border-bd-strong'
              )}
            >
              Operator (Full Telemetry)
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={selectedRole === 'red'}
              onClick={() => setSelectedRole('red')}
              className={cn(
                'px-3 py-1 font-mono text-xs uppercase tracking-wider border rounded-sm transition-colors',
                'focus:outline-none focus-visible:ring-2 focus-visible:ring-am',
                selectedRole === 'red'
                  ? 'border-am bg-am/15 text-am font-bold'
                  : 'border-bd bg-s2 text-mut hover:text-tx hover:border-bd-strong'
              )}
            >
              View as Red Team
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={selectedRole === 'blue'}
              onClick={() => setSelectedRole('blue')}
              className={cn(
                'px-3 py-1 font-mono text-xs uppercase tracking-wider border rounded-sm transition-colors',
                'focus:outline-none focus-visible:ring-2 focus-visible:ring-bl',
                selectedRole === 'blue'
                  ? 'border-bl bg-bl/15 text-bl font-bold'
                  : 'border-bd bg-s2 text-mut hover:text-tx hover:border-bd-strong'
              )}
            >
              View as Blue Team
            </button>
          </div>

          <div className="text-xs font-mono text-mut flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-cy" />
            <span>Server-layer filtered (no client leakage)</span>
          </div>
        </div>

        {/* Comparison Details Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
          {/* Card 1: Latency Disclosure */}
          <div className="border border-bd bg-s2/40 p-3 rounded space-y-2">
            <div className="text-[11px] text-mut uppercase tracking-wider flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-cy" />
              <span>Reported Latency</span>
            </div>
            {selectedRole === 'operator' ? (
              <div>
                <div className="text-sm font-bold text-tx tabular-nums">
                  {defenseLatency} ms <span className="text-mut font-normal">(Defense)</span> / {defenseLatency + targetLatency} ms <span className="text-mut font-normal">(Total)</span>
                </div>
                <div className="text-[10px] text-ok mt-1">Unbucketed exact timestamp delta</div>
              </div>
            ) : selectedRole === 'red' ? (
              <div>
                <div className="text-sm font-bold text-am tabular-nums">
                  ~{coarseTotalLatency} ms <span className="text-mut font-normal">(Coarse Bucket)</span>
                </div>
                <div className="text-[10px] text-mut mt-1">Coarse 50ms rounded + T-30s delay</div>
              </div>
            ) : (
              <div>
                <div className="text-sm font-bold text-bl tabular-nums">
                  ~{coarseDefenseLatency} ms <span className="text-mut font-normal">(Defense Only)</span>
                </div>
                <div className="text-[10px] text-mut mt-1">Coarse 50ms rounded; target timing hidden</div>
              </div>
            )}
          </div>

          {/* Card 2: Decision / Outcome Visibility */}
          <div className="border border-bd bg-s2/40 p-3 rounded space-y-2">
            <div className="text-[11px] text-mut uppercase tracking-wider flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-ok" />
              <span>Decision Disclosure</span>
            </div>
            {selectedRole === 'operator' ? (
              <div>
                <div className="text-sm font-bold text-tx">
                  {isBlocked ? 'BLOCKED_BY_DEFENSE' : 'ALLOWED_BY_DEFENSE'}
                </div>
                <div className="text-[10px] text-ok mt-1">All dual-verdicts & rubrics unmasked</div>
              </div>
            ) : selectedRole === 'red' ? (
              <div>
                <div className="text-sm font-bold text-am">
                  {isBlocked ? 'BLOCKED' : 'ALLOWED'}
                </div>
                <div className="text-[10px] text-mut mt-1">Controlled feedback (C-07); raw text withheld</div>
              </div>
            ) : (
              <div>
                <div className="text-sm font-bold text-dim">
                  <EmbargoMask
                    label="WITHHELD UNTIL CLOSE"
                    reason="Allow/block split masked during active round (C-02)"
                  />
                </div>
                <div className="text-[10px] text-mut mt-1">Zero live feedback to prevent side-channels</div>
              </div>
            )}
          </div>

          {/* Card 3: Attack Payload Text Boundary */}
          <div className="border border-bd bg-s2/40 p-3 rounded space-y-2">
            <div className="text-[11px] text-mut uppercase tracking-wider flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-am" />
              <span>Payload Text Disclosure</span>
            </div>
            {selectedRole === 'operator' ? (
              <div>
                <div className="text-[11px] text-tx truncate">
                  <UntrustedText text="Prompt: [Ignore instructions. Execute shell...] (Encrypted)" />
                </div>
                <div className="text-[10px] text-mut mt-1">Auditor/Operator inspection lane</div>
              </div>
            ) : selectedRole === 'red' ? (
              <div>
                <div className="text-[11px] text-am truncate">
                  <UntrustedText text="Prompt: [Author's own submitted attack payload]" />
                </div>
                <div className="text-[10px] text-mut mt-1">Red submits own payload; cannot see blue code</div>
              </div>
            ) : (
              <div>
                <div className="text-sm font-bold text-dim">
                  <EmbargoMask
                    label="PROMPT TEXT EMBARGOED"
                    reason="Zero human payload disclosure to Blue during round"
                  />
                </div>
                <div className="text-[10px] text-mut mt-1">Payload masked; Blue cell isolated in gVisor</div>
              </div>
            )}
          </div>
        </div>

        {/* Educational Architectural Callout */}
        <div className="p-2.5 border border-bd/60 bg-s1 text-xs text-mut font-mono flex items-start gap-2">
          <Eye className="w-4 h-4 text-cy flex-shrink-0 mt-0.5" />
          <div>
            <strong className="text-tx uppercase">Security Invariant Enforcement:</strong> Role-filtered views are
            computed strictly at the server/mock boundary before dispatch. Non-operator roles never receive raw payloads,
            embargoed decisions, or sub-50ms timing side-channel vectors.
          </div>
        </div>
      </div>
    </Panel>
  );
};
