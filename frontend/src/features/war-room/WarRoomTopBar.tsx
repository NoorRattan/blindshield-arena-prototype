import React, { useState } from 'react';
import { AlertOctagon, ShieldCheck, RefreshCw, Radio } from 'lucide-react';
import { StatusPill, type StatusValue } from '../../components/StatusPill';
import { DualVerdict } from '../../components/DualVerdict';
import { EpochBadge } from '../../components/EpochBadge';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { useArenaStore } from '../../state/useArenaStore';
import { cn } from '../../lib/cn';
import type { LifecycleState } from '../../lib/schemas';

export interface WarRoomTopBarProps {
  experimentId: string;
  domain: string;
  epoch: number;
  lifecycleState: LifecycleState;
  integrityStatus: StatusValue;
  modelOutcome: StatusValue;
  witnessStatus: 'SYNCED' | 'LAGGING' | 'OFFLINE';
  invalidReason?: string;
  onQuarantine: (reason: string) => void;
  onTriggerReWitness: () => void;
  isQuarantining?: boolean;
  isReWitnessing?: boolean;
}

export const WarRoomTopBar: React.FC<WarRoomTopBarProps> = ({
  experimentId,
  domain,
  epoch,
  lifecycleState,
  integrityStatus,
  modelOutcome,
  witnessStatus,
  invalidReason,
  onQuarantine,
  onTriggerReWitness,
  isQuarantining = false,
  isReWitnessing = false,
}) => {
  const [isQuarantineDialogOpen, setIsQuarantineDialogOpen] = useState(false);
  const role = useArenaStore((s) => s.role);
  const isOperator = role === 'operator';

  const isInvalid = lifecycleState === 'INVALID' || integrityStatus === 'INVALID';

  return (
    <div
      className={cn(
        'border border-bd bg-s1 p-4 mb-4 rounded',
        isInvalid && 'border-inv/60 bg-inv/5'
      )}
      role="region"
      aria-label="War Room Command Header"
    >
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left: Document info & Identity */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <Radio
              className={cn(
                'w-4 h-4',
                lifecycleState === 'RUNNING' && 'text-cy animate-pulse',
                lifecycleState === 'INVALID' && 'text-inv',
                lifecycleState === 'CLOSED' && 'text-mut'
              )}
            />
            <span className="font-mono text-xs uppercase tracking-wider text-mut">
              DOC-WAR-04 // ARENA COMMAND COCKPIT
            </span>
          </div>

          <span className="text-dim">|</span>

          {/* Domain name */}
          <span className="font-mono font-medium text-sm text-tx tracking-wide">
            {domain}
          </span>

          <span className="text-dim">|</span>

          {/* Experiment ID */}
          <span className="font-mono text-xs text-mut" title={`Experiment ID: ${experimentId}`}>
            {experimentId}
          </span>

          {/* Epoch Badge (Invariant 5: Exact positive integer) */}
          <EpochBadge epoch={epoch} />

          {/* Lifecycle state pill */}
          <StatusPill status={lifecycleState} size="md" />

          {/* Witness watermark pill */}
          <span
            className={cn(
              'inline-flex items-center gap-1 px-2 py-0.5 border text-xs font-mono uppercase tracking-wider',
              witnessStatus === 'SYNCED'
                ? 'border-ok/40 bg-ok/10 text-ok'
                : 'border-am/60 bg-am/15 text-am'
            )}
            title={witnessStatus === 'SYNCED' ? 'Witness anchor synced' : 'Witness lag detected'}
          >
            <ShieldCheck className="w-3 h-3" />
            WITNESS: {witnessStatus}
          </span>
        </div>

        {/* Right: Operational Actions & Dual Verdict */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Dual Verdict (Invariant 1: Two verdicts, always) */}
          <DualVerdict
            modelOutcome={modelOutcome}
            integrity={integrityStatus}
            size="sm"
            layout="row"
            className="bg-s2/80 py-1.5 px-3"
          />

          {/* Operator Controls (Emergency Quarantine & Re-Witness) */}
          {isOperator ? (
            <>
              {/* Trigger Re-Witness Button */}
              <button
                type="button"
                onClick={onTriggerReWitness}
                disabled={isReWitnessing || lifecycleState === 'INVALID'}
                className={cn(
                  'inline-flex items-center gap-1.5 px-3 py-1.5 border border-cy/50 bg-s2 text-cy',
                  'font-mono text-xs tracking-wider uppercase font-medium rounded-sm hover:bg-cy/10',
                  'focus:outline-none focus-visible:ring-2 focus-visible:ring-cy focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
                  'disabled:opacity-40 disabled:cursor-not-allowed transition-colors'
                )}
                title="Force immediate witness signature & anchor checkpoint"
              >
                <RefreshCw className={cn('w-3.5 h-3.5', isReWitnessing && 'animate-spin')} />
                <span>{isReWitnessing ? 'Witnessing...' : 'Re-Witness'}</span>
              </button>

              {/* Emergency Stop / Quarantine Button */}
              <button
                type="button"
                onClick={() => setIsQuarantineDialogOpen(true)}
                disabled={isQuarantining || lifecycleState === 'INVALID'}
                className={cn(
                  'inline-flex items-center gap-1.5 px-3 py-1.5 border border-bad/60 bg-s2 text-bad',
                  'font-mono text-xs tracking-wider uppercase font-medium rounded-sm hover:bg-bad/15',
                  'focus:outline-none focus-visible:ring-2 focus-visible:ring-bad focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
                  'disabled:opacity-40 disabled:cursor-not-allowed transition-colors'
                )}
                title="Immediately halt execution and mark domain as quarantined INVALID"
              >
                <AlertOctagon className="w-3.5 h-3.5 text-bad" />
                <span>
                  {lifecycleState === 'INVALID'
                    ? 'Domain Quarantined'
                    : isQuarantining
                      ? 'Quarantining...'
                      : 'Emergency Quarantine'}
                </span>
              </button>
            </>
          ) : (
            <span
              className="px-2.5 py-1 text-xs font-mono uppercase bg-am/10 border border-am/40 text-am tracking-wider rounded-sm select-none"
              title="Non-operator roles receive delayed, coarse-grained telemetry"
            >
              DELAYED T-30s
            </span>
          )}
        </div>
      </div>

      {/* Invalid reason alert banner if quarantined or failed */}
      {isInvalid && invalidReason && (
        <div
          role="alert"
          className="mt-3 p-2.5 border border-inv bg-inv/15 text-tx font-mono text-xs flex items-center justify-between"
        >
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-inv flex-shrink-0" />
            <span>
              <strong className="text-inv uppercase">ASSURANCE INTEGRITY ALERT:</strong>{' '}
              {invalidReason}
            </span>
          </div>
          <span className="text-[11px] text-mut uppercase">NO RETRY PERMITTED</span>
        </div>
      )}

      {/* Typed Confirmation Modal for Emergency Quarantine */}
      <ConfirmDialog
        isOpen={isQuarantineDialogOpen}
        title="EMERGENCY STOP & DOMAIN QUARANTINE"
        description="Quarantining this domain immediately halts active inference pipelines, invalidates in-flight turns, and permanently transitions this epoch lifecycle to INVALID. A signed witness incident event will be sealed into the ledger."
        confirmWord="QUARANTINE"
        confirmButtonLabel="Confirm Quarantine"
        isDestructive={true}
        onConfirm={() => {
          setIsQuarantineDialogOpen(false);
          onQuarantine('OPERATOR_EMERGENCY_QUARANTINE');
        }}
        onCancel={() => setIsQuarantineDialogOpen(false)}
      />
    </div>
  );
};
