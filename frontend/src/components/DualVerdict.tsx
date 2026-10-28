import React from 'react';
import { StatusPill, type StatusValue } from './StatusPill';
import { cn } from '../lib/cn';
import { AlertTriangle, ShieldCheck, ShieldAlert } from 'lucide-react';

export interface DualVerdictProps {
  modelOutcome: StatusValue;
  integrity: StatusValue;
  scoringOutcome?: StatusValue;
  size?: 'sm' | 'md';
  layout?: 'row' | 'stack';
  className?: string;
}

export const DualVerdict: React.FC<DualVerdictProps> = ({
  modelOutcome,
  integrity,
  scoringOutcome,
  size = 'md',
  layout = 'stack',
  className,
}) => {
  // Invariant 1 & P02 Requirement:
  // "Two verdicts, always. Model outcome and Evaluation Integrity are shown separately, side by side.
  // INVALID integrity forces model row to show NOT_EVALUATED/UNKNOWN style, never green."
  const isIntegrityInvalid = integrity === 'INVALID';

  // If integrity is INVALID, the model outcome cannot be trusted or considered valid/safe
  const effectiveModelOutcome: StatusValue = isIntegrityInvalid
    ? 'NOT_EVALUATED'
    : modelOutcome;

  return (
    <div
      className={cn(
        'border border-bd bg-s1/90 rounded p-2.5 font-mono select-none',
        layout === 'row' ? 'flex flex-wrap items-center gap-4' : 'flex flex-col gap-2',
        className
      )}
      role="group"
      aria-label="Dual Verdict: Model Outcome and Evaluation Integrity"
    >
      {/* Integrity Verdict */}
      <div className="flex items-center justify-between gap-3 text-xs">
        <span className="flex items-center gap-1.5 text-mut uppercase tracking-wider text-[11px]">
          {isIntegrityInvalid ? (
            <ShieldAlert className="w-3.5 h-3.5 text-inv" />
          ) : (
            <ShieldCheck className="w-3.5 h-3.5 text-ok" />
          )}
          <span>Assurance Integrity</span>
        </span>
        <StatusPill status={integrity} size={size} />
      </div>

      {/* Model Outcome Verdict */}
      <div className="flex items-center justify-between gap-3 text-xs pt-1.5 border-t border-bd/60">
        <span className="flex items-center gap-1.5 text-mut uppercase tracking-wider text-[11px]">
          {isIntegrityInvalid && (
            <span title="Compromised by invalid integrity">
              <AlertTriangle className="w-3.5 h-3.5 text-am" />
            </span>
          )}
          <span>Model Outcome</span>
        </span>
        <div className="flex items-center gap-1.5">
          <StatusPill
            status={effectiveModelOutcome}
            label={isIntegrityInvalid ? 'INVALIDATED' : undefined}
            size={size}
          />
          {scoringOutcome && !isIntegrityInvalid && (
            <StatusPill status={scoringOutcome} size="sm" />
          )}
        </div>
      </div>
    </div>
  );
};
