import React from 'react';
import { Clock } from 'lucide-react';
import { cn } from '../lib/cn';

export interface DelayedTagProps {
  delay?: string;
  className?: string;
}

/**
 * DelayedTag: Invariant 9 — Non-operators see coarse, delayed telemetry.
 * Always explicitly indicated in the UI.
 */
export const DelayedTag: React.FC<DelayedTagProps> = ({
  delay = 'T-30s',
  className,
}) => {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 font-mono text-[11px] text-mut bg-s2/80 border border-bd px-1.5 py-0.5 rounded select-none uppercase tracking-wider',
        className
      )}
      title="Non-operator telemetry is intentionally delayed and coarse-grained to mitigate side channels"
    >
      <Clock className="w-3 h-3 text-mut stroke-[1.5]" />
      <span>DELAYED {delay}</span>
    </span>
  );
};
