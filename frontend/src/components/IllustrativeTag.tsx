import React from 'react';
import { HelpCircle } from 'lucide-react';
import { cn } from '../lib/cn';

export interface IllustrativeTagProps {
  className?: string;
  tooltip?: string;
}

/**
 * IllustrativeTag: Invariant 8 — Honest Data.
 * Anything not computed by real code is tagged ILLUSTRATIVE in the UI.
 */
export const IllustrativeTag: React.FC<IllustrativeTagProps> = ({
  className,
  tooltip = 'ILLUSTRATIVE — not a measured result',
}) => {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 font-mono text-[10px] text-mut bg-s2/60 border border-bd px-1.5 py-0.5 rounded select-none tracking-wider uppercase',
        className
      )}
      title={tooltip}
    >
      <HelpCircle className="w-2.5 h-2.5 text-mut stroke-[1.5]" />
      <span>ILLUSTRATIVE</span>
    </span>
  );
};
