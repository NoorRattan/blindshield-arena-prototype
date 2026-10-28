import React from 'react';
import { z } from 'zod';
import { cn } from '../lib/cn';

// Invariant 5: Epoch is an exact positive integer
export const EpochSchema = z.number().int().positive();

export interface EpochBadgeProps {
  epoch: unknown;
  size?: 'sm' | 'md';
  className?: string;
}

export const EpochBadge: React.FC<EpochBadgeProps> = ({
  epoch,
  size = 'md',
  className,
}) => {
  const result = EpochSchema.safeParse(epoch);

  if (!result.success) {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1 font-mono uppercase rounded border border-inv/40 bg-inv/10 text-inv font-medium select-none',
          size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs',
          className
        )}
        title="Invalid epoch: must be an exact positive integer"
      >
        <span>EPOCH</span>
        <span className="tabular-nums font-bold">INVALID</span>
      </span>
    );
  }

  const validEpoch = result.data;
  const formatted = String(validEpoch).padStart(2, '0');

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 font-mono uppercase rounded border border-cy/30 bg-cy/10 text-tx select-none tracking-wider',
        size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs',
        className
      )}
    >
      <span className="text-mut text-[10px]">EPOCH</span>
      <span className="text-cy font-bold tabular-nums">{formatted}</span>
    </span>
  );
};
