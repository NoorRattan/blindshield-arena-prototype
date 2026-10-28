import React from 'react';
import { cn } from '../lib/cn';

export interface GaugeProps {
  label: string;
  value: number;
  max?: number;
  min?: number;
  target?: number;
  unit?: string;
  variant?: 'cy' | 'ok' | 'bad' | 'bl' | 'am';
  className?: string;
}

export const Gauge: React.FC<GaugeProps> = ({
  label,
  value,
  max = 100,
  min = 0,
  target,
  unit = '%',
  variant = 'cy',
  className,
}) => {
  const clampedValue = Math.min(Math.max(value, min), max);
  const percentage = ((clampedValue - min) / (max - min)) * 100;
  const targetPercentage = target !== undefined ? ((target - min) / (max - min)) * 100 : undefined;

  const variantColors: Record<typeof variant, { bar: string; text: string }> = {
    cy: { bar: 'bg-cy', text: 'text-cy' },
    ok: { bar: 'bg-ok', text: 'text-ok' },
    bad: { bar: 'bg-bad', text: 'text-bad' },
    bl: { bar: 'bg-bl', text: 'text-bl' },
    am: { bar: 'bg-am', text: 'text-am' },
  };

  const colors = variantColors[variant];

  return (
    <div className={cn('font-mono text-xs w-full select-none', className)}>
      <div className="flex items-center justify-between text-mut mb-1.5 uppercase text-[11px] tracking-wider">
        <span>{label}</span>
        <span className="tabular-nums font-medium text-tx">
          <strong className={colors.text}>{value}</strong>
          <span className="text-mut ml-0.5">{unit}</span>
          {target !== undefined && (
            <span className="text-mut text-[10px] ml-1.5">
              (TARGET ≤ {target}{unit})
            </span>
          )}
        </span>
      </div>

      <div className="relative h-2 w-full bg-s2/80 border border-bd rounded-none overflow-hidden">
        <div
          className={cn('h-full transition-all duration-300 ease-out', colors.bar)}
          style={{ width: `${percentage}%` }}
        />
        {targetPercentage !== undefined && (
          <div
            className="absolute top-0 bottom-0 w-0.5 bg-tx z-10"
            style={{ left: `${targetPercentage}%` }}
            title={`Target limit: ${target}${unit}`}
          />
        )}
      </div>
    </div>
  );
};
