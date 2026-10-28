import React from 'react';
import { Check, X, CircleDot } from 'lucide-react';
import { cn } from '../lib/cn';

export interface StepItem {
  id: string;
  label: string;
  description?: string;
  status: 'completed' | 'active' | 'pending' | 'failed';
}

export interface StepperProps {
  steps: StepItem[];
  orientation?: 'horizontal' | 'vertical';
  className?: string;
}

export const Stepper: React.FC<StepperProps> = ({
  steps,
  orientation = 'horizontal',
  className,
}) => {
  return (
    <div
      tabIndex={0}
      role="region"
      aria-label="Progress Stepper"
      className={cn(
        'font-mono text-xs select-none focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy',
        orientation === 'horizontal'
          ? 'flex items-center justify-between gap-2 overflow-x-auto py-2'
          : 'flex flex-col gap-4',
        className
      )}
    >
      {steps.map((step, index) => {
        const isLast = index === steps.length - 1;

        return (
          <div
            key={step.id}
            className={cn(
              'flex items-center gap-3',
              orientation === 'horizontal' ? 'flex-1 min-w-[140px]' : 'w-full'
            )}
          >
            {/* Step Icon Badge */}
            <div
              className={cn(
                'w-6 h-6 rounded flex items-center justify-center text-xs shrink-0 border transition-colors',
                step.status === 'completed' && 'bg-ok/10 border-ok text-ok',
                step.status === 'active' && 'bg-cy/10 border-cy text-cy animate-pulse',
                step.status === 'failed' && 'bg-bad/10 border-bad text-bad',
                step.status === 'pending' && 'bg-s2 border-bd text-mut'
              )}
            >
              {step.status === 'completed' && <Check className="w-3.5 h-3.5 stroke-[2]" />}
              {step.status === 'failed' && <X className="w-3.5 h-3.5 stroke-[2]" />}
              {step.status === 'active' && <CircleDot className="w-3.5 h-3.5 stroke-[2]" />}
              {step.status === 'pending' && (
                <span className="text-[10px] tabular-nums">{index + 1}</span>
              )}
            </div>

            {/* Label & Description */}
            <div className="flex flex-col truncate">
              <span
                className={cn(
                  'font-medium uppercase tracking-wider text-[11px] truncate',
                  step.status === 'active' && 'text-cy font-bold',
                  step.status === 'completed' && 'text-tx',
                  step.status === 'failed' && 'text-bad',
                  step.status === 'pending' && 'text-mut'
                )}
              >
                {step.label}
              </span>
              {step.description && (
                <span className="text-[10px] text-mut truncate">{step.description}</span>
              )}
            </div>

            {/* Connector Line */}
            {orientation === 'horizontal' && !isLast && (
              <div
                className={cn(
                  'flex-1 h-px ml-2 mr-1 transition-colors',
                  step.status === 'completed' ? 'bg-ok/40' : 'bg-bd'
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
};
