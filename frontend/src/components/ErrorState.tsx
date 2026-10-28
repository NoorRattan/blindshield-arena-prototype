import React from 'react';
import { AlertOctagon, RotateCcw } from 'lucide-react';
import { cn } from '../lib/cn';

export interface ErrorStateProps {
  code: string;
  title: string;
  message: string;
  details?: string;
  onRetry?: () => void;
  retryLabel?: string;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  code,
  title,
  message,
  details,
  onRetry,
  retryLabel,
  className,
}) => {
  return (
    <div
      role="alert"
      className={cn(
        'border border-bad/40 bg-s1 rounded p-6 font-mono text-xs text-tx relative',
        className
      )}
    >
      {/* Signature corner ticks in bad/strong */}
      <span aria-hidden="true" className="pointer-events-none absolute -top-px -left-px w-2 h-2 border-t-2 border-l-2 border-bad/60" />
      <span aria-hidden="true" className="pointer-events-none absolute -top-px -right-px w-2 h-2 border-t-2 border-r-2 border-bad/60" />
      <span aria-hidden="true" className="pointer-events-none absolute -bottom-px -left-px w-2 h-2 border-b-2 border-l-2 border-bad/60" />
      <span aria-hidden="true" className="pointer-events-none absolute -bottom-px -right-px w-2 h-2 border-b-2 border-r-2 border-bad/60" />

      <div className="flex items-start gap-3.5">
        <div className="w-8 h-8 rounded border border-bad/40 bg-bad/10 text-bad flex items-center justify-center shrink-0">
          <AlertOctagon className="w-4 h-4 stroke-[2]" />
        </div>

        <div className="flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] text-bad font-mono border border-bad/40 bg-bad/10 px-1.5 py-0.5 rounded uppercase">
              {code}
            </span>
            <h2 className="font-display text-lg text-tx tracking-wider uppercase">
              {title}
            </h2>
          </div>

          <p className="text-mut text-xs leading-relaxed">{message}</p>

          {details && (
            <pre className="mt-2 p-2.5 bg-bg/90 border border-bd rounded text-[11px] text-mut whitespace-pre-wrap break-all overflow-x-auto">
              {details}
            </pre>
          )}

          {onRetry && (
            <div className="pt-3">
              <button
                type="button"
                onClick={onRetry}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-bd text-xs font-mono uppercase tracking-wider text-tx hover:border-cy hover:text-cy transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>{retryLabel ?? 'Retry Operation'}</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
