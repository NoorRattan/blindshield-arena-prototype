import React from 'react';
import { cn } from '../lib/cn';

export interface PageHeaderProps {
  docId: string;
  title: string;
  description?: string;
  epoch?: number;
  timestamp?: string;
  status?: React.ReactNode;
  actions?: React.ReactNode;
  breadcrumb?: string;
  className?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  docId,
  title,
  description,
  epoch,
  timestamp,
  status,
  actions,
  breadcrumb,
  className,
}) => {
  return (
    <header className={cn('border-b border-bd pb-4 mb-6', className)}>
      {/* Top document metadata line */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-mut uppercase tracking-wider mb-2">
        <div className="flex items-center gap-2">
          <span className="text-cy font-medium">{docId}</span>
          {breadcrumb && (
            <>
              <span className="text-mut">/</span>
              <span className="text-mut">{breadcrumb}</span>
            </>
          )}
        </div>
        <div className="flex items-center gap-4 text-[11px] font-mono">
          {typeof epoch === 'number' && (
            <span>
              EPOCH <strong className="text-tx font-mono">{String(epoch).padStart(2, '0')}</strong>
            </span>
          )}
          {timestamp && <span className="text-mut">{timestamp}</span>}
          {status && <div>{status}</div>}
        </div>
      </div>

      {/* Main Title row */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-4xl sm:text-5xl lg:text-6xl text-tx tracking-wider leading-none">
            {title}
          </h1>
          {description && (
            <p className="mt-2 text-sm text-mut max-w-3xl leading-relaxed">
              {description}
            </p>
          )}
        </div>
        {actions && (
          <div className="flex items-center gap-3 shrink-0 self-start md:self-end">
            {actions}
          </div>
        )}
      </div>
    </header>
  );
};
