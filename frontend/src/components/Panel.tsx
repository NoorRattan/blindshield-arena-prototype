import React from 'react';
import { cn } from '../lib/cn';

export interface PanelProps extends React.HTMLAttributes<HTMLDivElement> {
  label?: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  interactive?: boolean;
  bodyClassName?: string;
  as?: 'section' | 'div' | 'article';
}

export const Panel: React.FC<PanelProps> = ({
  label,
  meta,
  actions,
  interactive = false,
  bodyClassName = 'p-5 md:p-6',
  className,
  children,
  as: Component = 'section',
  ...rest
}) => {
  const hasHeader = Boolean(label || meta || actions);

  return (
    <Component
      className={cn(
        'relative bg-s1 border border-bd rounded text-tx transition-colors',
        interactive && 'focus-within:border-cy hover:border-bd-strong',
        className
      )}
      {...rest}
    >
      {/* Corner ticks: 6px L-shaped marks at all four corners in --bd-strong */}
      <span
        aria-hidden="true"
        className="pointer-events-none absolute -top-px -left-px w-2 h-2 border-t-2 border-l-2 border-bd-strong z-10"
      />
      <span
        aria-hidden="true"
        className="pointer-events-none absolute -top-px -right-px w-2 h-2 border-t-2 border-r-2 border-bd-strong z-10"
      />
      <span
        aria-hidden="true"
        className="pointer-events-none absolute -bottom-px -left-px w-2 h-2 border-b-2 border-l-2 border-bd-strong z-10"
      />
      <span
        aria-hidden="true"
        className="pointer-events-none absolute -bottom-px -right-px w-2 h-2 border-b-2 border-r-2 border-bd-strong z-10"
      />

      {/* Header strip */}
      {hasHeader && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-bd px-4 py-2.5 bg-s2/40 text-xs font-mono tracking-wider">
          <div className="flex items-center gap-2 text-tx font-medium uppercase min-w-0">
            {label}
          </div>
          <div className="flex flex-wrap items-center gap-2 text-mut text-[11px]">
            {meta && <span>{meta}</span>}
            {actions && <div className="flex items-center gap-1.5">{actions}</div>}
          </div>
        </div>
      )}

      {/* Panel Body */}
      <div className={bodyClassName}>{children}</div>
    </Component>
  );
};
