import React, { useState } from 'react';
import { AlertCircle, ChevronDown, ChevronUp } from 'lucide-react';
import { cn } from '../lib/cn';

export interface UntrustedTextProps {
  text: string;
  label?: string;
  maxLines?: number;
  className?: string;
}

/**
 * UntrustedText: Renders untrusted inputs/outputs strictly as raw text nodes.
 * Invariant 4: No HTML execution, no markdown parsing, no link unfurling, no remote images.
 * DangerouslySetInnerHTML is banned repo-wide.
 */
export const UntrustedText: React.FC<UntrustedTextProps> = ({
  text,
  label = 'UNTRUSTED DATA SINK',
  maxLines,
  className,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  // Safe string coercion
  const rawString = typeof text === 'string' ? text : String(text ?? '');

  const lineCount = rawString.split('\n').length;
  const canCollapse = typeof maxLines === 'number' && maxLines > 0 && lineCount > maxLines;

  return (
    <div
      className={cn(
        'border border-bd bg-bg/90 rounded overflow-hidden font-mono text-xs text-tx',
        className
      )}
    >
      {/* Header banner labeling untrusted sink */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-s2/80 border-b border-bd text-[10px] text-mut uppercase tracking-wider select-none">
        <div className="flex items-center gap-1.5 text-am font-medium">
          <AlertCircle className="w-3 h-3 stroke-[2]" />
          <span>{label}</span>
        </div>
        <div className="flex items-center gap-2">
          <span>{rawString.length.toLocaleString()} bytes</span>
          {canCollapse && (
            <button
              type="button"
              onClick={() => setIsExpanded(!isExpanded)}
              className="flex items-center gap-1 text-cy hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
            >
              <span>{isExpanded ? 'Collapse' : 'Expand'}</span>
              {isExpanded ? (
                <ChevronUp className="w-3 h-3" />
              ) : (
                <ChevronDown className="w-3 h-3" />
              )}
            </button>
          )}
        </div>
      </div>

      {/* Raw text node inside pre element */}
      <pre
        className={cn(
          'p-3 font-mono text-xs text-tx whitespace-pre-wrap break-all overflow-hidden select-text',
          canCollapse && !isExpanded && 'line-clamp-[6] max-h-40 overflow-hidden'
        )}
        style={
          canCollapse && !isExpanded && maxLines
            ? {
                WebkitLineClamp: maxLines,
                display: '-webkit-box',
                WebkitBoxOrient: 'vertical',
              }
            : undefined
        }
      >
        {/* Pure text node child: React JSX escapes any HTML or script automatically */}
        {rawString}
      </pre>
    </div>
  );
};
