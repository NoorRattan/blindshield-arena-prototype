import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { cn } from '../lib/cn';

export interface DigestProps {
  hash: string;
  prefixLen?: number;
  suffixLen?: number;
  className?: string;
  showFullOnFocus?: boolean;
}

export const Digest: React.FC<DigestProps> = ({
  hash,
  prefixLen = 6,
  suffixLen = 4,
  className,
  showFullOnFocus = true,
}) => {
  const [copied, setCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  const cleanHash = (hash || '').trim();
  const isShort = cleanHash.length <= prefixLen + suffixLen + 3;
  const shortText = isShort
    ? cleanHash
    : `${cleanHash.slice(0, prefixLen)}…${cleanHash.slice(-suffixLen)}`;

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(cleanHash);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Fallback if clipboard API unavailable
      setCopied(false);
    }
  };

  return (
    <span
      className={cn(
        'relative inline-flex items-center gap-1.5 font-mono text-xs text-tx bg-s2/60 border border-bd px-1.5 py-0.5 rounded select-all',
        className
      )}
      onMouseEnter={() => showFullOnFocus && setIsExpanded(true)}
      onMouseLeave={() => showFullOnFocus && setIsExpanded(false)}
      title={cleanHash}
      aria-label={`Digest: ${cleanHash}`}
    >
      <span className="tabular-nums text-mut hover:text-tx transition-colors">
        {shortText}
      </span>

      <button
        type="button"
        onClick={handleCopy}
        onFocus={() => showFullOnFocus && setIsExpanded(true)}
        onBlur={() => showFullOnFocus && setIsExpanded(false)}
        className="p-0.5 hover:text-cy text-mut rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy transition-colors"
        aria-label={copied ? 'Digest copied to clipboard' : 'Copy full digest'}
        title="Copy full digest"
      >
        {copied ? (
          <Check className="w-3 h-3 text-ok stroke-[2]" />
        ) : (
          <Copy className="w-3 h-3 stroke-[1.5]" />
        )}
      </button>

      {/* Full hash popover on hover/focus */}
      {showFullOnFocus && isExpanded && !isShort && (
        <span
          role="tooltip"
          className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 px-2.5 py-1.5 bg-s1 border border-bd-strong text-tx text-[11px] font-mono break-all max-w-xs z-50 rounded shadow-none pointer-events-none whitespace-normal select-text"
        >
          <span className="text-mut block text-[9px] uppercase tracking-wider mb-0.5">
            Full SHA-256 Digest
          </span>
          {cleanHash}
        </span>
      )}
    </span>
  );
};
