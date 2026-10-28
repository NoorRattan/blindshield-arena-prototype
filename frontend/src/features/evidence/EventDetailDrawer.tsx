import React, { useEffect } from 'react';
import { X, Copy, Check, Hash, Clock, User, Shield } from 'lucide-react';
import { canonicalJson, computeChainDigest } from '../../lib/crypto';
import type { ArenaEvent } from '../../lib/schemas';
import { UntrustedText } from '../../components/UntrustedText';
import { StatusPill } from '../../components/StatusPill';

interface EventDetailDrawerProps {
  event: ArenaEvent | null;
  onClose: () => void;
  isOpen: boolean;
}

export const EventDetailDrawer: React.FC<EventDetailDrawerProps> = ({
  event,
  onClose,
  isOpen,
}) => {
  const [copied, setCopied] = React.useState(false);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !event) return null;

  let canonicalStr = '';
  let computedDigest = '';
  try {
    canonicalStr = canonicalJson(event);
    computedDigest = computeChainDigest(event.prev, event);
  } catch (err) {
    canonicalStr = JSON.stringify(event, null, 2);
    computedDigest = 'calculation error';
  }

  const handleCopyJson = () => {
    navigator.clipboard.writeText(canonicalStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Event Details Sequence #${event.seq}`}
      className="fixed inset-0 z-50 flex justify-end bg-bg/80 backdrop-blur-sm transition-opacity"
    >
      <div className="w-full max-w-lg bg-s1 border-l border-bd h-full flex flex-col shadow-2xl z-10 font-mono text-xs">
        {/* Drawer Header */}
        <div className="flex items-center justify-between p-4 border-b border-bd bg-s2/40">
          <div className="flex items-center gap-2">
            <span className="text-cy text-sm font-bold tracking-wider">
              EVENT #{String(event.seq).padStart(3, '0')}
            </span>
            <span className="text-mut text-[11px]">EPOCH {event.epoch}</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopyJson}
              className="p-1.5 rounded-[2px] border border-bd bg-s2 text-mut hover:text-tx hover:border-cy transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy flex items-center gap-1 text-[11px]"
              title="Copy canonical RFC 8785 JSON"
            >
              {copied ? <Check size={12} className="text-ok" /> : <Copy size={12} />}
              {copied ? 'COPIED' : 'COPY JSON'}
            </button>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-[2px] border border-bd bg-s2 text-mut hover:text-tx hover:border-bad transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy"
              aria-label="Close Event Details"
            >
              <X size={14} />
            </button>
          </div>
        </div>

        {/* Drawer Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="p-2.5 rounded-[2px] bg-s2 border border-bd space-y-1">
              <div className="text-mut text-[10px] uppercase flex items-center gap-1">
                <User size={11} className="text-cy" />
                Actor & Action
              </div>
              <div className="text-tx font-semibold truncate flex items-center gap-1.5">
                <StatusPill
                  status={event.actor === 'red' ? 'EXECUTED' : event.actor === 'blue' ? 'SEALED' : 'RUNNING'}
                  label={event.actor.toUpperCase()}
                  size="sm"
                />
                <span className="text-tx">{event.actor}</span>
              </div>
              <div className="text-mut truncate">{event.action}</div>
            </div>

            <div className="p-2.5 rounded-[2px] bg-s2 border border-bd space-y-1">
              <div className="text-mut text-[10px] uppercase flex items-center gap-1">
                <Shield size={11} className="text-cy" />
                Outcome
              </div>
              <div className="text-tx font-semibold truncate">{event.outcome}</div>
              <div className="text-mut text-[10px]">Schema {event.schema}</div>
            </div>

            <div className="p-2.5 rounded-[2px] bg-s2 border border-bd space-y-1 col-span-2">
              <div className="text-mut text-[10px] uppercase flex items-center gap-1">
                <Clock size={11} className="text-cy" />
                Timestamps (UTC &amp; Monotonic)
              </div>
              <div className="text-tx truncate">{event.ts_utc}</div>
              <div className="text-mut text-[10px]">mono_ms: {event.mono_ms} ms (watermark)</div>
            </div>
          </div>

          {/* Cryptographic Linkage Hashes */}
          <div className="p-2.5 rounded-[2px] bg-s2 border border-bd space-y-2">
            <div>
              <div className="text-[10px] text-mut uppercase flex items-center gap-1">
                <Hash size={11} className="text-cy" />
                Previous Link Digest (prev)
              </div>
              <div className="text-[11px] text-tx break-all select-all mt-0.5">
                {event.prev}
              </div>
            </div>

            <div className="pt-2 border-t border-bd/40">
              <div className="text-[10px] text-mut uppercase flex items-center gap-1">
                <Hash size={11} className="text-ok" />
                Chained Event Digest (SHA-256)
              </div>
              <div className="text-[11px] text-ok break-all select-all mt-0.5">
                {computedDigest}
              </div>
            </div>
          </div>

          {/* Artifacts Attached */}
          {event.artifacts && event.artifacts.length > 0 && (
            <div className="p-2.5 rounded-[2px] bg-s2 border border-bd space-y-1.5">
              <div className="text-[10px] text-mut uppercase">
                Artifact Hashes ({event.artifacts.length})
              </div>
              <div className="space-y-1">
                {event.artifacts.map((art, idx) => (
                  <div key={idx} className="text-[11px] text-tx break-all select-all bg-s1 p-1 rounded-[2px] border border-bd/40">
                    {art}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Canonical RFC 8785 JSON Representation */}
          <div className="space-y-1.5">
            <div className="text-[10px] text-mut uppercase tracking-wider flex items-center justify-between">
              <span>Canonical RFC 8785 JSON</span>
              <span className="text-[9px] text-dim">{new TextEncoder().encode(canonicalStr).length} UTF-8 bytes</span>
            </div>

            <div className="p-3 bg-s2/80 border border-bd rounded-[2px] overflow-hidden">
              {/* Invariant 4: Untrusted text is inert */}
              <div className="whitespace-pre-wrap break-all text-[11px] text-tx font-mono leading-relaxed">
                <UntrustedText text={canonicalStr} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
