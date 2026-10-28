import React, { useState } from 'react';
import { ShieldAlert, ArrowDown, ChevronRight, Hash, User } from 'lucide-react';
import type { ArenaEvent } from '../../lib/schemas';
import { StatusPill } from '../../components/StatusPill';

interface EvidenceChain2DFallbackProps {
  ledger: ArenaEvent[];
  brokenIndex?: number;
  selectedSeq?: number;
  onSelectEvent: (event: ArenaEvent) => void;
  className?: string;
}

export const EvidenceChain2DFallback: React.FC<EvidenceChain2DFallbackProps> = ({
  ledger,
  brokenIndex,
  selectedSeq,
  onSelectEvent,
  className,
}) => {
  const [filterActor, setFilterActor] = useState<string>('all');

  const filteredEvents = ledger.filter((ev) => {
    if (filterActor === 'all') return true;
    return ev.actor === filterActor;
  });

  return (
    <div className={`space-y-3 font-mono text-xs ${className || ''}`}>
      {/* Filter and stats strip */}
      <div className="flex items-center justify-between pb-2 border-b border-bd/40 text-[11px] text-mut">
        <div className="flex items-center gap-2">
          <span>Filter:</span>
          {['all', 'red', 'blue', 'operator'].map((actor) => (
            <button
              key={actor}
              type="button"
              onClick={() => setFilterActor(actor)}
              className={`px-2 py-0.5 rounded-[2px] border text-[10px] uppercase transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy ${
                filterActor === actor
                  ? 'bg-s2 border-cy text-tx'
                  : 'bg-s1 border-bd text-mut hover:border-bd-strong'
              }`}
            >
              {actor}
            </button>
          ))}
        </div>

        <div>
          Showing {filteredEvents.length} of {ledger.length} events
        </div>
      </div>

      {/* Events List */}
      <div
        className="space-y-1.5 max-h-[460px] overflow-y-auto pr-1"
        role="region"
        aria-label="2D Merkle Hash Chain Ledger Stream"
        tabIndex={0}
      >
        {filteredEvents.map((event, idx) => {
          const isBroken = brokenIndex !== undefined && event.seq === brokenIndex + 1;
          const isSelected = selectedSeq === event.seq;

          return (
            <React.Fragment key={event.seq}>
              {/* Chain rupture indicator */}
              {isBroken && (
                <div className="my-2 p-2 rounded-[2px] bg-bad/10 border-2 border-bad text-bad flex items-center justify-between animate-pulse">
                  <div className="flex items-center gap-2 text-xs font-bold">
                    <ShieldAlert size={14} />
                    CHAIN RUPTURE DETECTED (HASH MISMATCH AT SEQ #{event.seq})
                  </div>
                  <div className="text-[10px] uppercase tracking-wider">
                    Downstream Merkle links invalidated
                  </div>
                </div>
              )}

              <div
                role="button"
                aria-label={`Event #${event.seq}`}
                tabIndex={0}
                onClick={() => onSelectEvent(event)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelectEvent(event);
                  }
                }}
                className={`p-2.5 rounded-[2px] border cursor-pointer transition-all flex items-center justify-between gap-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy ${
                  isSelected
                    ? 'bg-cy/15 border-cy text-tx'
                    : isBroken
                      ? 'bg-bad/10 border-bad/50 hover:border-bad'
                      : 'bg-s2/50 border-bd/60 hover:bg-s2 hover:border-bd'
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className="text-cy text-[11px] font-bold w-12 shrink-0">
                    #{String(event.seq).padStart(3, '0')}
                  </span>

                  <StatusPill
                    status={event.actor === 'red' ? 'EXECUTED' : event.actor === 'blue' ? 'SEALED' : 'RUNNING'}
                    label={event.actor.toUpperCase()}
                    size="sm"
                  />

                  <div className="min-w-0">
                    <div className="text-xs text-tx font-medium truncate flex items-center gap-1.5">
                      <span>{event.action}</span>
                      <span className="text-[10px] text-mut">({event.outcome})</span>
                    </div>
                    <div className="text-[10px] text-mut truncate flex items-center gap-2">
                      <span className="flex items-center gap-0.5">
                        <User size={10} className="text-dim" />
                        {event.actor}
                      </span>
                      <span>·</span>
                      <span className="flex items-center gap-0.5">
                        <Hash size={10} className="text-dim" />
                        {event.prev === 'genesis' ? 'genesis' : event.prev.slice(0, 16) + '...'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-mut tabular-nums">{event.ts_utc.slice(11, 19)}</span>
                  <ChevronRight size={13} className="text-mut" />
                </div>
              </div>

              {idx < filteredEvents.length - 1 && (
                <div className="flex justify-center py-0.5 pointer-events-none">
                  <ArrowDown size={11} className={isBroken ? 'text-bad' : 'text-bd'} />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
