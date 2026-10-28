import React, { useState, useRef, useMemo, useEffect } from 'react';
import { Panel } from '../../components/Panel';
import { UntrustedText } from '../../components/UntrustedText';
import { Digest } from '../../components/Digest';
import { cn } from '../../lib/cn';
import { motion, AnimatePresence } from 'framer-motion';
import { Link2, RefreshCw, AlertCircle, Filter } from 'lucide-react';
import type { ArenaEvent } from '../../lib/schemas';

export interface LiveAuditLogProps {
  events: ArenaEvent[];
  streamStatus: 'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING';
  error?: Error | null;
  className?: string;
}

type ActorFilter = 'all' | 'red' | 'blue' | 'broker' | 'target' | 'scorer' | 'recorder' | 'witness';

const ROW_HEIGHT = 48; // px per row
const OVERSCAN = 6;

export const LiveAuditLog: React.FC<LiveAuditLogProps> = ({
  events,
  streamStatus,
  error,
  className,
}) => {
  const [filter, setFilter] = useState<ActorFilter>('all');
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  // Filter events based on active actor filter
  const filteredEvents = useMemo(() => {
    if (filter === 'all') return events;
    return events.filter((e) => e.actor.toLowerCase().includes(filter.toLowerCase()));
  }, [events, filter]);

  // Handle scroll for virtualisation
  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  };

  const containerHeight = 400; // Fixed window height
  const totalCount = filteredEvents.length;
  const totalHeight = totalCount * ROW_HEIGHT;

  // Calculate visible window
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(totalCount, Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + OVERSCAN);

  const visibleEvents = useMemo(() => {
    return filteredEvents.slice(startIndex, endIndex).map((event, i) => ({
      event,
      index: startIndex + i,
    }));
  }, [filteredEvents, startIndex, endIndex]);

  // Auto-scroll to top when new events arrive if user is at the top
  const prevCountRef = useRef(events.length);
  useEffect(() => {
    if (events.length > prevCountRef.current && containerRef.current && scrollTop < 60) {
      containerRef.current.scrollTop = 0;
    }
    prevCountRef.current = events.length;
  }, [events.length, scrollTop]);

  // Actor color tokens
  const getActorBadge = (actor: string) => {
    const act = actor.toLowerCase();
    if (act.includes('red')) return 'border-am/50 bg-am/10 text-am';
    if (act.includes('blue')) return 'border-bl/50 bg-bl/10 text-bl';
    if (act.includes('broker')) return 'border-cy/50 bg-cy/10 text-cy';
    if (act.includes('witness')) return 'border-ok/50 bg-ok/10 text-ok';
    if (act.includes('target')) return 'border-dim bg-s2 text-tx';
    if (act.includes('scorer')) return 'border-dim bg-s2 text-mut';
    return 'border-bd bg-s2 text-mut';
  };

  return (
    <Panel
      label="04 — LIVE CHAINED AUDIT LOG"
      meta={
        <div className="flex items-center gap-3">
          {/* Stream Status indicator */}
          <div className="flex items-center gap-1.5 font-mono text-xs">
            <span
              className={cn(
                'w-2 h-2 rounded-full',
                streamStatus === 'CONNECTED' && 'bg-ok animate-pulse',
                streamStatus === 'RECONNECTING' && 'bg-am animate-ping',
                streamStatus === 'LAGGING' && 'bg-am',
                streamStatus === 'CLOSED' && 'bg-dim'
              )}
            />
            <span
              className={cn(
                'text-[11px] uppercase tracking-wider',
                streamStatus === 'CONNECTED' && 'text-ok',
                streamStatus === 'RECONNECTING' && 'text-am font-bold',
                streamStatus === 'LAGGING' && 'text-am',
                streamStatus === 'CLOSED' && 'text-mut'
              )}
            >
              {streamStatus}
            </span>
          </div>

          <span className="font-mono text-xs text-mut">
            {filteredEvents.length} EVENTS (VIRTUALISED)
          </span>
        </div>
      }
      className={cn('h-full flex flex-col', className)}
    >
      <div className="flex flex-col h-full space-y-2">
        {/* Filter Controls Row */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-bd/60 pb-2">
          <div className="flex items-center gap-1 font-mono text-xs" role="group" aria-label="Actor Filters">
            <Filter className="w-3.5 h-3.5 text-mut mr-1" />
            {(['all', 'red', 'broker', 'blue', 'target', 'scorer', 'recorder', 'witness'] as ActorFilter[]).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFilter(f)}
                className={cn(
                  'px-2 py-0.5 uppercase tracking-wider text-[11px] border rounded-sm transition-colors',
                  'focus:outline-none focus-visible:ring-1 focus-visible:ring-cy',
                  filter === f
                    ? 'border-cy bg-cy/20 text-cy font-bold'
                    : 'border-bd bg-s2/60 text-mut hover:text-tx hover:border-bd-strong'
                )}
              >
                {f}
              </button>
            ))}
          </div>

          <span className="text-[10px] text-mut font-mono">60 FPS WINDOWED</span>
        </div>

        {/* Reconnecting Alert Banner */}
        {streamStatus === 'RECONNECTING' && (
          <div
            role="alert"
            className="p-2 border border-am bg-am/15 text-am font-mono text-xs flex items-center justify-between"
          >
            <div className="flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>RECONNECTING TO SSE STREAM (RECONCILING BY SEQUENCE)...</span>
            </div>
            <span className="text-[10px] uppercase">AUTO-RETRYING</span>
          </div>
        )}

        {/* Audit Unavailable Error Alert */}
        {error && (
          <div
            role="alert"
            className="p-2 border border-bad bg-bad/15 text-bad font-mono text-xs flex items-center gap-2"
          >
            <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
            <span>STREAM ERROR: {error.message}</span>
          </div>
        )}

        {/* Virtualized Event List Container */}
        <div
          ref={containerRef}
          onScroll={handleScroll}
          className="relative overflow-y-auto border border-bd/60 bg-s1 rounded divide-y divide-bd/30 font-mono text-xs"
          style={{ height: `${containerHeight}px` }}
          role="region"
          aria-label="Virtualized Audit Events Feed"
          tabIndex={0}
        >
          {filteredEvents.length === 0 ? (
            <div className="flex items-center justify-center h-full text-dim p-6">
              No audit events recorded for current filter.
            </div>
          ) : (
            <div style={{ height: `${totalHeight}px`, position: 'relative' }}>
              <div
                style={{
                  transform: `translateY(${startIndex * ROW_HEIGHT}px)`,
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  right: 0,
                }}
              >
                <AnimatePresence initial={false}>
                  {visibleEvents.map(({ event }) => {
                    const isInvalidOutcome =
                      event.outcome === 'INVALID' ||
                      event.outcome === 'DEADLINE_EXCEEDED' ||
                      event.outcome === 'AUDIT_UNAVAILABLE';

                    return (
                      <motion.div
                        key={`${event.experiment}-${event.seq}-${event.ts_utc}`}
                        layout
                        initial={{ opacity: 0, x: -6 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        className={cn(
                          'flex items-center justify-between gap-3 px-3 py-2 border-b border-bd/20 hover:bg-s2/50 transition-colors',
                          isInvalidOutcome && 'bg-inv/10 border-l-2 border-l-inv'
                        )}
                        style={{ height: `${ROW_HEIGHT}px` }}
                      >
                        {/* Left: Seq + Timestamp + Actor + Action */}
                        <div className="flex items-center gap-2 min-w-0">
                          {/* Sequence Badge */}
                          <span className="font-bold text-tx text-[11px] tabular-nums shrink-0">
                            #{event.seq.toString().padStart(4, '0')}
                          </span>

                          {/* Time */}
                          <span className="text-mut text-[10px] tabular-nums shrink-0">
                            {event.ts_utc.slice(11, 19)}
                          </span>

                          {/* Actor */}
                          <span
                            className={cn(
                              'px-1.5 py-0.2 text-[10px] font-bold uppercase tracking-wider border rounded-sm shrink-0',
                              getActorBadge(event.actor)
                            )}
                          >
                            <UntrustedText text={event.actor} />
                          </span>

                          {/* Action (UntrustedText: Invariant 4) */}
                          <span className="text-tx text-xs truncate">
                            <UntrustedText text={event.action} />
                          </span>
                        </div>

                        {/* Right: Prev Hash Link + Outcome */}
                        <div className="flex items-center gap-2 shrink-0">
                          {/* Prev Digest Link */}
                          <div className="hidden sm:flex items-center gap-1 text-[11px] text-dim" title={`Chained to prev: ${event.prev}`}>
                            <Link2 className="w-3 h-3 text-mut" />
                            {event.prev === 'genesis' ? (
                              <span className="text-cy text-[10px]">GENESIS</span>
                            ) : (
                              <Digest hash={event.prev} prefixLen={6} suffixLen={4} />
                            )}
                          </div>

                          {/* Outcome badge */}
                          <span
                            className={cn(
                              'px-2 py-0.5 text-[10px] uppercase font-bold tracking-wider border rounded-sm',
                              isInvalidOutcome
                                ? 'border-inv bg-inv/20 text-inv'
                                : event.outcome === 'ok' || event.outcome === 'SYNCED' || event.outcome === 'VALID_WITHIN_PROFILE'
                                  ? 'border-ok/40 bg-ok/10 text-ok'
                                  : 'border-bd bg-s2 text-tx'
                            )}
                          >
                            <UntrustedText text={event.outcome} />
                          </span>
                        </div>
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
              </div>
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
};
