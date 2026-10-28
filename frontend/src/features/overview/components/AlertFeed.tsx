import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Panel } from '../../../components/Panel';
import { Digest } from '../../../components/Digest';
import { DelayedTag } from '../../../components/DelayedTag';
import { UntrustedText } from '../../../components/UntrustedText';
import type { IntegrityAlert } from '../types';
import type { Role } from '../../../lib/schemas';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Wifi,
  WifiOff,
} from 'lucide-react';

interface AlertFeedProps {
  alerts: IntegrityAlert[];
  streamStatus: 'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING';
  isStale: boolean;
  lastUpdatedAgeSec: number;
  role: Role;
}

export const AlertFeed: React.FC<AlertFeedProps> = ({
  alerts,
  streamStatus,
  isStale,
  lastUpdatedAgeSec,
  role,
}) => {
  const isNonOperator = role !== 'operator';

  return (
    <Panel
      label="02 — INTEGRITY ALERTS"
      meta={
        <div className="flex items-center gap-2.5">
          {isNonOperator && <DelayedTag delay="T-30s" />}

          {/* SSE Stream status indicator */}
          {streamStatus === 'CONNECTED' && !isStale && (
            <span className="flex items-center gap-1.5 text-xs font-mono text-ok">
              <span className="w-2 h-2 rounded-full bg-ok animate-pulse" />
              <span>LIVE SSE</span>
            </span>
          )}

          {streamStatus === 'CONNECTED' && isStale && (
            <span
              className="flex items-center gap-1.5 text-xs font-mono text-am font-bold bg-am/10 border border-am px-1.5 py-0.5 rounded-[2px]"
              title={`No stream events received in ${lastUpdatedAgeSec}s`}
            >
              <Activity className="w-3 h-3 text-am animate-bounce" />
              <span>STALE ({lastUpdatedAgeSec}s)</span>
            </span>
          )}

          {streamStatus === 'RECONNECTING' && (
            <span className="flex items-center gap-1.5 text-xs font-mono text-am bg-am/10 border border-am px-1.5 py-0.5 rounded-[2px] animate-pulse">
              <WifiOff className="w-3 h-3 text-am" />
              <span>RECONNECTING...</span>
            </span>
          )}

          {streamStatus === 'LAGGING' && (
            <span className="flex items-center gap-1.5 text-xs font-mono text-am">
              <Wifi className="w-3 h-3 text-am" />
              <span>LAGGING</span>
            </span>
          )}

          {streamStatus === 'CLOSED' && (
            <span className="flex items-center gap-1.5 text-xs font-mono text-mut">
              <WifiOff className="w-3 h-3 text-mut" />
              <span>DISCONNECTED</span>
            </span>
          )}
        </div>
      }
      className="h-full flex flex-col justify-between"
    >
      <div className="py-1 flex-1 flex flex-col">
        {/* Reconnecting banner if SSE was interrupted */}
        {streamStatus === 'RECONNECTING' && (
          <div className="mb-3 p-2 bg-am/10 border border-am text-am font-mono text-xs rounded-[2px] flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-am" />
            <span>SSE stream interrupted. Resubscribing to witness gateway with exponential backoff...</span>
          </div>
        )}

        {/* Scrollable feed list */}
        <div
          role="region"
          aria-label="Real-time integrity alert stream"
          className="space-y-3 max-h-[500px] overflow-y-auto pr-1 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
          tabIndex={0}
        >
          {alerts.length === 0 ? (
            <div className="p-8 text-center font-mono text-xs text-mut border border-dashed border-bd rounded-[2px]">
              No alerts recorded in current session.
            </div>
          ) : (
            <AnimatePresence initial={false}>
              {alerts.map((alert) => {
                const isCritical = alert.severity === 'CRITICAL';
                const isWarning = alert.severity === 'WARNING';

                let borderTone = 'border-bd hover:border-bd-strong';
                let icon = <ShieldCheck className="w-4 h-4 text-cy shrink-0" />;
                let badgeClass = 'text-cy bg-cy/10 border-cy/40';

                if (isCritical) {
                  borderTone = 'border-inv/80 bg-inv/5';
                  icon = <AlertTriangle className="w-4 h-4 text-inv shrink-0" />;
                  badgeClass = 'text-inv bg-inv/10 border-inv font-bold';
                } else if (isWarning) {
                  borderTone = 'border-am/70 bg-am/5';
                  icon = <ShieldAlert className="w-4 h-4 text-am shrink-0" />;
                  badgeClass = 'text-am bg-am/10 border-am';
                }

                const timeStr = new Date(alert.timestamp_utc).toTimeString().split(' ')[0];

                return (
                  <motion.article
                    key={alert.id}
                    layout
                    initial={{ opacity: 1, y: -12 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.2, ease: 'easeOut' }}
                    className={`p-3 bg-s2/70 border rounded-[2px] transition-colors ${borderTone}`}
                  >
                    {/* Alert Header */}
                    <div className="flex items-center justify-between gap-2 text-xs font-mono mb-1.5">
                      <div className="flex items-center gap-2">
                        {icon}
                        <span className="text-tx font-bold tracking-wider">{alert.arena_id}</span>
                        <span className="text-mut" aria-hidden="true">·</span>
                        <span className="text-mut">{timeStr} UTC</span>
                      </div>
                      <span className={`px-1.5 py-0.5 text-[10px] uppercase font-mono rounded-[2px] border ${badgeClass}`}>
                        {alert.severity}
                      </span>
                    </div>

                    {/* Alert Title */}
                    <div className="font-sans font-medium text-xs text-tx leading-snug">
                      {alert.title}
                    </div>

                    {/* Alert Detail as Untrusted Data Sink */}
                    <div className="mt-2">
                      <UntrustedText
                        text={alert.detail}
                        label={`ALERT PAYLOAD [${alert.action}]`}
                        maxLines={2}
                      />
                    </div>

                    {/* Digest footer */}
                    {alert.digest && (
                      <div className="mt-2 pt-2 border-t border-bd/50 flex items-center justify-between text-[11px] font-mono">
                        <span className="text-mut uppercase">COMMITMENT:</span>
                        <Digest hash={alert.digest} prefixLen={8} suffixLen={6} />
                      </div>
                    )}
                  </motion.article>
                );
              })}
            </AnimatePresence>
          )}
        </div>
      </div>
    </Panel>
  );
};
