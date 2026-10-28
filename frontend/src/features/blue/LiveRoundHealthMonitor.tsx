import React from 'react';
import { Clock, ShieldAlert, Activity } from 'lucide-react';
import { Panel } from '../../components/Panel';
import { StatusPill } from '../../components/StatusPill';
import { EmbargoMask } from '../../components/EmbargoMask';
import { DelayedTag } from '../../components/DelayedTag';
import type { FeedbackItem } from '../../lib/schemas';

interface LiveRoundHealthMonitorProps {
  feedback: FeedbackItem[];
  isLoading?: boolean;
  isActiveRound?: boolean;
  experimentId: string;
}

export const LiveRoundHealthMonitor: React.FC<LiveRoundHealthMonitorProps> = ({
  feedback,
  isLoading = false,
  isActiveRound = true,
}) => {
  return (
    <Panel
      label="02 — LIVE ROUND HEALTH MONITOR"
      meta={isActiveRound ? "STATIC EMBARGOED PROJECTION (EmbargoedView)" : "SANITIZED TELEMETRY STREAM"}
      className="p-5"
    >
      <div className="space-y-5">
        {/* Policy Notice Box */}
        <div
          role="region"
          aria-label="Security Isolation Notice"
          className="border border-bd bg-s2 p-4 text-xs font-mono space-y-2"
        >
          <div className="flex items-center justify-between gap-2 text-bl font-semibold">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 shrink-0" />
              <span className="uppercase tracking-wider">
                SECURITY POLICY // SPEC CORRECTION C-02 &amp; FE-D-003
              </span>
            </div>
            {isActiveRound && (
              <span className="border border-emb/40 bg-emb/10 px-2 py-0.5 text-emb font-mono text-[10px] uppercase">
                STATUS: EMBARGOED
              </span>
            )}
          </div>
          <p className="text-tx text-[11px] leading-relaxed">
            In-flight attack payloads, defense classification decisions (Allow/Block), confidence scores, and rule match identifiers are strictly withheld from blue defenders during active evaluation rounds. Latency is delayed by ~30s and bucketed to coarse ~50ms windows to bound side-channel leakage.
          </p>
        </div>

        {/* Aggregate Metrics Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="border border-bd bg-s2 p-3.5 space-y-1">
            <div className="flex items-center justify-between text-mut text-[11px] font-mono uppercase tracking-wider">
              <span>Total Processed</span>
              <Activity className="h-3.5 w-3.5" />
            </div>
            <div className="font-mono text-xl font-bold text-tx">
              {isLoading ? '...' : feedback.length}
            </div>
            <div className="font-mono text-[10px] text-mut">
              Aggregate turns received
            </div>
          </div>

          <div className="border border-bd bg-s2 p-3.5 space-y-1">
            <div className="flex items-center justify-between text-mut text-[11px] font-mono uppercase tracking-wider">
              <span>Telemetry Feed</span>
              <Clock className="h-3.5 w-3.5 text-mut" />
            </div>
            <div className="pt-1">
              <DelayedTag delay="T-30s" />
            </div>
            <div className="font-mono text-[10px] text-mut">
              Coarse 50ms bucketed
            </div>
          </div>

          <div className="border border-bd bg-s2 p-3.5 space-y-1">
            <div className="text-mut text-[11px] font-mono uppercase tracking-wider">
              Round Status
            </div>
            <div className="pt-0.5">
              <StatusPill
                status={isActiveRound ? 'VALID_WITHIN_PROFILE' : 'SCORED'}
                label={isActiveRound ? 'ACTIVE EVALUATION' : 'ROUND CONCLUDED'}
              />
            </div>
            <div className="font-mono text-[10px] text-mut">
              Inference state isolated
            </div>
          </div>

          <div className="border border-bd bg-s2 p-3.5 space-y-1">
            <div className="text-mut text-[11px] font-mono uppercase tracking-wider">
              Allow / Block Split
            </div>
            <div className="pt-0.5">
              <span className="border border-emb/40 bg-emb/10 px-2 py-0.5 font-mono text-[11px] text-emb">
                WITHHELD (C-02)
              </span>
            </div>
            <div className="font-mono text-[10px] text-mut">
              Unlocks post-release
            </div>
          </div>
        </div>

        {/* Live Sanitized Turns Table */}
        <div
          role="region"
          aria-label="Sanitized Live Turns Table"
          tabIndex={0}
          className="border border-bd bg-s1 overflow-x-auto focus:outline-none focus:ring-1 focus:ring-cy"
        >
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-bd bg-s2 text-mut text-[11px] uppercase tracking-wider">
                <th scope="col" className="px-4 py-3 font-medium">Turn ID</th>
                <th scope="col" className="px-4 py-3 font-medium">Execution Status</th>
                <th scope="col" className="px-4 py-3 font-medium">Defense Latency</th>
                <th scope="col" className="px-4 py-3 font-medium">Emitted Decision</th>
                <th scope="col" className="px-4 py-3 font-medium">Payload Content</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bd">
              {isLoading ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-mut text-xs">
                    Loading sanitized telemetry stream...
                  </td>
                </tr>
              ) : feedback.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-mut text-xs">
                    No traffic observed yet in this round. Awaiting red probes.
                  </td>
                </tr>
              ) : (
                feedback.map((item) => {
                  const turnFormatted = `Turn ${String(item.turn).padStart(2, '0')}`;
                  const latencyDisplay = item.latency_bucket_ms !== undefined
                    ? `~${item.latency_bucket_ms} ms (bucketed)`
                    : item.latency_ms
                    ? `${item.latency_ms.defense} ms`
                    : '—';

                  return (
                    <tr
                      key={item.request_id}
                      className="hover:bg-s2/40 transition-colors"
                    >
                      <td className="px-4 py-3 font-semibold text-tx">
                        {turnFormatted}
                      </td>
                      <td className="px-4 py-3">
                        <StatusPill
                          status={item.integrity ?? 'VALID_WITHIN_PROFILE'}
                          label="EXECUTED"
                        />
                      </td>
                      <td className="px-4 py-3 text-tx">
                        <span className="flex items-center gap-2">
                          {latencyDisplay}
                          <span className="text-[10px] text-mut font-normal">
                            [T-30s]
                          </span>
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <EmbargoMask
                          label="DECISION EMBARGOED"
                          reason="Allow/Block split withheld until epoch close (C-02)"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <EmbargoMask
                          label="PAYLOAD MASKED"
                          reason="In-flight attack payload masked from blue defenders"
                        />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Panel>
  );
};
