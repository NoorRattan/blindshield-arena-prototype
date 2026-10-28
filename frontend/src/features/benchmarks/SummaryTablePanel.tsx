import React from 'react';
import { Panel } from '../../components/Panel';
import { IllustrativeTag } from '../../components/IllustrativeTag';
import type { SummaryTable } from './benchmarkSchemas';

const REASON_LABEL: Record<string, string> = {
  DEADLINE_EXCEEDED: 'Defense deadline exceeded',
  RECORDER_DOWN: 'Recorder unavailable',
  STALE_EPOCH: 'Stale epoch submitted',
  WITNESS_LAG: 'Witness lag / SLA breach',
  SCHEMA_VIOLATION: 'Schema violation',
  OTHER: 'Other / unclassified',
};

export interface SummaryTablePanelProps {
  summary: SummaryTable;
  illustrative: boolean;
}

export const SummaryTablePanel: React.FC<SummaryTablePanelProps> = ({
  summary,
  illustrative,
}) => {
  const integrityRate =
    summary.n_admitted > 0
      ? ((summary.n_valid / summary.n_admitted) * 100).toFixed(1)
      : '—';

  const invalidReasonEntries = Object.entries(summary.invalid_by_reason).filter(
    ([, count]) => count > 0
  );

  return (
    <Panel
      label="05 — TRIAL SUMMARY"
      meta={
        <span className="flex items-center gap-2">
          <span>ADMITTED · VALID · INVALID BY REASON · DENY-ALL SCORE</span>
          {illustrative && <IllustrativeTag />}
        </span>
      }
    >
      <div className="space-y-5">
        {/* Top metric strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-0 border border-bd rounded divide-x divide-bd overflow-hidden">
          {[
            { label: 'Admitted', value: String(summary.n_admitted), color: 'text-tx' },
            {
              label: 'Valid',
              value: `${summary.n_valid} / ${summary.n_admitted}`,
              color: 'text-bl',
            },
            {
              label: 'Invalid',
              value: `${summary.n_invalid} / ${summary.n_admitted}`,
              color: summary.n_invalid > 0 ? 'text-inv' : 'text-mut',
            },
            {
              label: 'Integrity Rate',
              value: summary.n_admitted > 0 ? `${integrityRate}%` : '—',
              color: 'text-cy',
            },
          ].map((tile) => (
            <div key={tile.label} className="flex flex-col items-center justify-center p-4 gap-1 bg-s1">
              <p className={`font-mono text-xl tabular-nums font-medium ${tile.color}`}>
                {tile.value}
              </p>
              <p className="font-mono text-[11px] text-mut uppercase tracking-wider">
                {tile.label}
              </p>
            </div>
          ))}
        </div>

        {/* Invalid by reason */}
        {summary.n_invalid > 0 && (
          <div
            role="region"
            tabIndex={0}
            aria-label="Invalid trial count by reason"
            className="overflow-x-auto border border-bd rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
          >
            <table className="w-full font-mono text-xs text-left border-collapse">
              <caption className="sr-only">Count of invalid trials by reason category</caption>
              <thead>
                <tr className="border-b border-bd bg-s2/80 text-mut uppercase text-[11px] tracking-wider">
                  <th scope="col" className="p-2.5 font-medium">Invalidation Reason</th>
                  <th scope="col" className="p-2.5 font-medium text-right">Count</th>
                  <th scope="col" className="p-2.5 font-medium text-right">% of Invalid</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-bd">
                {invalidReasonEntries.map(([reason, count]) => (
                  <tr key={reason} className="hover:bg-s2/20 transition-colors">
                    <td className="p-2.5 text-tx">{REASON_LABEL[reason] ?? reason}</td>
                    <td className="p-2.5 text-right tabular-nums text-inv">{count}</td>
                    <td className="p-2.5 text-right tabular-nums text-mut">
                      {summary.n_invalid > 0
                        ? `${((count / summary.n_invalid) * 100).toFixed(1)}%`
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Deny-all score */}
        <div className="flex flex-wrap items-start gap-4 border border-bd bg-s2/20 px-4 py-3 rounded">
          <div className="flex-1 min-w-0">
            <p className="font-mono text-[11px] text-mut uppercase tracking-wider mb-1">
              Deny-All Baseline Score (usefulness floor)
            </p>
            <p className="font-mono text-sm text-tx leading-relaxed">
              A defense that blocks <em>every</em> request achieves 0% attack success rate but
              also 0% usefulness. This baseline must be visible to contextualise defended rates.
            </p>
          </div>
          <div className="flex flex-col items-end gap-1 shrink-0">
            <p className="font-display text-3xl text-mut tabular-nums">
              {summary.deny_all_score !== null
                ? `${(summary.deny_all_score * 100).toFixed(0)}%`
                : 'INSUFFICIENT DATA'}
            </p>
            <p className="font-mono text-[11px] text-mut">usefulness</p>
          </div>
        </div>
      </div>
    </Panel>
  );
};
