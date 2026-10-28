import React, { useId } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  ErrorBar,
  ReferenceLine,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { Panel } from '../../components/Panel';
import { IllustrativeTag } from '../../components/IllustrativeTag';
import type { AttackRateRow } from './benchmarkSchemas';

// ── Label map ────────────────────────────────────────────────────────────────
const FAMILY_LABEL: Record<string, string> = {
  PROMPT_INJECTION: 'Prompt Injection',
  JAILBREAK: 'Jailbreak',
  ROLE_ESCALATION: 'Role Escalation',
  DENY_ALL_BASELINE: 'Deny-All Baseline',
};

// ── Custom tooltip (no default Recharts tooltip) ──────────────────────────────
interface TooltipPayload {
  payload?: AttackRateRow & { errorY?: [number, number] };
}

function AttackTooltip({ active, payload }: { active?: boolean; payload?: TooltipPayload[] }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  if (!d) return null;
  return (
    <div className="bg-s1 border border-bd px-3 py-2 font-mono text-[11px] text-tx space-y-0.5 max-w-[220px]">
      <p className="font-medium text-cy uppercase tracking-wider">
        {FAMILY_LABEL[d.family] ?? d.family}
      </p>
      <p>n total: <span className="text-tx">{d.n_total}</span></p>
      <p>blocked: <span className="text-bl">{d.n_blocked}</span></p>
      <p>invalid: <span className="text-inv">{d.n_invalid}</span></p>
      <p>passed: <span className="text-tx">{d.n_passed}</span></p>
      <p>defended rate: <span className="text-cy">{(d.defended_success_rate * 100).toFixed(1)}%</span></p>
      <p>raw (no defense): <span className="text-am">{(d.raw_success_rate * 100).toFixed(1)}%</span></p>
      <p className="text-mut">95% CI: [{(d.ci_lo * 100).toFixed(1)}, {(d.ci_hi * 100).toFixed(1)}]%</p>
    </div>
  );
}

// ── Bar fill by family ────────────────────────────────────────────────────────
function barFill(family: string): string {
  if (family === 'DENY_ALL_BASELINE') return 'var(--color-mut)';
  return 'var(--color-cy)';
}

// ── Chart data shape ──────────────────────────────────────────────────────────
interface ChartRow extends AttackRateRow {
  label: string;
  /** Error bar half-width: (ci_hi - ci_lo) / 2 */
  errorHalf: number;
  rawPct: number;
  defendedPct: number;
}

function toChartRows(rows: AttackRateRow[]): ChartRow[] {
  return rows.map((r) => ({
    ...r,
    label: FAMILY_LABEL[r.family] ?? r.family,
    errorHalf: (r.ci_hi - r.ci_lo) / 2,
    rawPct: r.raw_success_rate * 100,
    defendedPct: r.defended_success_rate * 100,
  }));
}

// ── Count table ───────────────────────────────────────────────────────────────
function CountTable({ rows }: { rows: AttackRateRow[] }) {
  return (
    <div
      role="region"
      tabIndex={0}
      aria-label="Attack success rate counts and confidence intervals"
      className="overflow-x-auto border border-bd rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
    >
      <table className="w-full font-mono text-xs text-left border-collapse min-w-[520px]">
        <caption className="sr-only">Attack success rate data table with counts and Wilson 95% confidence intervals</caption>
        <thead>
          <tr className="border-b border-bd bg-s2/80 text-mut uppercase text-[11px] tracking-wider">
            <th scope="col" className="p-2.5 font-medium">Attack Family</th>
            <th scope="col" className="p-2.5 font-medium text-right">n Total</th>
            <th scope="col" className="p-2.5 font-medium text-right">Blocked</th>
            <th scope="col" className="p-2.5 font-medium text-right">Invalid</th>
            <th scope="col" className="p-2.5 font-medium text-right">Raw %</th>
            <th scope="col" className="p-2.5 font-medium text-right">Defended %</th>
            <th scope="col" className="p-2.5 font-medium text-right">95% CI</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-bd">
          {rows.map((row) => (
            <tr
              key={row.family}
              className={
                row.family === 'DENY_ALL_BASELINE'
                  ? 'bg-s2/30 text-mut'
                  : 'hover:bg-s2/20 transition-colors'
              }
            >
              <td className="p-2.5 font-medium text-tx whitespace-nowrap">
                {row.family === 'DENY_ALL_BASELINE' ? (
                  <span className="flex items-center gap-1.5">
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-mut shrink-0" aria-hidden="true" />
                    {FAMILY_LABEL[row.family]}
                  </span>
                ) : (
                  FAMILY_LABEL[row.family] ?? row.family
                )}
              </td>
              <td className="p-2.5 text-right tabular-nums">{row.n_total}</td>
              <td className="p-2.5 text-right tabular-nums text-bl">{row.n_blocked}</td>
              <td className="p-2.5 text-right tabular-nums text-inv">{row.n_invalid}</td>
              <td className="p-2.5 text-right tabular-nums text-am">
                {(row.raw_success_rate * 100).toFixed(1)}%
              </td>
              <td className="p-2.5 text-right tabular-nums text-cy">
                {row.n_passed === 0 ? '—' : `${(row.defended_success_rate * 100).toFixed(1)}%`}
              </td>
              <td className="p-2.5 text-right tabular-nums text-mut text-[11px]">
                {row.n_passed === 0
                  ? '—'
                  : `[${(row.ci_lo * 100).toFixed(1)}, ${(row.ci_hi * 100).toFixed(1)}]`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export interface AttackSuccessRatePanelProps {
  rows: AttackRateRow[];
  illustrative: boolean;
}

export const AttackSuccessRatePanel: React.FC<AttackSuccessRatePanelProps> = ({
  rows,
  illustrative,
}) => {
  const chartId = useId();

  if (rows.length === 0) {
    return (
      <Panel label="01 — ATTACK SUCCESS RATE" meta="n · CI · BLOCKED · INVALID">
        <p className="font-mono text-xs text-mut py-8 text-center">INSUFFICIENT DATA</p>
      </Panel>
    );
  }

  const chartRows = toChartRows(rows);

  return (
    <Panel
      label="01 — ATTACK SUCCESS RATE"
      meta={
        <span className="flex items-center gap-2">
          <span>n · 95% CI · BLOCKED &amp; INVALID REPORTED SEPARATELY</span>
          {illustrative && <IllustrativeTag />}
        </span>
      }
    >
      <div className="space-y-5">
        {/* Legend */}
        <div className="flex flex-wrap items-center gap-4 font-mono text-[11px] text-mut">
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-2 bg-cy" aria-hidden="true" />
            Defended
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-2 bg-am" aria-hidden="true" />
            Raw (no defense)
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-2 bg-mut" aria-hidden="true" />
            Deny-All Baseline (0% usefulness)
          </span>
        </div>

        {/* Chart */}
        <div
          className="overflow-x-auto"
          role="region"
          tabIndex={0}
          aria-label="Attack success rate bar chart"
          aria-describedby={`${chartId}-desc`}
        >
          <p id={`${chartId}-title`} className="sr-only">Attack success rate bar chart</p>
          <p id={`${chartId}-desc`} className="sr-only">
            Compares defended success rate vs raw success rate per attack family.
            Error bars show Wilson 95% CI. See the table below for exact values.
          </p>
          <div className="min-w-[400px]">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart
                data={chartRows}
                barCategoryGap="28%"
                barGap={4}
                margin={{ top: 8, right: 12, left: 0, bottom: 4 }}
              >
                <XAxis
                  dataKey="label"
                  tick={{ fontFamily: 'DM Mono, monospace', fontSize: 10, fill: 'var(--color-mut)' }}
                  axisLine={{ stroke: 'var(--color-bd)' }}
                  tickLine={false}
                />
                <YAxis
                  tickFormatter={(v: number) => `${(v).toFixed(0)}%`}
                  tick={{ fontFamily: 'DM Mono, monospace', fontSize: 10, fill: 'var(--color-mut)' }}
                  axisLine={false}
                  tickLine={false}
                  domain={[0, 100]}
                  width={36}
                />
                <ReferenceLine y={0} stroke="var(--color-bd)" strokeWidth={1} />
                <Tooltip
                  content={<AttackTooltip />}
                  cursor={{ fill: 'var(--color-s2)', opacity: 0.4 }}
                />
                {/* Raw (amber) */}
                <Bar dataKey="rawPct" name="Raw" fill="var(--color-am)" opacity={0.45} isAnimationActive={false} />
                {/* Defended (cyan) with error bars */}
                <Bar dataKey="defendedPct" name="Defended" isAnimationActive={false}>
                  {chartRows.map((row) => (
                    <Cell key={row.family} fill={barFill(row.family)} />
                  ))}
                  <ErrorBar dataKey="errorHalf" width={4} stroke="var(--color-cy)" strokeWidth={1.5} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Count table — text summary required for accessibility */}
        <CountTable rows={rows} />
      </div>
    </Panel>
  );
};
