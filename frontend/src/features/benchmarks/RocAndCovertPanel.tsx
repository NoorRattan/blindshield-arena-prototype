import React, { useId } from 'react';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ErrorBar,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { Panel } from '../../components/Panel';
import { IllustrativeTag } from '../../components/IllustrativeTag';
import { StatusPill } from '../../components/StatusPill';
import type { CovertChannelCard, RocArm } from './benchmarkSchemas';

// ── Arm label ─────────────────────────────────────────────────────────────────
const ARM_LABEL: Record<string, string> = {
  cache_off: 'Cache Off',
  salted_shared: 'Salted Shared',
  dedicated: 'Dedicated',
};

// ── ROC tooltip ───────────────────────────────────────────────────────────────
interface RocTooltipProps {
  active?: boolean;
  payload?: { payload?: RocArm & { errorY?: [number, number]; armIdx: number } }[];
}

function RocTooltip({ active, payload }: RocTooltipProps) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  if (!d) return null;
  return (
    <div className="bg-s1 border border-bd px-3 py-2 font-mono text-[11px] text-tx space-y-0.5">
      <p className="font-medium text-cy uppercase tracking-wider">{ARM_LABEL[d.arm] ?? d.arm}</p>
      <p>AUC: <span className="text-tx">{d.auc.toFixed(3)}</span></p>
      <p>95% CI: <span className="text-mut">[{d.ci_lo.toFixed(3)}, {d.ci_hi.toFixed(3)}]</span></p>
      <p>n: <span className="text-tx">{d.n_samples}</span></p>
      {d.inconclusive && (
        <p className="text-inv">INCONCLUSIVE (weak baseline)</p>
      )}
    </div>
  );
}

// ── ROC data table ────────────────────────────────────────────────────────────
function RocTable({ arms }: { arms: RocArm[] }) {
  return (
    <div
      role="region"
      tabIndex={0}
      aria-label="Cache distinguishability ROC AUC measurements"
      className="overflow-x-auto border border-bd rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
    >
      <table className="w-full font-mono text-xs text-left border-collapse min-w-[440px]">
        <caption className="sr-only">ROC AUC per cache arm with 95% CI. Gate: AUC in [0.4, 0.6] implies no distinguishable signal.</caption>
        <thead>
          <tr className="border-b border-bd bg-s2/80 text-mut uppercase text-[11px] tracking-wider">
            <th scope="col" className="p-2.5 font-medium">Arm</th>
            <th scope="col" className="p-2.5 font-medium text-right">AUC</th>
            <th scope="col" className="p-2.5 font-medium text-right">95% CI</th>
            <th scope="col" className="p-2.5 font-medium text-right">n</th>
            <th scope="col" className="p-2.5 font-medium text-right">Signal</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-bd">
          {arms.map((arm) => (
            <tr key={arm.arm} className="hover:bg-s2/20 transition-colors">
              <td className="p-2.5 text-tx font-medium">{ARM_LABEL[arm.arm] ?? arm.arm}</td>
              <td className="p-2.5 text-right tabular-nums text-tx">{arm.auc.toFixed(3)}</td>
              <td className="p-2.5 text-right tabular-nums text-mut">
                [{arm.ci_lo.toFixed(3)}, {arm.ci_hi.toFixed(3)}]
              </td>
              <td className="p-2.5 text-right tabular-nums text-mut">{arm.n_samples}</td>
              <td className="p-2.5 text-right">
                {arm.inconclusive ? (
                  <span className="text-inv font-mono text-[11px]">INCONCLUSIVE</span>
                ) : (
                  <span className="text-bl font-mono text-[11px]">WITHIN GATE</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── ROC panel ─────────────────────────────────────────────────────────────────
export interface RocPanelProps {
  arms: RocArm[];
  illustrative: boolean;
}

export const RocPanel: React.FC<RocPanelProps> = ({ arms, illustrative }) => {
  const chartId = useId();

  if (arms.length === 0) {
    return (
      <Panel label="03 — CACHE DISTINGUISHABILITY · ROC AUC" meta="GATE [0.4, 0.6]">
        <p className="font-mono text-xs text-mut py-8 text-center">INSUFFICIENT DATA</p>
      </Panel>
    );
  }

  // Scatter data: x = arm index (1-based), y = AUC, error = CI half-width
  const scatterData = arms.map((arm, i) => ({
    ...arm,
    armIdx: i + 1,
    errorHalf: (arm.ci_hi - arm.ci_lo) / 2,
  }));

  return (
    <Panel
      label="03 — CACHE DISTINGUISHABILITY · ROC AUC per ARM"
      meta={
        <span className="flex items-center gap-2">
          <span>CANDIDATE GATE [0.4, 0.6] · INCONCLUSIVE IF WEAK BASELINE SHOWS NO SIGNAL</span>
          {illustrative && <IllustrativeTag />}
        </span>
      }
    >
      <div className="space-y-5">
        <div
          className="overflow-x-auto"
          role="region"
          tabIndex={0}
          aria-label="Cache distinguishability ROC AUC scatter plot"
          aria-describedby={`${chartId}-roc-desc`}
        >
          <p id={`${chartId}-roc-title`} className="sr-only">Cache distinguishability ROC AUC scatter plot</p>
          <p id={`${chartId}-roc-desc`} className="sr-only">
            Each point shows the measured AUC for a cache arm with 95% CI error bars.
            An AUC within [0.4, 0.6] indicates no distinguishable cache signal.
            See the table below for exact values.
          </p>
          <div className="min-w-[360px]">
            <ResponsiveContainer width="100%" height={180}>
              <ScatterChart margin={{ top: 12, right: 24, left: 0, bottom: 4 }}>
                <XAxis
                  type="number"
                  dataKey="armIdx"
                  domain={[0, arms.length + 1]}
                  ticks={scatterData.map((d) => d.armIdx)}
                  tickFormatter={(v: number) => ARM_LABEL[arms[v - 1]?.arm ?? ''] ?? String(v)}
                  tick={{ fontFamily: 'DM Mono, monospace', fontSize: 10, fill: 'var(--color-mut)' }}
                  axisLine={{ stroke: 'var(--color-bd)' }}
                  tickLine={false}
                />
                <YAxis
                  domain={[0.3, 0.7]}
                  tickFormatter={(v: number) => v.toFixed(2)}
                  tick={{ fontFamily: 'DM Mono, monospace', fontSize: 10, fill: 'var(--color-mut)' }}
                  axisLine={false}
                  tickLine={false}
                  width={38}
                  label={{
                    value: 'AUC',
                    position: 'insideTopLeft',
                    fontFamily: 'DM Mono, monospace',
                    fontSize: 9,
                    fill: 'var(--color-mut)',
                    dy: -4,
                  }}
                />
                {/* Gate bounds */}
                <ReferenceLine y={0.4} stroke="var(--color-cy)" strokeDasharray="3 3" strokeWidth={1} />
                <ReferenceLine y={0.6} stroke="var(--color-cy)" strokeDasharray="3 3" strokeWidth={1}
                  label={{ value: 'Gate [0.4, 0.6]', position: 'insideTopRight', fontFamily: 'DM Mono, monospace', fontSize: 8, fill: 'var(--color-cy)' }}
                />
                {/* Chance line */}
                <ReferenceLine y={0.5} stroke="var(--color-bd-strong)" strokeWidth={1} strokeDasharray="6 3" />
                <Tooltip content={<RocTooltip />} />
                <Scatter
                  data={scatterData}
                  dataKey="auc"
                  fill="var(--color-cy)"
                  isAnimationActive={false}
                  shape={({ cx, cy }: { cx?: number; cy?: number }) => (
                    <circle cx={cx} cy={cy} r={5} fill="var(--color-cy)" stroke="var(--color-s1)" strokeWidth={1.5} />
                  )}
                >
                  <ErrorBar dataKey="errorHalf" width={6} stroke="var(--color-cy)" strokeWidth={1.5} direction="y" />
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>

        <RocTable arms={arms} />
      </div>
    </Panel>
  );
};

// ── Covert Channel Panel ──────────────────────────────────────────────────────
export interface CovertChannelPanelProps {
  card: CovertChannelCard;
}

export const CovertChannelPanel: React.FC<CovertChannelPanelProps> = ({ card }) => {
  const isMeasured = card.bound_bits_per_query !== null;

  return (
    <Panel label="04 — COVERT-CHANNEL CAPACITY BOUND" meta="MICROARCHITECTURAL PARTIAL">
      <div className="space-y-4">
        {/* Capacity bound card */}
        <div className="border border-bd bg-s2/40 p-4 rounded space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-[11px] text-mut uppercase tracking-wider">
                Channel capacity bound
              </p>
              {isMeasured ? (
                <p className="font-display text-3xl text-tx tracking-wider mt-1">
                  ≤{card.bound_bits_per_query!.toFixed(3)}{' '}
                  <span className="text-sm text-mut font-mono">bits/query</span>
                </p>
              ) : (
                <p className="font-mono text-xl text-mut mt-1">NOT MEASURED</p>
              )}
            </div>
            <div className="font-mono text-xs text-mut text-right space-y-1">
              <p>n: {card.n_queries !== null ? String(card.n_queries) : '—'}</p>
              <p>method: {card.method ?? '—'}</p>
            </div>
          </div>

          {!isMeasured && (
            <p className="font-mono text-[11px] text-mut leading-relaxed border-t border-bd pt-3">
              Covert-channel capacity measurement requires dedicated timing experiments not yet
              executed. Default per declared evaluation profile. Does not imply zero capacity —
              use &ldquo;bounded&rdquo; language only after measurement.
            </p>
          )}
        </div>

        {/* Microarchitectural status */}
        <div className="flex flex-wrap items-center justify-between gap-3 border border-bd bg-s2/20 px-4 py-3 rounded">
          <div className="space-y-0.5">
            <p className="font-mono text-[11px] text-mut uppercase tracking-wider">
              Microarchitectural isolation
            </p>
            <p className="font-mono text-xs text-tx">
              SMT sharing off · dedicated cpusets · constant-time shaping (50ms bucket)
            </p>
          </div>
          <StatusPill status={card.microarch_status} size="sm" />
        </div>

        {/* Disclaimer */}
        <p className="font-mono text-[11px] text-mut leading-relaxed">
          Cross-core L3 cache eviction and speculative branch execution remain residual risk.
          Confidential computing (SEV-SNP/TDX) is{' '}
          <span className="text-inv">NOT ENABLED</span> (future work, Q-005).
          Assurances are strictly bounded within profile; absence of leakage is unproven.
        </p>
      </div>
    </Panel>
  );
};
