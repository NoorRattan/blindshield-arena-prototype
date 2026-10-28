import React, { useId } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  ReferenceLine,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { Panel } from '../../components/Panel';
import { IllustrativeTag } from '../../components/IllustrativeTag';
import type { LatencyPath } from './benchmarkSchemas';

// ── Tooltip ───────────────────────────────────────────────────────────────────
interface LatencyTooltipProps {
  active?: boolean;
  payload?: { payload?: LatencyPath }[];
}

function LatencyTooltip({ active, payload }: LatencyTooltipProps) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  if (!d) return null;
  return (
    <div className="bg-s1 border border-bd px-3 py-2 font-mono text-[11px] text-tx space-y-0.5 max-w-[200px]">
      <p className="font-medium text-cy uppercase tracking-wider truncate">{d.label}</p>
      <p>p95: <span className={d.within_gate ? 'text-bl' : 'text-bad'}>{d.p95_ms} ms</span></p>
      <p>p50: <span className="text-tx">{d.p50_ms} ms</span></p>
      <p>gate: <span className="text-mut">{d.target_gate_ms} ms TARGET</span></p>
      <p>n: <span className="text-tx">{d.n_samples}</span></p>
      <p className={d.within_gate ? 'text-bl' : 'text-bad'}>
        {d.within_gate ? 'WITHIN TARGET' : 'EXCEEDS TARGET'}
      </p>
    </div>
  );
}

// ── Latency table ─────────────────────────────────────────────────────────────
function LatencyTable({ paths }: { paths: LatencyPath[] }) {
  return (
    <div
      role="region"
      tabIndex={0}
      aria-label="Latency measurements by path"
      className="overflow-x-auto border border-bd rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
    >
      <table className="w-full font-mono text-xs text-left border-collapse min-w-[480px]">
        <caption className="sr-only">Latency p95 and p50 per path measured independently, compared against TARGET gates</caption>
        <thead>
          <tr className="border-b border-bd bg-s2/80 text-mut uppercase text-[11px] tracking-wider">
            <th scope="col" className="p-2.5 font-medium">Path</th>
            <th scope="col" className="p-2.5 font-medium text-right">p95 (ms)</th>
            <th scope="col" className="p-2.5 font-medium text-right">p50 (ms)</th>
            <th scope="col" className="p-2.5 font-medium text-right">TARGET Gate</th>
            <th scope="col" className="p-2.5 font-medium text-right">n</th>
            <th scope="col" className="p-2.5 font-medium text-right">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-bd">
          {paths.map((path) => (
            <tr key={path.label} className="hover:bg-s2/20 transition-colors">
              <td className="p-2.5 text-tx">{path.label}</td>
              <td className={`p-2.5 text-right tabular-nums font-medium ${path.within_gate ? 'text-bl' : 'text-bad'}`}>
                {path.p95_ms}
              </td>
              <td className="p-2.5 text-right tabular-nums text-tx">{path.p50_ms}</td>
              <td className="p-2.5 text-right tabular-nums text-mut">≤{path.target_gate_ms}</td>
              <td className="p-2.5 text-right tabular-nums text-mut">{path.n_samples}</td>
              <td className={`p-2.5 text-right whitespace-nowrap ${path.within_gate ? 'text-bl' : 'text-bad'}`}>
                {path.within_gate ? 'WITHIN TARGET' : 'EXCEEDS TARGET'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export interface LatencyPanelProps {
  paths: LatencyPath[];
  illustrative: boolean;
}

export const LatencyPanel: React.FC<LatencyPanelProps> = ({ paths, illustrative }) => {
  const chartId = useId();

  if (paths.length === 0) {
    return (
      <Panel label="02 — LATENCY (p95 PER PATH)" meta="TARGET GATES">
        <p className="font-mono text-xs text-mut py-8 text-center">INSUFFICIENT DATA</p>
      </Panel>
    );
  }

  const chartData = paths.map((p) => ({
    ...p,
    shortLabel: p.label.split(' ').slice(0, 2).join('\n'),
  }));

  return (
    <Panel
      label="02 — LATENCY · p95 PER PATH"
      meta={
        <span className="flex items-center gap-2">
          <span>MEASURED PER PATH · DO NOT SUM STAGES · TTFT = WALL-CLOCK REQUEST → MODEL START</span>
          {illustrative && <IllustrativeTag />}
        </span>
      }
    >
      <div className="space-y-5">
        {/* Legend */}
        <div className="flex flex-wrap items-center gap-4 font-mono text-[11px] text-mut">
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-2 bg-bl" aria-hidden="true" />
            Within TARGET
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-3 h-2 bg-bad" aria-hidden="true" />
            Exceeds TARGET
          </span>
          <span className="flex items-center gap-1.5 text-mut">
            — — TARGET gate (dashed)
          </span>
        </div>

        {/* Chart */}
        <div
          className="overflow-x-auto"
          role="region"
          tabIndex={0}
          aria-label="Latency p95 bar chart by path"
          aria-describedby={`${chartId}-desc`}
        >
          <p id={`${chartId}-title`} className="sr-only">Latency p95 bar chart by path</p>
          <p id={`${chartId}-desc`} className="sr-only">
            Compares p95 latency for each measured path against its TARGET gate.
            Paths within gate are shown in cobalt; exceeding paths in red.
            See the table below for exact values.
          </p>
          <div className="min-w-[400px]">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart
                data={chartData}
                barCategoryGap="35%"
                margin={{ top: 8, right: 12, left: 0, bottom: 4 }}
              >
                <XAxis
                  dataKey="shortLabel"
                  tick={{ fontFamily: 'DM Mono, monospace', fontSize: 9, fill: 'var(--color-mut)' }}
                  axisLine={{ stroke: 'var(--color-bd)' }}
                  tickLine={false}
                />
                <YAxis
                  tickFormatter={(v: number) => `${v}`}
                  tick={{ fontFamily: 'DM Mono, monospace', fontSize: 10, fill: 'var(--color-mut)' }}
                  axisLine={false}
                  tickLine={false}
                  width={42}
                  label={{
                    value: 'ms',
                    position: 'insideTopLeft',
                    fontFamily: 'DM Mono, monospace',
                    fontSize: 9,
                    fill: 'var(--color-mut)',
                    dy: -4,
                  }}
                />
                {/* Each path has its own gate — show the lowest gate as reference */}
                <ReferenceLine
                  y={100}
                  stroke="var(--color-cy)"
                  strokeDasharray="4 3"
                  strokeWidth={1}
                  label={{
                    value: '100ms gate',
                    position: 'insideTopRight',
                    fontFamily: 'DM Mono, monospace',
                    fontSize: 9,
                    fill: 'var(--color-cy)',
                  }}
                />
                <Tooltip
                  content={<LatencyTooltip />}
                  cursor={{ fill: 'var(--color-s2)', opacity: 0.4 }}
                />
                <Bar dataKey="p95_ms" name="p95 (ms)" isAnimationActive={false} radius={0}>
                  {chartData.map((path) => (
                    <Cell
                      key={path.label}
                      fill={path.within_gate ? 'var(--color-bl)' : 'var(--color-bad)'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Data table — text summary for accessibility */}
        <LatencyTable paths={paths} />
      </div>
    </Panel>
  );
};
