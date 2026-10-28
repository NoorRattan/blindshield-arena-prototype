import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Panel } from '../../../components/Panel';
import { DataTable, type Column } from '../../../components/DataTable';
import { StatusPill } from '../../../components/StatusPill';
import { EpochBadge } from '../../../components/EpochBadge';
import { DelayedTag } from '../../../components/DelayedTag';
import type { ExperimentStatus, Role } from '../../../lib/schemas';
import type { OverviewFilter } from '../types';
import { ArrowUpDown, AlertTriangle } from 'lucide-react';

interface ArenaRosterProps {
  experiments: ExperimentStatus[];
  filteredExperiments: ExperimentStatus[];
  activeFilter: OverviewFilter;
  setActiveFilter: (filter: OverviewFilter) => void;
  isLoading: boolean;
  role: Role;
}

type SortField = 'domain' | 'target_model' | 'state' | 'integrity' | 'epoch' | 'updated_at';
type SortDirection = 'asc' | 'desc';

const FILTER_OPTIONS: { id: OverviewFilter; label: string }[] = [
  { id: 'ALL', label: 'All Arenas' },
  { id: 'RUNNING', label: 'Running' },
  { id: 'SEALED', label: 'Sealed' },
  { id: 'INVALID', label: 'Invalid' },
  { id: 'RELEASED', label: 'Released' },
];

function formatEventAge(isoString: string): string {
  try {
    const diffSec = Math.max(0, Math.floor((Date.now() - new Date(isoString).getTime()) / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    return `${diffHr}h ago`;
  } catch {
    return '–';
  }
}

export const ArenaRoster: React.FC<ArenaRosterProps> = ({
  experiments,
  filteredExperiments,
  activeFilter,
  setActiveFilter,
  isLoading,
  role,
}) => {
  const navigate = useNavigate();
  const [sortField, setSortField] = useState<SortField>('domain');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const sortedData = useMemo(() => {
    return [...filteredExperiments].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'domain':
          cmp = a.domain.localeCompare(b.domain);
          break;
        case 'target_model':
          cmp = (a.target_model ?? '').localeCompare(b.target_model ?? '');
          break;
        case 'state':
          cmp = a.state.localeCompare(b.state);
          break;
        case 'integrity': {
          const aInv = a.state === 'INVALID' || a.invalid_attempts_count > 0 ? 1 : 0;
          const bInv = b.state === 'INVALID' || b.invalid_attempts_count > 0 ? 1 : 0;
          cmp = aInv - bInv;
          break;
        }
        case 'epoch':
          cmp = a.epoch - b.epoch;
          break;
        case 'updated_at':
          cmp = new Date(a.updated_at).getTime() - new Date(b.updated_at).getTime();
          break;
      }
      return sortDirection === 'asc' ? cmp : -cmp;
    });
  }, [filteredExperiments, sortField, sortDirection]);

  const handleRowClick = (row: ExperimentStatus) => {
    navigate(`/war-room?arena=${encodeURIComponent(row.experiment_id)}`);
  };

  const isNonOperator = role !== 'operator';

  const columns: Column<ExperimentStatus>[] = [
    {
      id: 'arena_id',
      header: (
        <button
          type="button"
          onClick={() => handleSort('domain')}
          className="flex items-center gap-1.5 hover:text-tx focus:outline-none focus-visible:text-cy"
          aria-label="Sort by Arena Domain"
        >
          <span>Arena ID / Domain</span>
          <ArrowUpDown className="w-3 h-3 text-mut" />
        </button>
      ),
      accessor: (row) => (
        <div>
          <div className="font-bold text-tx tracking-wider">{row.domain}</div>
          <div className="text-[11px] text-mut">{row.experiment_id}</div>
        </div>
      ),
    },
    {
      id: 'target_model',
      header: (
        <button
          type="button"
          onClick={() => handleSort('target_model')}
          className="flex items-center gap-1.5 hover:text-tx focus:outline-none focus-visible:text-cy"
          aria-label="Sort by Target Model"
        >
          <span>Target Model</span>
          <ArrowUpDown className="w-3 h-3 text-mut" />
        </button>
      ),
      accessor: (row) => (
        <div className="text-tx font-medium truncate max-w-[150px]">
          {row.target_model ?? 'meta-llama/Llama-3-8B'}
        </div>
      ),
    },
    {
      id: 'defense_guardrail',
      header: 'Defense Guardrail',
      accessor: (row) => (
        <div className="text-mut truncate max-w-[160px]">
          {row.defense_guardrail ?? 'blindshield-defense-v1.4'}
        </div>
      ),
    },
    {
      id: 'lifecycle_state',
      header: (
        <button
          type="button"
          onClick={() => handleSort('state')}
          className="flex items-center gap-1.5 hover:text-tx focus:outline-none focus-visible:text-cy"
          aria-label="Sort by Lifecycle State"
        >
          <span>Round Phase</span>
          <ArrowUpDown className="w-3 h-3 text-mut" />
        </button>
      ),
      accessor: (row) => <StatusPill status={row.state} size="sm" />,
    },
    {
      id: 'integrity_state',
      header: (
        <button
          type="button"
          onClick={() => handleSort('integrity')}
          className="flex items-center gap-1.5 hover:text-tx focus:outline-none focus-visible:text-cy"
          aria-label="Sort by Integrity State"
        >
          <span>Integrity State</span>
          <ArrowUpDown className="w-3 h-3 text-mut" />
        </button>
      ),
      accessor: (row) => {
        const isInvalid = row.state === 'INVALID' || row.invalid_attempts_count > 0;
        if (isInvalid) {
          return (
            <div className="flex items-center gap-1.5">
              <StatusPill status="INVALID" size="sm" />
              <span className="text-[11px] text-inv font-bold tracking-tight flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-inv" />
                <span>({row.invalid_reason ?? 'DEADLINE_EXCEEDED'})</span>
              </span>
            </div>
          );
        }
        return <StatusPill status={row.integrity_status ?? 'VALID_WITHIN_PROFILE'} size="sm" />;
      },
    },
    {
      id: 'epoch',
      header: (
        <button
          type="button"
          onClick={() => handleSort('epoch')}
          className="flex items-center gap-1.5 hover:text-tx focus:outline-none focus-visible:text-cy"
          aria-label="Sort by Epoch"
        >
          <span>Epoch</span>
          <ArrowUpDown className="w-3 h-3 text-mut" />
        </button>
      ),
      accessor: (row) => <EpochBadge epoch={row.epoch} size="sm" />,
    },
    {
      id: 'last_event_age',
      header: (
        <button
          type="button"
          onClick={() => handleSort('updated_at')}
          className="flex items-center gap-1.5 hover:text-tx focus:outline-none focus-visible:text-cy"
          aria-label="Sort by Event Age"
        >
          <span>Last Event</span>
          <ArrowUpDown className="w-3 h-3 text-mut" />
        </button>
      ),
      accessor: (row) => (
        <span className="text-mut tabular-nums">
          {formatEventAge(row.updated_at)}
        </span>
      ),
    },
  ];

  return (
    <Panel
      label="01 — ARENA ROSTER"
      meta={
        <div className="flex items-center gap-3">
          {isNonOperator && <DelayedTag delay="T-30s" />}
          <span className="text-mut uppercase">
            {sortedData.length} / {experiments.length} ARENAS
          </span>
        </div>
      }
      className="w-full"
    >
      <div className="space-y-4 py-1">
        {/* Filter chips bar */}
        <div
          role="group"
          aria-label="Filter arenas by lifecycle status"
          className="flex flex-wrap items-center gap-2 border-b border-bd/60 pb-3"
        >
          <span className="text-xs font-mono text-mut uppercase mr-1">FILTER:</span>
          {FILTER_OPTIONS.map((opt) => {
            const isSelected = activeFilter === opt.id;
            const count =
              opt.id === 'ALL'
                ? experiments.length
                : opt.id === 'RUNNING'
                ? experiments.filter((e) => e.state === 'RUNNING').length
                : opt.id === 'SEALED'
                ? experiments.filter((e) => e.state === 'SEALED').length
                : opt.id === 'INVALID'
                ? experiments.filter((e) => e.state === 'INVALID' || e.invalid_attempts_count > 0).length
                : experiments.filter((e) => e.state === 'RELEASED').length;

            return (
              <button
                key={opt.id}
                type="button"
                aria-pressed={isSelected}
                onClick={() => setActiveFilter(opt.id)}
                className={`px-2.5 py-1 text-xs font-mono rounded-[2px] border transition-colors cursor-pointer focus:outline-none focus:ring-1 focus:ring-cy ${
                  isSelected
                    ? 'bg-cy/15 border-cy text-cy font-semibold'
                    : 'bg-s2 border-bd text-mut hover:text-tx hover:border-bd-strong'
                }`}
              >
                {opt.label} <span className="font-semibold text-tx">({count})</span>
              </button>
            );
          })}
        </div>

        {/* DataTable */}
        <DataTable
          columns={columns}
          data={sortedData}
          keyExtractor={(row) => row.experiment_id}
          onRowClick={handleRowClick}
          isLoading={isLoading}
          emptyMessage={`No arenas found matching filter "${activeFilter}".`}
          className="w-full"
        />

        <div className="text-[11px] font-mono text-mut flex items-center justify-between pt-1">
          <span>Click any row or press Enter to launch into War Room command center.</span>
          <span className="text-mut font-semibold">ENTER ↵</span>
        </div>
      </div>
    </Panel>
  );
};
