import type { ExperimentStatus, Role } from '../../lib/schemas';

export type OverviewFilter = 'ALL' | 'RUNNING' | 'SEALED' | 'INVALID' | 'RELEASED';

export interface OverviewMetrics {
  activeDomains: number;
  totalDomains: number;
  evaluationsRun: number;
  blockedCount: number;
  validCount: number;
  admittedCount: number;
  invalidCount: number;
  integrityPercentage: number;
  p95BrokerOverheadMs: number;
  targetBrokerOverheadMs: number;
}

export type AlertSeverity = 'CRITICAL' | 'WARNING' | 'INFO';

export interface IntegrityAlert {
  id: string;
  seq: number;
  timestamp_utc: string;
  arena_id: string;
  severity: AlertSeverity;
  action: string;
  title: string;
  detail: string;
  digest?: string;
  turn?: number;
}

export interface WitnessCheckpointTick {
  watermark: number;
  seq: number;
  timestamp_utc: string;
  receipt: string;
  status: 'SYNCED' | 'LAGGING' | 'INVALID';
  experiment_id: string;
}

export interface OverviewDataState {
  experiments: ExperimentStatus[];
  filteredExperiments: ExperimentStatus[];
  metrics: OverviewMetrics;
  alerts: IntegrityAlert[];
  heartbeatTicks: WitnessCheckpointTick[];
  activeFilter: OverviewFilter;
  setActiveFilter: (filter: OverviewFilter) => void;
  isLoading: boolean;
  isStale: boolean;
  streamStatus: 'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING';
  role: Role;
  lastUpdatedAgeSec: number;
}
