import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { arenaClient } from '../../../lib/api';
import { useArenaStore } from '../../../state/useArenaStore';
import type { ArenaEvent } from '../../../lib/schemas';
import type {
  IntegrityAlert,
  OverviewDataState,
  OverviewFilter,
  OverviewMetrics,
  WitnessCheckpointTick,
} from '../types';

/**
 * Seed initial alerts deterministically to populate the feed before live SSE events arrive
 */
function createInitialAlerts(): IntegrityAlert[] {
  return [
    {
      id: 'alert_init_01',
      seq: 104,
      timestamp_utc: '2026-10-19T08:15:37Z',
      arena_id: 'BAYORA-PROD-01',
      severity: 'WARNING',
      action: 'defense_filtered',
      title: 'Turn 12 Red attack blocked by defense guardrail',
      detail: 'Adversarial jailbreak payload intercepted by blindshield-defense-v1.4. Target model inference suppressed.',
      digest: 'sha256:7b914ac5d89234e19038ba7130dfc829034e402830a84092bba741298492c10a',
      turn: 12,
    },
    {
      id: 'alert_init_02',
      seq: 103,
      timestamp_utc: '2026-10-19T07:00:22Z',
      arena_id: 'BAYORA-TEST-03',
      severity: 'CRITICAL',
      action: 'attempt_invalidated',
      title: 'Defense container deadline exceeded (1002 ms > 1000 ms limit)',
      detail: 'Attempt invalidated. Model execution marked UNKNOWN. Target inference NOT_EVALUATED.',
      digest: 'sha256:4a7c59e1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9',
      turn: 2,
    },
    {
      id: 'alert_init_03',
      seq: 102,
      timestamp_utc: '2026-10-19T08:14:05Z',
      arena_id: 'BAYORA-PROD-01',
      severity: 'INFO',
      action: 'preflight_passed',
      title: 'Hardware isolation and cpuset binding verified',
      detail: 'Assurance profile VALID_WITHIN_PROFILE. SMT threads pinned to cpusets 4-7 with dedicated cache lines.',
      digest: 'sha256:d8f3e291a0b4c8d2e6f0a4b8c2d6e0f4a8b2c6d0e4f8a2b6c0d4e8f2a6b0c4d8',
    },
    {
      id: 'alert_init_04',
      seq: 101,
      timestamp_utc: '2026-10-19T09:30:01Z',
      arena_id: 'BAYORA-SEC-02',
      severity: 'INFO',
      action: 'manifest_sealed',
      title: 'Manifest sealed with witness consensus',
      detail: 'Immutable configuration committed to witness ledger. Protocol version arena.v2 initialized.',
      digest: 'sha256:e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2',
    },
  ];
}

/**
 * Generate 20 deterministic witness checkpoint heartbeat ticks
 */
function createHeartbeatTicks(): WitnessCheckpointTick[] {
  const ticks: WitnessCheckpointTick[] = [];
  const baseWatermark = 422;
  const baseTime = new Date('2026-10-19T08:00:00Z').getTime();

  for (let i = 0; i < 20; i++) {
    const wm = baseWatermark + i;
    const timeIso = new Date(baseTime + i * 45000).toISOString();
    ticks.push({
      watermark: wm,
      seq: i + 1,
      timestamp_utc: timeIso,
      receipt: `rcpt_8f4e2${(wm * 13).toString(16).slice(0, 8)}`,
      status: i === 14 ? 'LAGGING' : 'SYNCED',
      experiment_id: i % 2 === 0 ? 'BAYORA-PROD-01' : 'BAYORA-SEC-02',
    });
  }
  return ticks;
}

export function useOverviewData(): OverviewDataState {
  const role = useArenaStore((s) => s.role);
  const epoch = useArenaStore((s) => s.epoch);

  const [activeFilter, setActiveFilter] = useState<OverviewFilter>('ALL');
  const [alerts, setAlerts] = useState<IntegrityAlert[]>(createInitialAlerts);
  const [streamStatus, setStreamStatus] = useState<'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING'>('CONNECTED');
  const [lastEventTime, setLastEventTime] = useState<number>(Date.now());
  const [lastUpdatedAgeSec, setLastUpdatedAgeSec] = useState<number>(0);

  // Set of seen event IDs for deduplication
  const seenEventIdsRef = useRef<Set<string>>(new Set(['init_104', 'init_103', 'init_102', 'init_101']));

  // Fetch experiments roster and status
  const { data: experiments = [], isLoading } = useQuery({
    queryKey: ['experiments', role],
    queryFn: () => arenaClient.getExperiments(role),
    staleTime: 5000,
    refetchInterval: 10000,
  });

  // Calculate metrics across all arenas
  const metrics = useMemo<OverviewMetrics>(() => {
    const activeDomains = experiments.filter((e) => e.state === 'RUNNING').length;
    const totalDomains = experiments.length;
    let evaluationsRun = 0;
    let blockedCount = 0;
    let validCount = 0;
    let invalidCount = 0;

    for (const exp of experiments) {
      evaluationsRun += exp.attempts_count;
      blockedCount += exp.blocked_attempts_count ?? 0;
      validCount += exp.valid_attempts_count;
      invalidCount += exp.invalid_attempts_count;
    }

    const admittedCount = evaluationsRun;
    const integrityPercentage = admittedCount > 0 ? (validCount / admittedCount) * 100 : 100;

    return {
      activeDomains,
      totalDomains,
      evaluationsRun,
      blockedCount,
      validCount,
      admittedCount,
      invalidCount,
      integrityPercentage,
      p95BrokerOverheadMs: 18.4,
      targetBrokerOverheadMs: 100,
    };
  }, [experiments]);

  // Filter experiments based on selected chip
  const filteredExperiments = useMemo(() => {
    if (activeFilter === 'ALL') return experiments;
    if (activeFilter === 'RUNNING') return experiments.filter((e) => e.state === 'RUNNING');
    if (activeFilter === 'SEALED') return experiments.filter((e) => e.state === 'SEALED');
    if (activeFilter === 'INVALID') {
      return experiments.filter((e) => e.state === 'INVALID' || e.integrity_status === 'INVALID');
    }
    if (activeFilter === 'RELEASED') return experiments.filter((e) => e.state === 'RELEASED');
    return experiments;
  }, [experiments, activeFilter]);

  // Heartbeat ticks
  const heartbeatTicks = useMemo(() => createHeartbeatTicks(), []);

  // SSE subscription to active running arena
  useEffect(() => {
    const activeArena = experiments.find((e) => e.state === 'RUNNING') ?? experiments[0];
    if (!activeArena) return;

    const unsubscribe = arenaClient.subscribeEvents(
      activeArena.experiment_id,
      (event: ArenaEvent) => {
        // 1. Deduplication check: ignore duplicate events
        const eventKey = `${event.experiment}:${event.seq}:${event.action}`;
        if (seenEventIdsRef.current.has(eventKey)) {
          return;
        }
        seenEventIdsRef.current.add(eventKey);

        // 2. Stale epoch check: ignore events with stale epoch
        if (event.epoch < epoch) {
          return;
        }

        // 3. Map event to alert item
        let severity: 'CRITICAL' | 'WARNING' | 'INFO' = 'INFO';
        let title = `System event: ${event.action}`;
        let detail = `Executed by ${event.actor} in epoch ${event.epoch}. Outcome: ${event.outcome}`;

        if (event.action === 'attempt_invalidated' || event.outcome === 'INVALID' || event.outcome === 'DEADLINE_EXCEEDED') {
          severity = 'CRITICAL';
          title = `Integrity violation: ${event.outcome}`;
          detail = `Attempt invalidated by ${event.actor}. Target inference halted.`;
        } else if (event.outcome === 'BLOCKED_BY_DEFENSE' || event.action === 'defense_filtered') {
          severity = event.outcome === 'BLOCKED_BY_DEFENSE' ? 'WARNING' : 'INFO';
          title = event.outcome === 'BLOCKED_BY_DEFENSE' ? 'Adversarial query blocked by defense' : 'Defense filter passed';
          detail = `Evaluation outcome: ${event.outcome} recorded in signed ledger.`;
        } else if (event.action === 'manifest_sealed' || event.action === 'preflight_passed') {
          severity = 'INFO';
          title = event.action === 'manifest_sealed' ? 'Manifest sealed with witness receipt' : 'Hardware preflight validated';
          detail = `Outcome: ${event.outcome}. Digest committed to cryptographic chain.`;
        }

        const newAlert: IntegrityAlert = {
          id: `alert_sse_${Date.now()}_${event.seq}`,
          seq: event.seq,
          timestamp_utc: event.ts_utc,
          arena_id: activeArena.domain,
          severity,
          action: event.action,
          title,
          detail,
          digest: event.artifacts[0],
        };

        setAlerts((prev) => [newAlert, ...prev.slice(0, 19)]);
        setLastEventTime(Date.now());
      },
      (_err) => {
        // Handled in streamStatus
      },
      (status) => {
        setStreamStatus(status);
        if (status === 'CONNECTED') {
          setLastEventTime(Date.now());
        }
      },
      role
    );

    return () => {
      unsubscribe();
    };
  }, [experiments, epoch, role]);

  // Periodic timer to detect staleness (> 10 seconds without events)
  useEffect(() => {
    const interval = setInterval(() => {
      const ageSec = Math.floor((Date.now() - lastEventTime) / 1000);
      setLastUpdatedAgeSec(ageSec);
    }, 1000);

    return () => clearInterval(interval);
  }, [lastEventTime]);

  const isStale = lastUpdatedAgeSec > 10;

  return {
    experiments,
    filteredExperiments,
    metrics,
    alerts,
    heartbeatTicks,
    activeFilter,
    setActiveFilter,
    isLoading,
    isStale,
    streamStatus,
    role,
    lastUpdatedAgeSec,
  };
}
