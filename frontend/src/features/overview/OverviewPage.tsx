import React from 'react';
import { PageHeader } from '../../components/PageHeader';
import { SimulatedDataTag } from '../../components/SimulatedDataTag';
import { useArenaStore } from '../../state/useArenaStore';
import { useOverviewData } from './hooks/useOverviewData';
import { MetricTiles } from './components/MetricTiles';
import { ArenaRoster } from './components/ArenaRoster';
import { AlertFeed } from './components/AlertFeed';
import { HeartbeatStrip } from './components/HeartbeatStrip';
import { OverviewSkeleton } from './components/OverviewSkeleton';

export const OverviewPage: React.FC = () => {
  const activeEpoch = useArenaStore((state) => state.epoch);
  const connectionMode = useArenaStore((state) => state.connectionMode);

  const {
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
  } = useOverviewData();

  if (isLoading) {
    return <OverviewSkeleton />;
  }

  const currentEpoch = experiments[0]?.epoch ?? activeEpoch;
  const currentTimestamp = experiments[0]?.updated_at ?? '2026-10-28T12:00:00Z';

  return (
    <div className="space-y-6" data-testid="overview-page">
      {/* Prominent Simulated Data Notice when operating in simulation mode */}
      {connectionMode === 'simulated' && (
        <SimulatedDataTag
          variant="banner"
          message="SIMULATED DATA: All metric aggregates, arenas, and alert feeds are generated in-memory. No live backend connected."
        />
      )}

      {/* Document-style Page Header */}
      <PageHeader
        docId="OVW-ARENA-01"
        title="ARENA ROSTER & INTEGRITY OVERVIEW"
        description="Executive assurance console for evaluation operators and auditors. Real-time tenant isolation status, verified cryptographic evidence bounds, and streaming tamper detection."
        epoch={currentEpoch}
        timestamp={currentTimestamp}
        actions={<SimulatedDataTag />}
        status={
          <span className="text-cy uppercase tracking-wider font-mono text-xs font-semibold">
            ROLE: {role.toUpperCase()}
          </span>
        }
      />

      {/* Row 1: Four Global Metric Tiles */}
      <section aria-label="Global Metric Tiles">
        <MetricTiles metrics={metrics} />
      </section>

      {/* Row 2: Arena Roster (cols 1-8) & Integrity Alerts Feed (cols 9-12) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <section className="lg:col-span-8 h-full" aria-label="Active Arenas Roster">
          <ArenaRoster
            experiments={experiments}
            filteredExperiments={filteredExperiments}
            activeFilter={activeFilter}
            setActiveFilter={setActiveFilter}
            isLoading={isLoading}
            role={role}
          />
        </section>

        <section className="lg:col-span-4 h-full" aria-label="Streaming Integrity Alerts">
          <AlertFeed
            alerts={alerts}
            streamStatus={streamStatus}
            isStale={isStale}
            lastUpdatedAgeSec={lastUpdatedAgeSec}
            role={role}
          />
        </section>
      </div>

      {/* Row 3: Witness Consensus Heartbeat Strip */}
      <section aria-label="Witness Checkpoint Heartbeat Strip">
        <HeartbeatStrip ticks={heartbeatTicks} />
      </section>
    </div>
  );
};
