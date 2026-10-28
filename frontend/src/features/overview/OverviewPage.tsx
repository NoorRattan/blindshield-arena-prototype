import React from 'react';
import { PageHeader } from '../../components/PageHeader';
import { useOverviewData } from './hooks/useOverviewData';
import { MetricTiles } from './components/MetricTiles';
import { ArenaRoster } from './components/ArenaRoster';
import { AlertFeed } from './components/AlertFeed';
import { HeartbeatStrip } from './components/HeartbeatStrip';
import { OverviewSkeleton } from './components/OverviewSkeleton';

export const OverviewPage: React.FC = () => {
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

  return (
    <div className="space-y-6" data-testid="overview-page">
      {/* Document-style Page Header */}
      <PageHeader
        docId="OVW-ARENA-01"
        title="ARENA ROSTER & INTEGRITY OVERVIEW"
        description="Executive assurance console for evaluation operators and auditors. Real-time tenant isolation status, verified cryptographic evidence bounds, and streaming tamper detection."
        epoch={4}
        timestamp="2026-10-19T08:15:37Z"
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
