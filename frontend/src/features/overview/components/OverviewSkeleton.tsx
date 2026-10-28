import React from 'react';
import { Skeleton } from '../../../components/Skeleton';
import { Panel } from '../../../components/Panel';

export const OverviewSkeleton: React.FC = () => {
  return (
    <div className="space-y-6 animate-pulse" data-testid="overview-skeleton">
      {/* PageHeader Skeleton */}
      <div className="border-b border-bd pb-4 mb-6">
        <div className="flex justify-between items-center mb-3">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-4 w-48" />
        </div>
        <Skeleton className="h-10 w-96 mb-2" />
        <Skeleton className="h-4 w-3/4 max-w-2xl" />
      </div>

      {/* Row 1: 4 Metric Tiles */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Panel key={`metric-skel-${i}`} label={`0${i + 1} / METRIC`}>
            <div className="py-2 space-y-3">
              <Skeleton className="h-10 w-24" />
              <div className="pt-3 border-t border-bd flex justify-between">
                <Skeleton className="h-3 w-28" />
                <Skeleton className="h-3 w-16" />
              </div>
            </div>
          </Panel>
        ))}
      </div>

      {/* Row 2: Roster (cols 1-8) & Alert Feed (cols 9-12) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Roster Skeleton (cols 1-8) */}
        <div className="lg:col-span-8">
          <Panel label="01 — ARENA ROSTER" meta={<Skeleton className="h-3 w-24" />}>
            <div className="space-y-4 py-1">
              <div className="flex gap-2 border-b border-bd/60 pb-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={`filter-skel-${i}`} className="h-7 w-20" />
                ))}
              </div>
              <div className="border border-bd rounded overflow-hidden">
                <div className="p-3 bg-s2/90 border-b border-bd flex gap-4">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-4 w-28" />
                </div>
                <div className="divide-y divide-bd/60 p-2 space-y-3">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <div key={`row-skel-${i}`} className="py-2 flex gap-4">
                      <Skeleton className="h-5 w-32" />
                      <Skeleton className="h-5 w-32" />
                      <Skeleton className="h-5 w-24" />
                      <Skeleton className="h-5 w-28" />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Panel>
        </div>

        {/* Alert Feed Skeleton (cols 9-12) */}
        <div className="lg:col-span-4">
          <Panel label="02 — INTEGRITY ALERTS" meta={<Skeleton className="h-3 w-20" />}>
            <div className="space-y-3 py-1">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={`alert-skel-${i}`} className="p-3 bg-s2/70 border border-bd rounded space-y-2">
                  <div className="flex justify-between">
                    <Skeleton className="h-3 w-28" />
                    <Skeleton className="h-3 w-16" />
                  </div>
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-8 w-full" />
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      {/* Row 3: Heartbeat Strip Skeleton */}
      <Panel label="03 — WITNESS CONSENSUS HEARTBEAT">
        <div className="py-2 space-y-3">
          <Skeleton className="h-8 w-full" />
          <div className="pt-3 border-t border-bd flex justify-between">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-4 w-40" />
          </div>
        </div>
      </Panel>
    </div>
  );
};
