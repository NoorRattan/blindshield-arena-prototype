import React from 'react';

export const RouteLoadingFallback: React.FC = () => {
  return (
    <div
      className="container mx-auto px-4 py-8 max-w-7xl animate-pulse space-y-6"
      role="status"
      aria-label="Loading subsystem partition"
    >
      <div className="flex items-center justify-between border-b border-bd/40 pb-4">
        <div className="space-y-2">
          <div className="h-4 w-32 bg-s2 rounded" />
          <div className="h-8 w-64 bg-s2 rounded" />
        </div>
        <div className="h-8 w-24 bg-s2 rounded" />
      </div>

      <div className="h-44 w-full bg-s1 border border-bd/40 rounded p-6">
        <div className="h-4 w-48 bg-s2 rounded mb-4" />
        <div className="h-20 w-full bg-s2/50 rounded" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="h-64 bg-s1 border border-bd/40 rounded p-6">
          <div className="h-4 w-36 bg-s2 rounded mb-4" />
          <div className="h-44 w-full bg-s2/40 rounded" />
        </div>
        <div className="h-64 bg-s1 border border-bd/40 rounded p-6">
          <div className="h-4 w-36 bg-s2 rounded mb-4" />
          <div className="h-44 w-full bg-s2/40 rounded" />
        </div>
      </div>
    </div>
  );
};
