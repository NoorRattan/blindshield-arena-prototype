import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';
import { Panel } from '../components/Panel';
import { ErrorState } from '../components/ErrorState';
import { ArrowLeft } from 'lucide-react';

export const NotFoundPage: React.FC = () => {
  const location = useLocation();

  return (
    <div className="space-y-6">
      <PageHeader
        docId="ERR-404"
        title="ROUTE NOT RESOLVED"
        description="The requested route does not map to any recognized console subsystem or evidence partition."
      />

      <Panel label="01 — NAVIGATION FAULT" meta="STATUS: 404_PAGE_NOT_FOUND">
        <ErrorState
          code="ERR_ROUTE_NOT_FOUND"
          title="Unmapped Arena Endpoint"
          message={`No route registered for target path: ${location.pathname}. The resource may be restricted under current role policy or unmapped.`}
          details={`Requested URI: ${location.pathname}\nTimestamp: ${new Date().toISOString()}\nAction: Re-route to landing or authorized arena console`}
        />

        <div className="mt-6 flex items-center gap-3">
          <Link
            to="/"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cy text-bg text-xs font-mono uppercase tracking-wider font-semibold hover:opacity-90 transition-opacity"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Return to Landing</span>
          </Link>
          <Link
            to="/overview"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded border border-bd text-xs font-mono uppercase tracking-wider text-tx hover:bg-s2 transition-colors"
          >
            <span>Arena Overview</span>
          </Link>
        </div>
      </Panel>
    </div>
  );
};
