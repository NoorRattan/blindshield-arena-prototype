import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '../components/Toast';
import { AppShell } from './AppShell';
import { SmokeRoute } from './SmokeRoute';
import { NotFoundPage } from './NotFoundPage';

// Route-level code-splitting for bundle size optimization (P12-S5)
const LandingPage = React.lazy(() =>
  import('../features/landing').then((m) => ({ default: m.LandingPage }))
);
const OverviewPage = React.lazy(() =>
  import('../features/overview').then((m) => ({ default: m.OverviewPage }))
);
const SetupPage = React.lazy(() =>
  import('../features/setup').then((m) => ({ default: m.SetupPage }))
);
const WarRoomPage = React.lazy(() =>
  import('../features/war-room').then((m) => ({ default: m.WarRoomPage }))
);
const RedPage = React.lazy(() =>
  import('../features/red').then((m) => ({ default: m.RedPage }))
);
const BluePage = React.lazy(() =>
  import('../features/blue').then((m) => ({ default: m.BluePage }))
);
const EvidencePage = React.lazy(() =>
  import('../features/evidence').then((m) => ({ default: m.EvidencePage }))
);
const BenchmarksPage = React.lazy(() =>
  import('../features/benchmarks').then((m) => ({ default: m.BenchmarksPage }))
);
const KitPage = React.lazy(() =>
  import('./KitPage').then((m) => ({ default: m.KitPage }))
);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 5000,
    },
  },
});

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<AppShell />}>
              {/* Landing / Foundation */}
              <Route path="/" element={<LandingPage />} />
              <Route path="/smoke" element={<SmokeRoute />} />

            {/* Overview Console Page */}
            <Route path="/overview" element={<OverviewPage />} />

            {/* Setup & Manifest Composer Page */}
            <Route path="/setup" element={<SetupPage />} />

            {/* Live War Room Cockpit Page */}
            <Route path="/war-room" element={<WarRoomPage />} />

            {/* Red Team Portal */}
            <Route path="/red" element={<RedPage />} />

            {/* Blue Team Defense Console */}
            <Route path="/blue" element={<BluePage />} />
            {/* Evidence Inspector & Offline Verifier */}
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/benchmarks" element={<BenchmarksPage />} />

            {/* Dev Component Kit Showcase */}
            <Route path="/__kit" element={<KitPage />} />

            {/* 404 Route */}
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  </QueryClientProvider>
  );
};
