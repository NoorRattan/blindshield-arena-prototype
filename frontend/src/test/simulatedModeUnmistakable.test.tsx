import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '../components/Toast';
import { useArenaStore } from '../state/useArenaStore';
import { OverviewPage } from '../features/overview/OverviewPage';
import { RedPage } from '../features/red/RedPage';
import { BluePage } from '../features/blue/BluePage';
import { WarRoomPage } from '../features/war-room/WarRoomPage';
import { SetupPage } from '../features/setup/SetupPage';
import { BenchmarksPage } from '../features/benchmarks/BenchmarksPage';

describe('Unmistakable Simulated vs Live Mode Test Suite (Task 1 & Task 5)', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    useArenaStore.setState({
      connectionMode: 'simulated',
      role: 'operator',
      epoch: 4,
      liveBackendStatus: 'DISCONNECTED',
      authenticatedPrincipal: null,
    });
    vi.clearAllMocks();
  });

  afterEach(() => {
    queryClient.clear();
  });

  const renderWithProviders = (ui: React.ReactElement) => {
    return render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <BrowserRouter>{ui}</BrowserRouter>
        </ToastProvider>
      </QueryClientProvider>
    );
  };

  it('renders unmistakable SIMULATED DATA banner and badges on OverviewPage in simulated mode', async () => {
    renderWithProviders(<OverviewPage />);
    await waitFor(() => {
      const simulatedTags = screen.getAllByText(/SIMULATED DATA/i);
      expect(simulatedTags.length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getByText(/All metric aggregates, arenas, and alert feeds are generated in-memory/i)).toBeInTheDocument();
  });

  it('renders unmistakable SIMULATED DATA badge and banner on RedPage in simulated mode', async () => {
    renderWithProviders(<RedPage />);
    await waitFor(() => {
      const simulatedTags = screen.getAllByText(/SIMULATED DATA/i);
      expect(simulatedTags.length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getByText(/Offensive payload workshop and feedback logs running in-memory demo mode/i)).toBeInTheDocument();
  });

  it('renders unmistakable SIMULATED DATA banner on BluePage in simulated mode', async () => {
    useArenaStore.setState({ role: 'blue' });
    renderWithProviders(<BluePage />);
    await waitFor(() => {
      const simulatedTags = screen.getAllByText(/SIMULATED DATA/i);
      expect(simulatedTags.length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getByText(/Blue defense artifact envelopes, readiness probes, and forensic workshop running in-memory demo mode/i)).toBeInTheDocument();
  });

  it('renders unmistakable SIMULATED DATA banner on WarRoomPage in simulated mode', async () => {
    renderWithProviders(<WarRoomPage />);
    await waitFor(() => {
      const simulatedTags = screen.getAllByText(/SIMULATED DATA/i);
      expect(simulatedTags.length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getByText(/War Room gauges, event waterfall, and audit feed are running in local simulation mode/i)).toBeInTheDocument();
  });

  it('renders unmistakable SIMULATED DATA banner on SetupPage in simulated mode', async () => {
    renderWithProviders(<SetupPage />);
    await waitFor(() => {
      const simulatedTags = screen.getAllByText(/SIMULATED DATA/i);
      expect(simulatedTags.length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getByText(/Operating in local mock mode without live broker commitment/i)).toBeInTheDocument();
  });

  it('renders unmistakable SIMULATED DATA banner on BenchmarksPage when illustrative', async () => {
    renderWithProviders(<BenchmarksPage />);
    await waitFor(() => {
      const simulatedTags = screen.getAllByText(/SIMULATED DATA/i);
      expect(simulatedTags.length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getByText(/Generated from seeded synthetic distributions/i)).toBeInTheDocument();
  });

  it('removes SIMULATED DATA banners when switched to live mode with authenticated principal', async () => {
    useArenaStore.setState({
      connectionMode: 'live',
      liveBackendStatus: 'CONNECTED',
      authenticatedPrincipal: {
        subject_id: 'operator-root-01',
        domain_id: 'BAYORA-PROD-01',
        expires_at: '2026-10-29T12:00:00Z',
        role: 'operator',
        subject: 'CN=operator-root-01',
        certFingerprint: 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        is_mtls_verified: true,
      },
    });

    renderWithProviders(<OverviewPage />);
    await waitFor(() => {
      expect(screen.queryByText(/All metric aggregates, arenas, and alert feeds are generated in-memory/i)).not.toBeInTheDocument();
    });
  });
});
