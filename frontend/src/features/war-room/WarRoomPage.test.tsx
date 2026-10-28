import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { WarRoomPage } from './WarRoomPage';
import { ToastProvider } from '../../components/Toast';
import { useArenaStore } from '../../state/useArenaStore';
import { arenaClient } from '../../lib/api/client';

describe('WarRoomPage Feature Component', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });
    arenaClient.reset();
    useArenaStore.setState({ role: 'operator', epoch: 4, failureMode: 'none' });
    vi.clearAllMocks();
  });

  const renderComponent = () =>
    render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <BrowserRouter>
            <WarRoomPage />
          </BrowserRouter>
        </ToastProvider>
      </QueryClientProvider>
    );

  it('renders PageHeader, top bar metadata, and dual verdict for operator role', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getAllByText(/DOC-WAR-04/i).length).toBeGreaterThan(0);
      expect(screen.getByText(/LIVE ARENA WAR ROOM/i)).toBeInTheDocument();
      expect(screen.getByText('BAYORA-PROD-01')).toBeInTheDocument();
    });

    expect(screen.getAllByText('04').length).toBeGreaterThan(0);
    expect(screen.getAllByText('RUNNING').length).toBeGreaterThan(0);
  });

  it('renders 6-stage pipeline waterfall with real event durations', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText(/01 — PIPELINE EXECUTION WATERFALL/i)).toBeInTheDocument();
    });

    expect(screen.getByTestId('waterfall-stage-red')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-broker')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-blue')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-target')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-scorer')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-recorder')).toBeInTheDocument();
  });

  it('renders telemetry gauges with illustrative tags and target benchmarks', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText(/02 — ATTRIBUTE TELEMETRY GAUGES/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/Broker Queue Depth/i)).toBeInTheDocument();
    expect(screen.getByText(/Blue Cell Memory/i)).toBeInTheDocument();
    expect(screen.getByText(/Target TTFT/i)).toBeInTheDocument();
    expect(screen.getByText(/Generation Speed/i)).toBeInTheDocument();
    expect(screen.getByText(/Circuit Breaker/i)).toBeInTheDocument();
    expect(screen.getByText(/Network Isolation/i)).toBeInTheDocument();
    expect(screen.getByText(/Egress Probes/i)).toBeInTheDocument();
    expect(screen.getByText(/Witness Watermark/i)).toBeInTheDocument();
  });

  it('renders virtualized chained audit log with filters and link digests', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText(/04 — LIVE CHAINED AUDIT LOG/i)).toBeInTheDocument();
    });

    // Check filter buttons
    expect(screen.getByRole('button', { name: /^all$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^red$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^blue$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^broker$/i })).toBeInTheDocument();
  });

  it('renders role observability boundary comparison between operator, red, and blue', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText(/03 — ROLE OBSERVABILITY BOUNDARY/i)).toBeInTheDocument();
    });

    expect(screen.getByRole('tab', { name: /Operator/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /View as Red Team/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /View as Blue Team/i })).toBeInTheDocument();

    // Switch to Red Team tab
    fireEvent.click(screen.getByRole('tab', { name: /View as Red Team/i }));
    expect(screen.getByText(/DELAYED T-30s/i)).toBeInTheDocument();
    expect(screen.getByText(/Coarse Bucket/i)).toBeInTheDocument();

    // Switch to Blue Team tab
    fireEvent.click(screen.getByRole('tab', { name: /View as Blue Team/i }));
    expect(screen.getByText(/WITHHELD UNTIL CLOSE/i)).toBeInTheDocument();
    expect(screen.getByText(/PROMPT TEXT EMBARGOED/i)).toBeInTheDocument();
  });

  it('handles defense_timeout failure mode correctly and updates integrity to INVALID', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /defense_timeout/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /defense_timeout/i }));

    await waitFor(() => {
      const blueStage = screen.getByTestId('waterfall-stage-blue');
      expect(blueStage).toHaveClass('border-inv');
      expect(blueStage).toHaveTextContent('TIMEOUT');
      expect(blueStage).toHaveTextContent('1002ms');
    });

    // Integrity alert is rendered
    expect(screen.getByRole('alert')).toHaveTextContent(/DEFENSE_DEADLINE_EXCEEDED/i);
    expect(screen.getByText(/NO RETRY PERMITTED/i)).toBeInTheDocument();
  });

  it('executes typed emergency quarantine and marks lifecycle as INVALID', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Emergency Quarantine/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Emergency Quarantine/i }));

    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeInTheDocument();

    const input = screen.getByPlaceholderText('QUARANTINE');
    fireEvent.change(input, { target: { value: 'QUARANTINE' } });

    const confirmBtn = screen.getByRole('button', { name: /Confirm Quarantine/i });
    expect(confirmBtn).not.toBeDisabled();
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(screen.getAllByText(/DOMAIN QUARANTINED/i).length).toBeGreaterThan(0);
    });
  });

  it('triggers on-demand re-witness checkpoint', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Re-Witness/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Re-Witness/i }));

    await waitFor(() => {
      expect(screen.getAllByText(/RE-WITNESS/i).length).toBeGreaterThan(0);
    });
  });
});
