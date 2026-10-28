import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { OverviewPage } from './OverviewPage';
import { OverviewSkeleton } from './components/OverviewSkeleton';
import { useArenaStore } from '../../state/useArenaStore';
import type { Role } from '../../lib/schemas';

const mockedNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockedNavigate,
  };
});

describe('OverviewPage Feature', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    vi.clearAllMocks();
    queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
        },
      },
    });
    useArenaStore.getState().setRole('operator');
    document.documentElement.setAttribute('data-theme', 'dark');
  });

  const renderOverview = async () => {
    const rendered = render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <OverviewPage />
        </MemoryRouter>
      </QueryClientProvider>
    );
    await waitFor(() => {
      expect(screen.getByTestId('overview-page')).toBeInTheDocument();
    });
    return rendered;
  };

  it('renders PageHeader with document ID, title, and role status', async () => {
    await renderOverview();
    expect(screen.getByText('OVW-ARENA-01')).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: /ARENA ROSTER & INTEGRITY OVERVIEW/i })
    ).toBeInTheDocument();
    expect(screen.getByText(/ROLE: OPERATOR/i)).toBeInTheDocument();
  });

  it('renders four metric tiles with numerator/denominator and blocked count', async () => {
    await renderOverview();

    expect(screen.getByText(/01 \/ ACTIVE DOMAINS/i)).toBeInTheDocument();
    expect(screen.getByText(/02 \/ EVALUATIONS RUN/i)).toBeInTheDocument();
    expect(screen.getByText(/03 \/ INTEGRITY RATE/i)).toBeInTheDocument();
    expect(screen.getByText(/04 \/ P95 BROKER LATENCY/i)).toBeInTheDocument();

    // Check numerator/denominator in integrity rate
    expect(screen.getByText(/33 \/ 34/i)).toBeInTheDocument();
    expect(screen.getByText(/\[1 INVALIDATED\]/i)).toBeInTheDocument();

    // Check blocked count shown separately
    expect(screen.getByText(/\[9 BLOCKED\]/i)).toBeInTheDocument();

    // Check target broker line
    expect(screen.getByText(/TARGET ≤ 100 ms/i)).toBeInTheDocument();
  });

  it('renders Arena Roster with target models, defenses, and distinct purple INVALID state with reason code', async () => {
    await renderOverview();
    const dataTable = screen.getByRole('region', { name: /Data Table/i });

    expect(within(dataTable).getByText('BAYORA-PROD-01')).toBeInTheDocument();
    expect(within(dataTable).getByText('BAYORA-SEC-02')).toBeInTheDocument();
    expect(within(dataTable).getByText('BAYORA-TEST-03')).toBeInTheDocument();
    expect(within(dataTable).getByText('BAYORA-EVAL-04')).toBeInTheDocument();

    // Distinct INVALID pill with reason code
    expect(within(dataTable).getByText(/(DEADLINE_EXCEEDED)/i)).toBeInTheDocument();
  });

  it('filters arenas using filter chips', async () => {
    await renderOverview();
    const dataTable = screen.getByRole('region', { name: /Data Table/i });

    expect(within(dataTable).getByText('BAYORA-PROD-01')).toBeInTheDocument();

    // Click 'Running' chip
    const runningChip = screen.getByRole('button', { name: /Running/i });
    fireEvent.click(runningChip);
    expect(within(dataTable).getByText('BAYORA-PROD-01')).toBeInTheDocument();
    expect(within(dataTable).queryByText('BAYORA-SEC-02')).not.toBeInTheDocument();

    // Click 'Invalid' chip
    const invalidChip = screen.getByRole('button', { name: /Invalid/i });
    fireEvent.click(invalidChip);
    expect(within(dataTable).getByText('BAYORA-TEST-03')).toBeInTheDocument();
    expect(within(dataTable).queryByText('BAYORA-PROD-01')).not.toBeInTheDocument();

    // Click 'All Arenas' chip
    const allChip = screen.getByRole('button', { name: /All Arenas/i });
    fireEvent.click(allChip);
    expect(within(dataTable).getByText('BAYORA-PROD-01')).toBeInTheDocument();
    expect(within(dataTable).getByText('BAYORA-SEC-02')).toBeInTheDocument();
    expect(within(dataTable).getByText('BAYORA-TEST-03')).toBeInTheDocument();
  });

  it('navigates to war-room on row click', async () => {
    await renderOverview();
    const dataTable = screen.getByRole('region', { name: /Data Table/i });

    const runningRow = within(dataTable).getByText('BAYORA-PROD-01').closest('tr');
    expect(runningRow).toBeInTheDocument();

    if (runningRow) {
      fireEvent.click(runningRow);
      expect(mockedNavigate).toHaveBeenCalledWith('/war-room?arena=exp_running_01');
    }
  });

  it('renders streaming alert feed and interactive heartbeat strip', async () => {
    await renderOverview();

    expect(screen.getByText(/02 — INTEGRITY ALERTS/i)).toBeInTheDocument();
    expect(screen.getByText(/03 — WITNESS CONSENSUS HEARTBEAT/i)).toBeInTheDocument();
    expect(screen.getByText(/WATERMARK #441/i)).toBeInTheDocument();

    // Check alert feed contains initial seeded alert
    expect(screen.getByText(/Turn 12 Red attack blocked/i)).toBeInTheDocument();
  });

  it('displays DELAYED T-30s for non-operator roles in role matrix', async () => {
    const nonOperatorRoles: Role[] = ['red', 'blue', 'auditor'];

    for (const role of nonOperatorRoles) {
      useArenaStore.getState().setRole(role);
      const { unmount } = render(
        <QueryClientProvider client={new QueryClient()}>
          <MemoryRouter>
            <OverviewPage />
          </MemoryRouter>
        </QueryClientProvider>
      );

      await waitFor(() => {
        expect(screen.getAllByText(/DELAYED T-30s/i).length).toBeGreaterThan(0);
      });

      unmount();
    }
  });

  it('renders OverviewSkeleton with matching layout structure', () => {
    render(<OverviewSkeleton />);
    expect(screen.getByTestId('overview-skeleton')).toBeInTheDocument();
    expect(screen.getByText('01 — ARENA ROSTER')).toBeInTheDocument();
    expect(screen.getByText('02 — INTEGRITY ALERTS')).toBeInTheDocument();
    expect(screen.getByText('03 — WITNESS CONSENSUS HEARTBEAT')).toBeInTheDocument();
  });
});
