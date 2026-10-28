import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { RedPage } from './RedPage';
import { arenaClient } from '../../lib/api/client';
import { useArenaStore } from '../../state/useArenaStore';
import { CANARY_TOKENS } from '../../lib/mock/fixtures';

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        staleTime: 0,
      },
    },
  });
}

function renderRedPage() {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <RedPage />
      </BrowserRouter>
    </QueryClientProvider>
  );
}

describe('RedPage Feature Component', () => {
  beforeEach(() => {
    arenaClient.reset();
    useArenaStore.setState({ role: 'red', epoch: 4 });
  });

  afterEach(() => {
    useArenaStore.setState({ role: 'operator', epoch: 4 });
  });

  it('renders PageHeader, identity bar, and 12-column layout for red role', async () => {
    renderRedPage();

    await waitFor(() => {
      expect(screen.getByText(/RED TEAM OPERATIONAL PORTAL/i)).toBeInTheDocument();
      expect(screen.getByText(/DOC-RED-05/i)).toBeInTheDocument();
      expect(screen.getByText(/red-agent-01 · mTLS verified/i)).toBeInTheDocument();
      expect(screen.getByText(/01 — PAYLOAD COMMITMENT WORKSHOP/i)).toBeInTheDocument();
      expect(screen.getByText(/02 — TURN BUDGET & CAPACITY/i)).toBeInTheDocument();
      expect(screen.getByText(/03 — OUTCOME & FEEDBACK LOG/i)).toBeInTheDocument();
      expect(screen.getByText(/04 — OPERATIONAL PRIVACY NOTICE/i)).toBeInTheDocument();
    });
  });

  it('renders RadialMeter budget and tracks quota consumption', async () => {
    renderRedPage();

    await waitFor(() => {
      expect(screen.getByText(/BUDGET USED/i)).toBeInTheDocument();
      expect(screen.getByText(/TURNS SUBMITTED/i)).toBeInTheDocument();
      expect(screen.getByText(/REMAINING QUOTA/i)).toBeInTheDocument();
    });
  });

  it('renders turn feedback items with dual verdicts, bounded decisions, and coarse latency buckets', async () => {
    renderRedPage();

    await waitFor(() => {
      // Expect turn header
      expect(screen.getByText(/TURN 12/i)).toBeInTheDocument();
      // Bounded decision
      expect(screen.getAllByText(/BLOCKED_BY_DEFENSE/i).length).toBeGreaterThan(0);
      // Coarse 50ms latency bucket
      expect(screen.getAllByText(/50ms bucket/i).length).toBeGreaterThan(0);
      // Embargoed target output
      expect(screen.getAllByText(/Target response withheld until official round release/i).length).toBeGreaterThan(0);
    });
  });

  it('enforces role matrix: denies access to blue and auditor roles with UNAUTHORIZED status', async () => {
    // Test Blue Role
    useArenaStore.setState({ role: 'blue' });
    const { unmount } = renderRedPage();

    await waitFor(() => {
      expect(screen.getAllByText(/ACCESS DENIED — ROLE BOUNDARY ENFORCED/i).length).toBeGreaterThan(0);
      expect(screen.getByText(/UNAUTHORIZED/i)).toBeInTheDocument();
      expect(screen.getByText(/Role 'blue' is prohibited from inspecting active offensive attack queues/i)).toBeInTheDocument();
    });

    unmount();

    // Test Auditor Role
    useArenaStore.setState({ role: 'auditor' });
    renderRedPage();

    await waitFor(() => {
      expect(screen.getAllByText(/ACCESS DENIED — ROLE BOUNDARY ENFORCED/i).length).toBeGreaterThan(0);
      expect(screen.getByText(/UNAUTHORIZED/i)).toBeInTheDocument();
      expect(screen.getByText(/Role 'auditor' is prohibited from inspecting active offensive attack queues/i)).toBeInTheDocument();
    });
  });

  it('allows operator access in demo mode with flagged identity', async () => {
    useArenaStore.setState({ role: 'operator' });
    renderRedPage();

    await waitFor(() => {
      expect(screen.getByText(/operator-root-01 · mTLS verified \(DEMO MODE\)/i)).toBeInTheDocument();
      expect(screen.getByText(/01 — PAYLOAD COMMITMENT WORKSHOP/i)).toBeInTheDocument();
    });
  });

  it('never leaks internal canary tokens in the rendered DOM (Invariant 3)', async () => {
    renderRedPage();

    await waitFor(() => {
      expect(screen.getByText(/RED TEAM OPERATIONAL PORTAL/i)).toBeInTheDocument();
    });

    const domHtml = document.body.innerHTML;
    for (const canary of Object.values(CANARY_TOKENS)) {
      expect(domHtml).not.toContain(canary);
    }
  });
});
