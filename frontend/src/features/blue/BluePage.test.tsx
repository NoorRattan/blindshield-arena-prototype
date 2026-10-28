import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { BluePage } from './BluePage';
import { ToastProvider } from '../../components/Toast';
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

function renderBluePage() {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <BrowserRouter>
          <BluePage />
        </BrowserRouter>
      </ToastProvider>
    </QueryClientProvider>
  );
}

describe('BluePage Feature Component', () => {
  beforeEach(() => {
    arenaClient.reset();
    useArenaStore.setState({ role: 'blue', epoch: 4 });
  });

  afterEach(() => {
    useArenaStore.setState({ role: 'operator', epoch: 4 });
  });

  it('renders PageHeader, identity context, and all 3 panels for blue role', async () => {
    renderBluePage();

    await waitFor(() => {
      expect(screen.getByText(/BLUE TEAM DEFENSIVE CONSOLE/i)).toBeInTheDocument();
      expect(screen.getByText(/DOC-BLUE-06/i)).toBeInTheDocument();
      expect(screen.getByText(/01 — DEFENSE ARTIFACT VAULT & ENVELOPE/i)).toBeInTheDocument();
      expect(screen.getByText(/02 — LIVE ROUND HEALTH MONITOR/i)).toBeInTheDocument();
      expect(screen.getByText(/03 — CLOSED ROUND FORENSIC WORKSHOP/i)).toBeInTheDocument();
    });
  });

  it('renders defense artifact status, memory envelope, and readiness probes', async () => {
    renderBluePage();

    await waitFor(() => {
      expect(screen.getByText(/NeMo-Guard-blindshield-defense-v1.4/i)).toBeInTheDocument();
      expect(screen.getByText(/2,048 MB LIMIT/i)).toBeInTheDocument();
      expect(screen.getByText(/cgroup v2 isolation enforced/i)).toBeInTheDocument();
      expect(screen.getByText(/Readiness probe \(\/healthz\)/i)).toBeInTheDocument();
      expect(screen.getByText(/Filter latency baseline check/i)).toBeInTheDocument();
      expect(screen.getByText(/gVisor runsc isolation verified/i)).toBeInTheDocument();
      expect(screen.getByText(/Default-deny egress filter/i)).toBeInTheDocument();
      expect(screen.getByText(/FROZEN & SEALED/i)).toBeInTheDocument();
    });
  });

  it('toggles defense version mismatch and displays VERSION_MISMATCH alert banner', async () => {
    renderBluePage();

    await waitFor(() => {
      expect(screen.getByText(/Simulate Version Mismatch/i)).toBeInTheDocument();
    });

    const toggleBtn = screen.getByRole('button', { name: /Simulate Version Mismatch/i });
    fireEvent.click(toggleBtn);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText(/VERSION_MISMATCH/i)).toBeInTheDocument();
      expect(screen.getByText(/ACTIVE EPOCH INVALIDATED/i)).toBeInTheDocument();
      expect(screen.getByText(/VERSION INVALIDATED/i)).toBeInTheDocument();
    });
  });

  it('sanitizes live round health: masks payloads and decisions during active round (C-02 / FE-D-003)', async () => {
    renderBluePage();

    await waitFor(() => {
      // Security policy banner
      expect(screen.getByText(/SECURITY POLICY \/\/ SPEC CORRECTION C-02 & FE-D-003/i)).toBeInTheDocument();
      // Aggregate request count is shown
      expect(screen.getByText(/Total Processed/i)).toBeInTheDocument();
      // DELAYED T-30s indicator
      expect(screen.getAllByText(/DELAYED T-30s/i).length).toBeGreaterThan(0);
      // Withheld split notice
      expect(screen.getByText(/WITHHELD \(C-02\)/i)).toBeInTheDocument();
      // Embargoed decisions and masked payloads
      expect(screen.getAllByText(/DECISION EMBARGOED/i).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/PAYLOAD MASKED/i).length).toBeGreaterThan(0);
    });

    // In active round, the DOM must NOT contain allow/block ratio percentages for the live monitor
    const monitorRegion = screen.getByRole('region', { name: /Sanitized Live Turns Table/i });
    expect(monitorRegion.innerHTML).not.toContain('ALLOWED');
    expect(monitorRegion.innerHTML).not.toContain('BLOCKED');
  });

  it('renders closed-round forensic workshop with released epoch telemetry and payload traces', async () => {
    renderBluePage();

    await waitFor(() => {
      // Released epoch summary metrics
      expect(screen.getByText(/Total Analyzed Turns/i)).toBeInTheDocument();
      expect(screen.getByText(/Blocked by Defense/i)).toBeInTheDocument();
      expect(screen.getByText(/Allowed to Target/i)).toBeInTheDocument();
      expect(screen.getByText(/VERIFIED POST-RELEASE/i)).toBeInTheDocument();
      // Forensic quad cards
      expect(screen.getByText(/Attack Payload \(Released\)/i)).toBeInTheDocument();
      expect(screen.getByText(/Defense Decision Log/i)).toBeInTheDocument();
      expect(screen.getByText(/Scorer Ground Truth/i)).toBeInTheDocument();
      expect(screen.getByText(/Model Response \(Post-Release\)/i)).toBeInTheDocument();
    });
  });

  it('gates replay bundle download by role: disabled for blue, enabled for auditor', async () => {
    // 1. Role: blue -> download button is disabled
    useArenaStore.setState({ role: 'blue' });
    const { unmount } = renderBluePage();

    await waitFor(() => {
      const downloadBtn = screen.getByRole('button', { name: /Download Decrypted Replay Bundle/i });
      expect(downloadBtn).toBeDisabled();
      expect(screen.getByText(/Auditor Credentials Required/i)).toBeInTheDocument();
    });

    unmount();

    // 2. Role: auditor -> download button is enabled
    useArenaStore.setState({ role: 'auditor' });
    renderBluePage();

    await waitFor(() => {
      const downloadBtn = screen.getByRole('button', { name: /Download Decrypted Replay Bundle/i });
      expect(downloadBtn).toBeEnabled();
    });
  });

  it('enforces role matrix: red hitting /blue is denied with UNAUTHORIZED status', async () => {
    useArenaStore.setState({ role: 'red' });
    renderBluePage();

    await waitFor(() => {
      expect(screen.getByText(/ACCESS DENIED — ROLE BOUNDARY ENFORCED/i)).toBeInTheDocument();
      expect(screen.getByText(/UNAUTHORIZED/i)).toBeInTheDocument();
      expect(screen.getByText(/Offensive Red Team operators are strictly prohibited from viewing Blue Team defense artifacts/i)).toBeInTheDocument();
    });
  });

  it('never leaks internal canary tokens in the rendered DOM (Invariant 3)', async () => {
    renderBluePage();

    await waitFor(() => {
      expect(screen.getByText(/BLUE TEAM DEFENSIVE CONSOLE/i)).toBeInTheDocument();
    });

    const domHtml = document.body.innerHTML;
    for (const canary of Object.values(CANARY_TOKENS)) {
      expect(domHtml).not.toContain(canary);
    }
  });
});
