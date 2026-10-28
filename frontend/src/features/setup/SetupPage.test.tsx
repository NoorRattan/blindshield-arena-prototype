import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SetupPage } from './SetupPage';
import { useArenaStore } from '../../state/useArenaStore';
import { arenaClient } from '../../lib/api/client';

describe('SetupPage Feature Component', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });
    useArenaStore.setState({ role: 'operator', epoch: 1 });
    arenaClient.setFailureMode('none');
    vi.clearAllMocks();
  });

  const renderComponent = () =>
    render(
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <SetupPage />
        </BrowserRouter>
      </QueryClientProvider>
    );

  it('runs preflight directly', async () => {
    const report = await arenaClient.runPreflight('operator');
    expect(report.overall_status).toBe('PASS');
    expect(report.checks.length).toBe(9);
  });

  it('renders PageHeader with document ID and title for operator role', async () => {
    renderComponent();

    expect(screen.getByText(/DOC-EXP-SETUP/i)).toBeInTheDocument();
    expect(
      screen.getByText(/EXPERIMENT SETUP & CANONICAL MANIFEST COMPOSER/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/OPERATOR READY/i)).toBeInTheDocument();
  });

  it('renders 5-step wizard and live canonical preview', async () => {
    renderComponent();

    // Wizard Stepper items
    expect(screen.getByRole('tab', { name: /1. Domain & Epoch/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /2. Target Inference/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /3. Blue Defense/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /4. Red Constraints/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /5. Disclosure Policy/i })).toBeInTheDocument();

    // Canonical manifest preview
    expect(screen.getByText(/CANONICAL MANIFEST PREVIEW/i)).toBeInTheDocument();
    expect(screen.getByText(/LIVE WEB WORKER DIGEST/i)).toBeInTheDocument();
  });

  it('rejects invalid epoch values with strict Invariant 5 error message', async () => {
    renderComponent();

    const epochInput = screen.getByLabelText(/Evaluation Epoch/i);

    // Enter float or invalid epoch
    fireEvent.change(epochInput, { target: { value: '1.5' } });
    const nextBtn = screen.getByRole('button', { name: /Next Step/i });
    fireEvent.click(nextBtn);

    await waitFor(() => {
      expect(
        screen.getByText(/Epoch must be an exact positive integer/i)
      ).toBeInTheDocument();
    });

    // Enter negative epoch
    fireEvent.change(epochInput, { target: { value: '-2' } });
    fireEvent.click(nextBtn);

    await waitFor(() => {
      expect(
        screen.getByText(/Epoch must be an exact positive integer/i)
      ).toBeInTheDocument();
    });
  });

  it('validates domain identifier', async () => {
    renderComponent();

    const domainInput = screen.getByLabelText(/Arena Domain Identifier/i);
    fireEvent.change(domainInput, { target: { value: '' } });

    const nextBtn = screen.getByRole('button', { name: /Next Step/i });
    fireEvent.click(nextBtn);

    await waitFor(() => {
      expect(screen.getByText(/Domain identifier is required/i)).toBeInTheDocument();
    });
  });

  it('renders locked prefix-cache salt with uneditable embargo note in step 3', async () => {
    renderComponent();

    // Navigate to step 3
    const step3Tab = screen.getByRole('tab', { name: /3. Blue Defense/i });
    fireEvent.click(step3Tab);

    await waitFor(() => {
      expect(screen.getByText(/Prefix-Cache Isolation Salt/i)).toBeInTheDocument();
      expect(screen.getAllByText(/server-assigned secret \[embargoed\]/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/LOCKED · SERVER SECRET/i)).toBeInTheDocument();
    });
  });

  it('renders PreflightScannerPanel with 9 checks and handles preflight failure', async () => {
    // Inject failure mode
    arenaClient.setFailureMode('defense_timeout');
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText(/INFRASTRUCTURE PREFLIGHT SCANNER/i)).toBeInTheDocument();
      expect(
        screen.getByText(/PREFLIGHT FAILED · REQUIRED INFRASTRUCTURE CHECKS FAILED/i)
      ).toBeInTheDocument();
      expect(screen.getByText(/^FAIL$/i)).toBeInTheDocument();
    });

    // Sign button must be disabled when preflight fails
    const signBtn = screen.getByRole('button', { name: /SIGN & REGISTER WITH WITNESS/i });
    expect(signBtn).toBeDisabled();
  });

  it('renders ResidualRiskPanel with NOT VERIFIED status', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText(/THREAT SCOPE & RESIDUAL RISK/i)).toBeInTheDocument();
      expect(screen.getAllByText(/NOT VERIFIED/i).length).toBeGreaterThan(0);
    });
  });

  it('successfully signs and registers manifest, rendering ReceiptCard', async () => {
    renderComponent();

    // Wait for preflight to pass
    await waitFor(() => {
      expect(screen.getByText(/PREFLIGHT CLEARED · 8 OF 8/i)).toBeInTheDocument();
    });

    const signBtn = screen.getByRole('button', { name: /SIGN & REGISTER WITH WITNESS/i });
    expect(signBtn).not.toBeDisabled();

    fireEvent.click(signBtn);

    // Expect ReceiptCard with witness receipt ID and epoch
    await waitFor(() => {
      expect(screen.getByText(/EXPERIMENT SEALED & ATTESTED/i)).toBeInTheDocument();
      expect(screen.getByText(/Witness Receipt ID/i)).toBeInTheDocument();
      expect(screen.getByText(/Sealed Manifest Digest/i)).toBeInTheDocument();
      expect(screen.getByText(/Enter War Room/i)).toBeInTheDocument();
    });
  });

  it('enforces role gating: non-operator roles receive an explicit UNAUTHORIZED state', async () => {
    // Test Red role
    useArenaStore.setState({ role: 'red' });
    const { unmount } = renderComponent();

    expect(screen.getByText(/UNAUTHORIZED/i)).toBeInTheDocument();
    expect(screen.getByText(/OPERATOR PRIVILEGES REQUIRED/i)).toBeInTheDocument();
    expect(screen.queryByText(/1. Domain & Epoch/i)).not.toBeInTheDocument();
    unmount();

    // Test Blue role
    useArenaStore.setState({ role: 'blue' });
    const { unmount: unmountBlue } = renderComponent();
    expect(screen.getByText(/UNAUTHORIZED/i)).toBeInTheDocument();
    expect(screen.queryByText(/1. Domain & Epoch/i)).not.toBeInTheDocument();
    unmountBlue();

    // Test Auditor role
    useArenaStore.setState({ role: 'auditor' });
    const { unmount: unmountAuditor } = renderComponent();
    expect(screen.getByText(/UNAUTHORIZED/i)).toBeInTheDocument();
    expect(screen.queryByText(/1. Domain & Epoch/i)).not.toBeInTheDocument();
    unmountAuditor();
  });
});
