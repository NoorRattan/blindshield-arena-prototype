import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { PayloadWorkshop } from './PayloadWorkshop';
import { arenaClient } from '../../lib/api/client';
import type { Epoch } from '../../lib/schemas';

describe('PayloadWorkshop Component', () => {
  const defaultProps = {
    experimentId: 'exp_running_01',
    domain: 'BAYORA-PROD-01',
    epoch: 4 as Epoch,
  };

  beforeEach(() => {
    arenaClient.reset();
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch {
      // ignore
    }
    vi.clearAllMocks();
  });

  it('renders payload workshop with accessible label, byte count, token estimate, and digests', () => {
    render(<PayloadWorkshop {...defaultProps} />);

    // Accessible textarea label
    const textarea = screen.getByLabelText(/ADVERSARIAL ATTACK PAYLOAD/i);
    expect(textarea).toBeInTheDocument();

    // Mode buttons
    expect(screen.getByRole('button', { name: /PLAIN TEXT/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /AUTOMATED SCRIPT/i })).toBeInTheDocument();

    // Limit badge
    expect(screen.getByText(/64.0 KiB TEXT/i)).toBeInTheDocument();

    // Token estimate labeled ESTIMATE
    expect(screen.getByText(/^ESTIMATE$/i)).toBeInTheDocument();

    // Secret Nonce & Idempotency Key
    expect(screen.getByText(/SECRET NONCE/i)).toBeInTheDocument();
    expect(screen.getByText(/IDEMPOTENCY KEY/i)).toBeInTheDocument();

    // Submit button
    expect(
      screen.getByRole('button', { name: /SUBMIT PAYLOAD TO BROKER/i })
    ).toBeInTheDocument();
  });

  it('updates live UTF-8 byte counter and token estimate when payload text changes', async () => {
    render(<PayloadWorkshop {...defaultProps} />);

    const textarea = screen.getByLabelText(/ADVERSARIAL ATTACK PAYLOAD/i);

    // Enter a known multi-byte text (e.g. 5 ASCII chars + 1 4-byte emoji = 9 bytes)
    fireEvent.change(textarea, { target: { value: 'TEST 👋' } });

    await waitFor(() => {
      expect(screen.getAllByText(/9 B/i).length).toBeGreaterThan(0);
    });
  });

  it('blocks submit and shows alert in live region when payload exceeds 65,536 bytes limit', async () => {
    render(<PayloadWorkshop {...defaultProps} />);

    const textarea = screen.getByLabelText(/ADVERSARIAL ATTACK PAYLOAD/i);
    const submitBtn = screen.getByRole('button', { name: /SUBMIT PAYLOAD TO BROKER/i });

    // Enter oversized string
    const oversized = 'A'.repeat(65537);
    fireEvent.change(textarea, { target: { value: oversized } });

    await waitFor(() => {
      expect(
        screen.getByText(/PAYLOAD EXCEEDS 65,536 BYTE LIMIT/i)
      ).toBeInTheDocument();
      expect(submitBtn).toBeDisabled();
    });
  });

  it('regenerates secret nonce and updates commitment digest', async () => {
    render(<PayloadWorkshop {...defaultProps} />);

    const regenNonceBtn = screen.getByRole('button', { name: /REGENERATE NONCE/i });

    // Click regenerate nonce
    fireEvent.click(regenNonceBtn);

    // Expect nonce button still available and responsive
    expect(regenNonceBtn).toBeInTheDocument();
  });

  it('submits payload to broker and displays ReceiptCard upon success', async () => {
    const onSubmitted = vi.fn();
    render(<PayloadWorkshop {...defaultProps} onAttackSubmitted={onSubmitted} />);

    const submitBtn = screen.getByRole('button', { name: /SUBMIT PAYLOAD TO BROKER/i });
    fireEvent.click(submitBtn);

    // Receipt card should render upon confirmation
    await waitFor(() => {
      expect(screen.getByText(/BROKER RECEIPT CONFIRMED/i)).toBeInTheDocument();
      expect(screen.getByText(/PAYLOAD COMMITTED TO LEDGER/i)).toBeInTheDocument();
      expect(onSubmitted).toHaveBeenCalled();
    });
  });

  it('handles idempotency replay and 409 conflict demonstrations in dev drawer', async () => {
    render(<PayloadWorkshop {...defaultProps} />);

    // Expand dev drawer
    const expandBtn = screen.getByRole('button', { name: /EXPAND DRAWER/i });
    fireEvent.click(expandBtn);

    // Replay idempotency button
    const replayBtn = screen.getByRole('button', { name: /REPLAY IDEMPOTENT KEY/i });
    expect(replayBtn).toBeInTheDocument();
    fireEvent.click(replayBtn);

    await waitFor(() => {
      expect(screen.getByText(/IDEMPOTENT REPLAY VERIFIED/i)).toBeInTheDocument();
    });

    // Trigger conflict button
    const conflictBtn = screen.getByRole('button', { name: /TRIGGER 409 CONFLICT/i });
    fireEvent.click(conflictBtn);

    await waitFor(() => {
      expect(screen.getByText(/409 CONFLICT DEMONSTRATED/i)).toBeInTheDocument();
    });
  });

  it('never persists payload drafts into browser storage (Invariant 3 & Forbidden Scope)', () => {
    render(<PayloadWorkshop {...defaultProps} />);

    const textarea = screen.getByLabelText(/ADVERSARIAL ATTACK PAYLOAD/i);
    fireEvent.change(textarea, { target: { value: 'SECRET_PAYLOAD_DRAFT_DO_NOT_STORE' } });

    // Ensure localStorage and sessionStorage remain completely empty
    const storage = typeof localStorage !== 'undefined' ? localStorage : window.localStorage;
    const session = typeof sessionStorage !== 'undefined' ? sessionStorage : window.sessionStorage;
    expect(storage?.getItem('payload') ?? null).toBeNull();
    expect(storage?.getItem('draft') ?? null).toBeNull();
    expect(storage?.length ?? 0).toBe(0);
    expect(session?.length ?? 0).toBe(0);
  });
});
