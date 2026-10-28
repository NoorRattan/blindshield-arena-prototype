import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { EmbargoMask } from './EmbargoMask';

describe('EmbargoMask Component (Invariant 3)', () => {
  it('renders server-withheld placeholder block with lock icon and release conditions', () => {
    render(
      <EmbargoMask
        label="ATTACK VECTOR #04 EMBARGOED"
        reason="Withheld during active round under frozen feedback policy"
        releasePhase="DURABLE ROUND CLOSE"
        epoch={4}
      />
    );

    expect(screen.getByText('ATTACK VECTOR #04 EMBARGOED')).toBeInTheDocument();
    expect(
      screen.getByText(/Withheld during active round under frozen feedback policy/i)
    ).toBeInTheDocument();
    expect(screen.getByText('DURABLE ROUND CLOSE')).toBeInTheDocument();
    expect(screen.getByText(/EPOCH 04/i)).toBeInTheDocument();
  });

  it('exposes accessible status role without leaking secret content', () => {
    render(<EmbargoMask />);
    const statusEl = screen.getByRole('status');
    expect(statusEl).toBeInTheDocument();
    expect(statusEl).toHaveAttribute('aria-label');
  });
});
