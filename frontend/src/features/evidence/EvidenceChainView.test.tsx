import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { EvidenceChainView } from './EvidenceChainView';
import { EventDetailDrawer } from './EventDetailDrawer';
import { MockArenaServer } from '../../lib/mock/server';
import type { ArenaEvent } from '../../lib/schemas';

describe('Evidence Chain View and Event Drawer (P10-S3)', () => {
  const server = new MockArenaServer();
  const rawBundle = server.getEvidenceBundle('exp_released_04', 'auditor');
  const ledger = rawBundle.ledger as ArenaEvent[];

  it('renders 2D fallback view when WebGL is absent and displays events', () => {
    const handleSelect = vi.fn();
    render(
      <EvidenceChainView
        ledger={ledger}
        onSelectEvent={handleSelect}
      />
    );

    expect(screen.getByText(/04 — MERKLE HASH CHAIN LEDGER/i)).toBeInTheDocument();
    expect(screen.getByText(/Showing 41 of 41 events/i)).toBeInTheDocument();
    expect(screen.getByText(/#001/i)).toBeInTheDocument();
  });

  it('displays chain rupture indicator when brokenIndex is provided', () => {
    render(
      <EvidenceChainView
        ledger={ledger}
        brokenIndex={1}
      />
    );

    expect(screen.getByText(/CHAIN RUPTURE DETECTED \(HASH MISMATCH AT SEQ #2\)/i)).toBeInTheDocument();
  });

  it('opens EventDetailDrawer on event click and renders canonical RFC 8785 JSON', () => {
    render(<EvidenceChainView ledger={ledger} />);

    // Click event #001
    const eventRow = screen.getByText(/#001/i);
    fireEvent.click(eventRow);

    // EventDetailDrawer should open
    expect(screen.getByRole('dialog', { name: /Event Details Sequence #1/i })).toBeInTheDocument();
    expect(screen.getByText(/Canonical RFC 8785 JSON/i)).toBeInTheDocument();
    expect(screen.getByText(/Chained Event Digest/i)).toBeInTheDocument();

    // Close button
    const closeBtn = screen.getByRole('button', { name: /Close Event Details/i });
    fireEvent.click(closeBtn);

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('closes EventDetailDrawer on Escape key press', () => {
    const handleClose = vi.fn();
    render(
      <EventDetailDrawer
        event={ledger[0]}
        isOpen={true}
        onClose={handleClose}
      />
    );

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(handleClose).toHaveBeenCalled();
  });
});
