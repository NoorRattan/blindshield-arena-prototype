import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StatusPill, ALL_STATUSES } from './StatusPill';

describe('StatusPill Component', () => {
  it('renders every status from the status vocabulary (§11 + Q-005)', () => {
    ALL_STATUSES.forEach((status) => {
      const { unmount } = render(<StatusPill status={status} />);
      expect(screen.getByText(status)).toBeInTheDocument();
      unmount();
    });
  });

  it('supports custom label overrides while preserving status metadata', () => {
    render(<StatusPill status="VALID_WITHIN_PROFILE" label="AUDITED OK" />);
    expect(screen.getByText('AUDITED OK')).toBeInTheDocument();
  });

  it('sets data-status attribute matching status string', () => {
    const { container } = render(<StatusPill status="INVALID" />);
    const pill = container.querySelector('[data-status="INVALID"]');
    expect(pill).toBeInTheDocument();
  });
});
