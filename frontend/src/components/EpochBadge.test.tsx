import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { EpochBadge } from './EpochBadge';

describe('EpochBadge Component (Invariant 5)', () => {
  it('renders valid positive integers with leading zeros and cyan styling', () => {
    render(<EpochBadge epoch={4} />);
    expect(screen.getByText('EPOCH')).toBeInTheDocument();
    expect(screen.getByText('04')).toBeInTheDocument();
  });

  it('rejects non-positive integers with EPOCH INVALID', () => {
    const { rerender } = render(<EpochBadge epoch={0} />);
    expect(screen.getByText('INVALID')).toBeInTheDocument();

    rerender(<EpochBadge epoch={-3} />);
    expect(screen.getByText('INVALID')).toBeInTheDocument();
  });

  it('rejects floats, strings, booleans, and null per Invariant 5', () => {
    const { rerender } = render(<EpochBadge epoch={4.5} />);
    expect(screen.getByText('INVALID')).toBeInTheDocument();

    rerender(<EpochBadge epoch={'4'} />);
    expect(screen.getByText('INVALID')).toBeInTheDocument();

    rerender(<EpochBadge epoch={true} />);
    expect(screen.getByText('INVALID')).toBeInTheDocument();

    rerender(<EpochBadge epoch={null} />);
    expect(screen.getByText('INVALID')).toBeInTheDocument();
  });
});
