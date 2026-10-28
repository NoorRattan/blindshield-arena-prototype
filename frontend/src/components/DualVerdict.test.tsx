import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DualVerdict } from './DualVerdict';

describe('DualVerdict Component (Invariant 1 & P02 Rule)', () => {
  it('renders both model outcome and evaluation integrity separately', () => {
    render(
      <DualVerdict
        modelOutcome="EXECUTED"
        integrity="VALID_WITHIN_PROFILE"
        scoringOutcome="SCORED"
      />
    );

    expect(screen.getByText(/Assurance Integrity/i)).toBeInTheDocument();
    expect(screen.getByText('VALID_WITHIN_PROFILE')).toBeInTheDocument();

    expect(screen.getByText(/Model Outcome/i)).toBeInTheDocument();
    expect(screen.getByText('EXECUTED')).toBeInTheDocument();
    expect(screen.getByText('SCORED')).toBeInTheDocument();
  });

  it('downgrades model outcome to NOT_EVALUATED/INVALIDATED when integrity is INVALID', () => {
    const { container } = render(
      <DualVerdict
        modelOutcome="EXECUTED"
        integrity="INVALID"
      />
    );

    // Integrity displays INVALID
    expect(screen.getByText('INVALID')).toBeInTheDocument();

    // Model outcome must NOT display as EXECUTED or have green text-ok style
    expect(screen.queryByText('EXECUTED')).toBeNull();
    expect(screen.getByText('INVALIDATED')).toBeInTheDocument();

    // Verify no green 'text-ok' is assigned to the invalidated model pill
    const okElements = container.querySelectorAll('.text-ok');
    expect(okElements.length).toBe(0);
  });
});
