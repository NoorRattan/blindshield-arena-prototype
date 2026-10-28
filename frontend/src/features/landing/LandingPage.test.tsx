import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { LandingPage } from './LandingPage';
import { arenaClient } from '../../lib/api';

describe('LandingPage Feature', () => {
  beforeEach(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
    arenaClient.setFailureMode('none');
  });

  const renderLanding = () => {
    return render(
      <BrowserRouter>
        <LandingPage />
      </BrowserRouter>
    );
  };

  it('renders hero headline, eyebrow, actions, and mono fact strip', () => {
    renderLanding();
    expect(
      screen.getByText(/BLINDSHIELD ARENA · EVALUATION INTEGRITY/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/EVERY SAFETY FINDING,/i)).toBeInTheDocument();
    expect(screen.getByText(/ACCOUNTABLE TO ITS/i)).toBeInTheDocument();
    expect(screen.getByText(/EXECUTION CONDITIONS/i)).toBeInTheDocument();

    expect(
      screen.getAllByRole('button', { name: /ENTER THE ARENA/i }).length
    ).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /VERIFY A BUNDLE/i })).toBeInTheDocument();

    expect(screen.getAllByText(/FROZEN DEFENSE/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/SEALED ATTACKS/i)).toBeInTheDocument();
    expect(screen.getByText(/SIGNED, WITNESSED/i)).toBeInTheDocument();
  });

  it('renders Section 01: Four ways evaluations lie with editorial numerals', () => {
    renderLanding();
    expect(
      screen.getByText(/01 — THE FAILURE MODES OF UNCHECKED TESTING/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/THE FOUR WAYS EVALUATIONS LIE/i)).toBeInTheDocument();

    expect(screen.getByText(/FLAW-ADAPTIVE-OVERFIT/i)).toBeInTheDocument();
    expect(screen.getByText(/FLAW-PROMPT-EXTRACTION/i)).toBeInTheDocument();
    expect(screen.getByText(/FLAW-STATE-CONTAMINATION/i)).toBeInTheDocument();
    expect(screen.getByText(/FLAW-FAILURE-MASKING/i)).toBeInTheDocument();
  });

  it('renders Section 02: Two Verdicts demo and toggles failure injection', () => {
    renderLanding();
    expect(screen.getByText(/TWO INDEPENDENT OUTCOMES, ALWAYS/i)).toBeInTheDocument();

    // Default state: VALID_WITHIN_PROFILE present in pills and explanation
    expect(screen.getAllByText(/VALID_WITHIN_PROFILE/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/BLOCKED_BY_DEFENSE/i).length).toBeGreaterThan(0);

    // Click "Inject Defense Timeout" button
    const toggleBtn = screen.getByRole('button', { name: /Inject Defense Timeout/i });
    fireEvent.click(toggleBtn);

    // After failure injection: INVALID integrity and NOT_EVALUATED / INVALIDATED model
    expect(screen.getAllByText(/INVALID/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/DEADLINE_EXCEEDED/i).length).toBeGreaterThan(0);
    expect(arenaClient.getFailureMode()).toBe('defense_timeout');

    // Click to restore normal flow
    const restoreBtn = screen.getByRole('button', { name: /Restore Normal Flow/i });
    fireEvent.click(restoreBtn);
    expect(screen.getAllByText(/VALID_WITHIN_PROFILE/i).length).toBeGreaterThan(0);
    expect(arenaClient.getFailureMode()).toBe('none');
  });

  it('renders Section 03: Six hand-offs sequence and navigates steps', () => {
    renderLanding();
    expect(screen.getByText(/ONE ROUND, SIX HAND-OFFS/i)).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: /Adversarial Submission/i })
    ).toBeInTheDocument();

    // Click step tab 02: Default-Deny Ingestion
    const step2Tab = screen.getByRole('tab', { name: /02/i });
    fireEvent.click(step2Tab);

    expect(screen.getAllByText(/TRUSTED BROKER/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/WHAT OBSERVER CAN SEE/i)).toBeInTheDocument();
    expect(screen.getByText(/WHAT IS WITHHELD/i)).toBeInTheDocument();
  });

  it('renders Section 04: ResidualRiskPanel full width', () => {
    renderLanding();
    expect(screen.getByText(/04 — BOUNDARIES OF ASSURANCE/i)).toBeInTheDocument();
    expect(screen.getByText(/00 — THREAT SCOPE & RESIDUAL RISK/i)).toBeInTheDocument();
    expect(screen.getByText(/Malicious tenant code/i)).toBeInTheDocument();
    expect(screen.getByText(/Red–blue collusion/i)).toBeInTheDocument();
  });

  it('renders Section 05: Enter CTA and honest disclaimer note', () => {
    renderLanding();
    expect(screen.getByText(/05 — ARENA ENTRY & AUDIT SINK/i)).toBeInTheDocument();
    expect(screen.getByText(/VERIFIABLE AI SAFETY ASSURANCE/i)).toBeInTheDocument();
    expect(screen.getByText(/TCB METADATA:/i)).toBeInTheDocument();
    expect(screen.getByText(/ILLUSTRATIVE/i)).toBeInTheDocument();
  });

  it('passes banned-word check across the entire rendered Landing page', () => {
    const { container } = renderLanding();
    const textContent = container.textContent?.toLowerCase() || '';

    const bannedWords = [
      'zero leakage',
      'tamper-proof',
      'unhackable',
      'guaranteed safe',
      'proves absence',
      'military-grade',
      '100% safe',
      'ai-powered',
    ];

    bannedWords.forEach((word) => {
      expect(textContent).not.toContain(word);
    });
  });
});
