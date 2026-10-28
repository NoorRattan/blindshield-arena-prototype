import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SmokeRoute } from './SmokeRoute';

describe('SmokeRoute Foundation', () => {
  beforeEach(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
  });

  it('renders headline and all 3 typography sections', () => {
    render(<SmokeRoute />);
    expect(screen.getByText('BLINDSHIELD ARENA')).toBeInTheDocument();
    expect(screen.getByText(/01 — DISPLAY TYPOGRAPHY/i)).toBeInTheDocument();
    expect(screen.getByText(/02 — BODY TYPOGRAPHY/i)).toBeInTheDocument();
    expect(screen.getByText(/03 — MONO TYPOGRAPHY/i)).toBeInTheDocument();
  });

  it('enforces dark theme and renders exclusive dark badge', () => {
    render(<SmokeRoute />);
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(screen.getByText(/DARK \(EXCLUSIVE\)/i)).toBeInTheDocument();
  });

  it('does not contain banned marketing slop claims', () => {
    const { container } = render(<SmokeRoute />);
    const textContent = container.textContent?.toLowerCase() || '';

    const bannedWords = [
      'zero leakage',
      'tamper-proof',
      'unhackable',
      'guaranteed safe',
      'proves absence',
      'military-grade',
      '100% safe',
    ];

    bannedWords.forEach((word) => {
      expect(textContent).not.toContain(word);
    });
  });
});
