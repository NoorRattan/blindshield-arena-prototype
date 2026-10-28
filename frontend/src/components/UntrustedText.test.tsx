import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { UntrustedText } from './UntrustedText';

describe('UntrustedText Component (Invariant 4)', () => {
  it('renders raw text strictly as inert text nodes without HTML execution', () => {
    const maliciousPayload = '<img src="https://evil.internal/canary.png" onerror="alert(1)">';
    const { container } = render(<UntrustedText text={maliciousPayload} />);

    // Verify no <img> element was created in the DOM
    const imgElement = container.querySelector('img');
    expect(imgElement).toBeNull();

    // Verify text node contains raw string safely
    expect(screen.getByText(maliciousPayload)).toBeInTheDocument();
  });

  it('does not render markdown links as anchor elements', () => {
    const markdownAttack = '[Malicious Link](http://attacker.local/exploit.sh)';
    const { container } = render(<UntrustedText text={markdownAttack} />);

    // Verify no <a> tag was rendered
    const anchor = container.querySelector('a');
    expect(anchor).toBeNull();

    // Verify text node contains literal markdown
    expect(screen.getByText(markdownAttack)).toBeInTheDocument();
  });

  it('renders inside a pre element with proper styling', () => {
    const normalText = 'Adversarial attack prompt text here';
    const { container } = render(<UntrustedText text={normalText} />);

    const pre = container.querySelector('pre');
    expect(pre).toBeInTheDocument();
    expect(pre?.textContent).toBe(normalText);
  });
});
