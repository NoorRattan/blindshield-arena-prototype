import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { generateIllustrativeBenchmarks } from './benchmarkFixtures';
import { BenchmarkImportDropzone } from './BenchmarkImportDropzone';
import { AttackSuccessRatePanel } from './AttackSuccessRatePanel';
import { LatencyPanel } from './LatencyPanel';
import { SummaryTablePanel } from './SummaryTablePanel';
import { CovertChannelPanel } from './RocAndCovertPanel';
import type { BenchmarkDataset } from './benchmarkSchemas';

const DATASET: BenchmarkDataset = generateIllustrativeBenchmarks();

// ── BenchmarkImportDropzone ────────────────────────────────────────────────────
describe('BenchmarkImportDropzone', () => {
  it('shows load illustrative button when no dataset loaded', () => {
    render(
      <BenchmarkImportDropzone
        currentDataset={null}
        fileName={null}
        onDatasetLoaded={() => undefined}
        onLoadIllustrative={() => undefined}
      />
    );
    expect(screen.getByRole('button', { name: /load illustrative/i })).toBeInTheDocument();
  });

  it('calls onLoadIllustrative when button clicked', async () => {
    const spy = vi.fn();
    render(
      <BenchmarkImportDropzone
        currentDataset={null}
        fileName={null}
        onDatasetLoaded={() => undefined}
        onLoadIllustrative={spy}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: /load illustrative/i }));
    expect(spy).toHaveBeenCalledOnce();
  });

  it('shows loaded state with experiment id when dataset present', () => {
    render(
      <BenchmarkImportDropzone
        currentDataset={DATASET}
        fileName="test.json"
        onDatasetLoaded={() => undefined}
        onLoadIllustrative={() => undefined}
      />
    );
    expect(screen.getByText('test.json')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reset to illustrative/i })).toBeInTheDocument();
  });
});

// ── AttackSuccessRatePanel ────────────────────────────────────────────────────
describe('AttackSuccessRatePanel', () => {
  it('renders INSUFFICIENT DATA when rows empty', () => {
    render(<AttackSuccessRatePanel rows={[]} illustrative />);
    expect(screen.getByText(/insufficient data/i)).toBeInTheDocument();
  });

  it('renders deny-all baseline row', () => {
    render(<AttackSuccessRatePanel rows={DATASET.attack_rates} illustrative />);
    expect(screen.getAllByText(/deny-all baseline/i).length).toBeGreaterThanOrEqual(1);
  });

  it('never folds blocked/invalid into the attack success rate column', () => {
    render(<AttackSuccessRatePanel rows={DATASET.attack_rates} illustrative />);
    // The Blocked column header must be present
    expect(screen.getByRole('columnheader', { name: /blocked/i })).toBeInTheDocument();
    // The Invalid column header must be present
    expect(screen.getByRole('columnheader', { name: /invalid/i })).toBeInTheDocument();
  });

  it('shows 95% CI column header', () => {
    render(<AttackSuccessRatePanel rows={DATASET.attack_rates} illustrative />);
    expect(screen.getByRole('columnheader', { name: /95% CI/i })).toBeInTheDocument();
  });

  it('shows ILLUSTRATIVE tag when illustrative=true', () => {
    render(<AttackSuccessRatePanel rows={DATASET.attack_rates} illustrative />);
    expect(screen.getByText(/illustrative/i)).toBeInTheDocument();
  });
});

// ── LatencyPanel ──────────────────────────────────────────────────────────────
describe('LatencyPanel', () => {
  it('renders INSUFFICIENT DATA when paths empty', () => {
    render(<LatencyPanel paths={[]} illustrative />);
    expect(screen.getByText(/insufficient data/i)).toBeInTheDocument();
  });

  it('renders WITHIN TARGET labels', () => {
    render(<LatencyPanel paths={DATASET.latency_paths} illustrative />);
    expect(screen.getAllByText(/within target/i).length).toBeGreaterThan(0);
  });

  it('shows p95 column header', () => {
    render(<LatencyPanel paths={DATASET.latency_paths} illustrative />);
    expect(screen.getByRole('columnheader', { name: /p95/i })).toBeInTheDocument();
  });
});

// ── SummaryTablePanel ─────────────────────────────────────────────────────────
describe('SummaryTablePanel', () => {
  it('shows admit / valid / invalid tiles', () => {
    render(<SummaryTablePanel summary={DATASET.summary} illustrative />);
    expect(screen.getAllByText(/admitted/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/valid/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/invalid/i).length).toBeGreaterThanOrEqual(1);
  });

  it('shows deny-all score as 0%', () => {
    render(<SummaryTablePanel summary={DATASET.summary} illustrative />);
    expect(screen.getByText('0%')).toBeInTheDocument();
  });

  it('shows invalidation-reason table when n_invalid > 0', () => {
    render(<SummaryTablePanel summary={DATASET.summary} illustrative />);
    // DEADLINE_EXCEEDED appears in reasons
    expect(screen.getByText(/defense deadline exceeded/i)).toBeInTheDocument();
  });
});

// ── CovertChannelPanel ────────────────────────────────────────────────────────
describe('CovertChannelPanel', () => {
  it('shows NOT MEASURED when bound_bits_per_query is null', () => {
    render(<CovertChannelPanel card={DATASET.covert_channel} />);
    expect(screen.getByText(/not measured/i)).toBeInTheDocument();
  });

  it('does not use "proves" or "zero leakage" wording', () => {
    const { container } = render(<CovertChannelPanel card={DATASET.covert_channel} />);
    expect(container.textContent?.toLowerCase()).not.toContain('proves');
    expect(container.textContent?.toLowerCase()).not.toContain('zero leakage');
    expect(container.textContent?.toLowerCase()).not.toContain('tamper-proof');
  });
});
