import React, { useState, useCallback } from 'react';
import { BarChart2 } from 'lucide-react';
import { PageHeader } from '../../components/PageHeader';
import { IllustrativeTag } from '../../components/IllustrativeTag';
import { ResidualRiskPanel } from '../../components/ResidualRiskPanel';
import { generateIllustrativeBenchmarks } from './benchmarkFixtures';
import { BenchmarkImportDropzone } from './BenchmarkImportDropzone';
import { AttackSuccessRatePanel } from './AttackSuccessRatePanel';
import { LatencyPanel } from './LatencyPanel';
import { RocPanel, CovertChannelPanel } from './RocAndCovertPanel';
import { SummaryTablePanel } from './SummaryTablePanel';
import type { BenchmarkDataset } from './benchmarkSchemas';

export const BenchmarksPage: React.FC = () => {
  const [dataset, setDataset] = useState<BenchmarkDataset | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);

  const loadIllustrative = useCallback(() => {
    const data = generateIllustrativeBenchmarks();
    setDataset(data);
    setFileName('illustrative-benchmarks.v1.json');
  }, []);

  // Auto-load illustrative on mount for demonstrability
  React.useEffect(() => {
    loadIllustrative();
  }, [loadIllustrative]);

  const handleDatasetLoaded = (d: BenchmarkDataset, name: string) => {
    setDataset(d);
    setFileName(name);
  };

  const now = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC';

  return (
    <div className="px-4 sm:px-6 lg:px-8 py-8 max-w-screen-xl mx-auto space-y-8">
      {/* Page Header */}
      <PageHeader
        docId="DOC-BENCH-07"
        title="BENCHMARK ANALYTICS & CHANNEL CAPACITY"
        description="Attack success rates, latency per path, cache distinguishability (ROC AUC), and covert-channel capacity bound. All numbers are ILLUSTRATIVE until a validated dataset is imported."
        timestamp={now}
        status={
          dataset?.illustrative ? (
            <IllustrativeTag tooltip="No measured data imported — all values are ILLUSTRATIVE" />
          ) : (
            <span className="font-mono text-xs text-bl border border-bl/40 px-2 py-0.5 rounded">
              MEASURED DATA
            </span>
          )
        }
        actions={
          <div className="flex items-center gap-1.5 text-mut font-mono text-[11px]">
            <BarChart2 className="w-4 h-4" aria-hidden="true" />
            <span>OPERATOR · AUDITOR</span>
          </div>
        }
      />

      {/* Global ILLUSTRATIVE banner — required by spec */}
      {dataset?.illustrative && (
        <div
          role="alert"
          aria-live="polite"
          className="border border-inv/40 bg-inv/5 px-4 py-3 rounded font-mono text-xs text-inv flex items-start gap-2.5"
        >
          <IllustrativeTag className="shrink-0 mt-0.5" />
          <p>
            All metrics shown are <strong>ILLUSTRATIVE</strong> — generated from a seeded PRNG,
            not from real model inference or timing measurements. Import a{' '}
            <code>benchmarks.v1</code> JSON file produced by the evaluation pipeline to replace
            these values with measured results.
          </p>
        </div>
      )}

      {/* Import dropzone */}
      <BenchmarkImportDropzone
        currentDataset={dataset}
        fileName={fileName}
        onDatasetLoaded={handleDatasetLoaded}
        onLoadIllustrative={loadIllustrative}
      />

      {dataset && (
        <>
          {/* Row 1: Attack Success Rate */}
          <AttackSuccessRatePanel
            rows={dataset.attack_rates}
            illustrative={dataset.illustrative}
          />

          {/* Row 2: Latency */}
          <LatencyPanel paths={dataset.latency_paths} illustrative={dataset.illustrative} />

          {/* Row 3: Cache Distinguishability ROC */}
          <RocPanel arms={dataset.roc_arms} illustrative={dataset.illustrative} />

          {/* Row 4: Covert-channel + Threat scope */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CovertChannelPanel card={dataset.covert_channel} />
            <ResidualRiskPanel compact />
          </div>

          {/* Row 5: Summary */}
          <SummaryTablePanel summary={dataset.summary} illustrative={dataset.illustrative} />
        </>
      )}
    </div>
  );
};
