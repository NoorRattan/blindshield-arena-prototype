import React, { useRef, useState } from 'react';
import { UploadCloud, FileJson, CheckCircle2, AlertCircle, RefreshCw, BarChart2 } from 'lucide-react';
import { Panel } from '../../components/Panel';
import { BenchmarkDatasetSchema } from './benchmarkSchemas';
import type { BenchmarkDataset } from './benchmarkSchemas';

export interface BenchmarkImportDropzoneProps {
  currentDataset: BenchmarkDataset | null;
  fileName: string | null;
  onDatasetLoaded: (dataset: BenchmarkDataset, fileName: string) => void;
  onLoadIllustrative: () => void;
  className?: string;
}

export const BenchmarkImportDropzone: React.FC<BenchmarkImportDropzoneProps> = ({
  currentDataset,
  fileName,
  onDatasetLoaded,
  onLoadIllustrative,
  className,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = (file: File) => {
    setImportError(null);
    if (!file.name.endsWith('.json')) {
      setImportError('Only .json benchmark dataset files are accepted.');
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const raw: unknown = JSON.parse(reader.result as string);
        const parsed = BenchmarkDatasetSchema.parse(raw);
        onDatasetLoaded(parsed, file.name);
      } catch (err) {
        // Surface Zod path info when available
        let msg = err instanceof Error ? err.message : String(err);
        // Zod errors start with a long block — trim to first line for clarity
        const firstLine = msg.split('\n')[0];
        if (firstLine) msg = firstLine;
        setImportError(`Schema validation failed: ${msg}`);
      }
    };
    reader.onerror = () => {
      setImportError('File read error. Please try again.');
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => setIsDragging(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
  };

  return (
    <Panel
      label="00 — BENCHMARK DATASET IMPORT"
      meta="schema: benchmarks.v1 · .json only · Zod-validated at boundary"
      className={className}
    >
      {currentDataset ? (
        /* Loaded state */
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3 font-mono text-sm">
            <CheckCircle2 className="w-5 h-5 text-bl shrink-0" aria-hidden="true" />
            <div>
              <p className="text-tx font-medium">{fileName}</p>
              <p className="text-mut text-xs mt-0.5">
                {currentDataset.illustrative ? (
                  <span className="text-inv">ILLUSTRATIVE</span>
                ) : (
                  <span className="text-bl">MEASURED</span>
                )}{' '}
                · exp: {currentDataset.experiment_id} · {currentDataset.attack_rates.length} attack families
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              id="bench-reset-btn"
              type="button"
              onClick={onLoadIllustrative}
              className="flex items-center gap-1.5 font-mono text-xs text-mut border border-bd px-3 py-1.5 rounded hover:text-tx hover:border-bd-strong transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
            >
              <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
              Reset to illustrative
            </button>
            <button
              id="bench-import-btn"
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center gap-1.5 font-mono text-xs text-tx border border-cy px-3 py-1.5 rounded hover:bg-cy/10 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
            >
              <UploadCloud className="w-3.5 h-3.5" aria-hidden="true" />
              Import new
            </button>
          </div>
        </div>
      ) : (
        /* Drop zone */
        <div
          role="button"
          tabIndex={0}
          aria-label="Benchmark dataset drop zone — drop a .json file or press enter to browse"
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              fileInputRef.current?.click();
            }
          }}
          className={`
            flex flex-col items-center justify-center gap-3 border-2 border-dashed rounded cursor-pointer
            min-h-[140px] transition-colors
            ${isDragging ? 'border-cy bg-cy/5' : 'border-bd hover:border-bd-strong'}
          `}
        >
          <BarChart2 className="w-8 h-8 text-mut" aria-hidden="true" />
          <div className="text-center font-mono">
            <p className="text-sm text-tx">Drop <code className="text-cy">benchmarks.v1</code> JSON here</p>
            <p className="text-xs text-mut mt-1">or click to browse — schema validated, unknown keys rejected</p>
          </div>
        </div>
      )}

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        id="bench-file-input"
        type="file"
        accept=".json,application/json"
        className="sr-only"
        aria-label="Select benchmark JSON file"
        onChange={handleFileChange}
      />

      {/* Load illustrative button (always visible in empty state) */}
      {!currentDataset && (
        <div className="mt-3 flex items-center gap-2">
          <button
            id="bench-load-illustrative-btn"
            type="button"
            onClick={onLoadIllustrative}
            className="flex items-center gap-1.5 font-mono text-xs text-cy border border-cy/50 px-3 py-1.5 rounded hover:bg-cy/10 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
          >
            <FileJson className="w-3.5 h-3.5" aria-hidden="true" />
            Load illustrative dataset
          </button>
          <span className="font-mono text-[11px] text-mut">ILLUSTRATIVE — not a measured result</span>
        </div>
      )}

      {/* Validation error */}
      {importError && (
        <div
          role="alert"
          aria-live="polite"
          className="mt-3 flex items-start gap-2 border border-bad/50 bg-bad/5 px-3 py-2.5 rounded font-mono text-xs text-bad"
        >
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
          <div>
            <p className="font-medium">Import failed</p>
            <p className="text-bad/80 mt-0.5 break-all">{importError}</p>
          </div>
        </div>
      )}
    </Panel>
  );
};
