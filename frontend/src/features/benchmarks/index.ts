// Do NOT re-export lazy-loaded components from this barrel — see FE-L-031
export { BenchmarksPage } from './BenchmarksPage';
export { BenchmarkImportDropzone } from './BenchmarkImportDropzone';
export { AttackSuccessRatePanel } from './AttackSuccessRatePanel';
export { LatencyPanel } from './LatencyPanel';
export { RocPanel, CovertChannelPanel } from './RocAndCovertPanel';
export { SummaryTablePanel } from './SummaryTablePanel';
export { generateIllustrativeBenchmarks } from './benchmarkFixtures';
export * from './benchmarkSchemas';
