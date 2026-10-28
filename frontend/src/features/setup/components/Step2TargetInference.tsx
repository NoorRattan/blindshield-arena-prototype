import React from 'react';
import type { SetupFormData, SetupFieldErrors } from '../types';

interface Step2Props {
  formData: SetupFormData;
  errors: SetupFieldErrors;
  onChange: (updates: Partial<SetupFormData>) => void;
}

export const Step2TargetInference: React.FC<Step2Props> = ({
  formData,
  errors,
  onChange,
}) => {
  return (
    <div className="space-y-6">
      {/* Target Model Selection */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="target-model-select"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            01. Target Model Under Evaluation
          </label>
          <span className="font-mono text-[11px] text-mut">ISOLATED LANE</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Frozen target model weights executed inside isolated tenant container.
        </p>
        <select
          id="target-model-select"
          value={formData.target_model}
          onChange={(e) => onChange({ target_model: e.target.value })}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        >
          <option value="qwen-2.5-0.5b-instruct">qwen-2.5-0.5b-instruct (Qwen 2.5 0.5B Instruct, Apache-2.0 portable baseline)</option>
          <option value="smollm2-360m-instruct">smollm2-360m-instruct (HuggingFace SmolLM2 360M Instruct, fallback)</option>
          <option value="llama-3-8b-instruct-q4">llama-3-8b-instruct-q4 (Meta Llama 3 8B Instruct, AWQ Q4)</option>
          <option value="mistral-7b-instruct-v0.2">mistral-7b-instruct-v0.2 (Mistral AI 7B Instruct v0.2)</option>
          <option value="gemma-2-9b-it">gemma-2-9b-it (Google Gemma 2 9B Instruction Tuned)</option>
          <option value="qwen-2.5-7b-instruct">qwen-2.5-7b-instruct (Alibaba Qwen 2.5 7B Instruct)</option>
        </select>
      </div>

      {/* Inference Engine Runtime */}
      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="inference-engine-select"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            02. Serving Engine & Runtime
          </label>
          <span className="font-mono text-[11px] text-mut">FROZEN RUNTIME</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Inference serving stack with prefix caching and kernel-level timing envelopes.
        </p>
        <select
          id="inference-engine-select"
          value={formData.inference_engine}
          onChange={(e) => onChange({ inference_engine: e.target.value })}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        >
          <option value="llama.cpp-server">llama.cpp-server (CPU-first pinned process, 3 isolated lanes)</option>
          <option value="vllm-v0.6.2">vllm-v0.6.2 (PagedAttention + CUDA Graphs)</option>
          <option value="tgi-v2.3">tgi-v2.3 (HuggingFace Text Generation Inference)</option>
          <option value="sglang-v0.3">sglang-v0.3 (Structured Decoding Engine)</option>
        </select>
      </div>

      {/* Target Deadlines and Token Limits */}
      <div className="pt-4 border-t border-bd grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label
              htmlFor="target-deadline-input"
              className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
            >
              Target Deadline
            </label>
            <span className="font-mono text-[10px] text-cy bg-cy/10 border border-cy/30 px-1.5 py-0.5 rounded uppercase tracking-wider">TARGET DEFAULT</span>
          </div>
          <p className="font-sans text-xs text-mut mb-2">
            Max time before target inference attempt times out.
          </p>
          <div className="relative">
            <input
              id="target-deadline-input"
              type="number"
              min="1000"
              step="1000"
              value={formData.target_deadline_ms}
              onChange={(e) => onChange({ target_deadline_ms: Number(e.target.value) })}
              className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
            />
            <span className="absolute right-3 top-2.5 font-mono text-xs text-dim">ms</span>
          </div>
          {errors.target_deadline_ms && (
            <p className="font-mono text-xs text-bad mt-1.5">⚠ {errors.target_deadline_ms}</p>
          )}
        </div>

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label
              htmlFor="output-tokens-input"
              className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
            >
              Max Output Tokens
            </label>
            <span className="font-mono text-[10px] text-cy bg-cy/10 border border-cy/30 px-1.5 py-0.5 rounded uppercase tracking-wider">TARGET DEFAULT</span>
          </div>
          <p className="font-sans text-xs text-mut mb-2">
            Target token generation cap per turn.
          </p>
          <div className="relative">
            <input
              id="output-tokens-input"
              type="number"
              min="1"
              max="2048"
              step="1"
              value={formData.output_max_tokens}
              onChange={(e) => onChange({ output_max_tokens: Number(e.target.value) })}
              className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
            />
            <span className="absolute right-3 top-2.5 font-mono text-xs text-dim">tokens</span>
          </div>
          {errors.output_max_tokens && (
            <p className="font-mono text-xs text-bad mt-1.5">⚠ {errors.output_max_tokens}</p>
          )}
        </div>
      </div>
    </div>
  );
};
