import React, { useState } from 'react';
import { ChevronLeft, ChevronRight, CheckCircle2 } from 'lucide-react';
import { Stepper, type StepItem } from '../../../components/Stepper';
import { Panel } from '../../../components/Panel';
import type { SetupFormData, SetupFieldErrors } from '../types';
import { Step1DomainEpoch } from './Step1DomainEpoch';
import { Step2TargetInference } from './Step2TargetInference';
import { Step3BlueDefense } from './Step3BlueDefense';
import { Step4RedConstraints } from './Step4RedConstraints';
import { Step5DisclosurePolicy } from './Step5DisclosurePolicy';

interface SetupWizardProps {
  formData: SetupFormData;
  errors: SetupFieldErrors;
  onChange: (updates: Partial<SetupFormData>) => void;
  onValidateStep: (stepIndex: number) => boolean;
  onAllStepsValidated: () => void;
}

const STEP_LABELS = [
  { id: 'step-1', label: '1. Domain & Epoch', description: 'Namespace & Epoch' },
  { id: 'step-2', label: '2. Target Inference', description: 'Model & Engine' },
  { id: 'step-3', label: '3. Blue Defense', description: 'Image & Deadlines' },
  { id: 'step-4', label: '4. Red Constraints', description: 'Limits & Lane' },
  { id: 'step-5', label: '5. Disclosure Policy', description: 'Feedback Mode' },
];

export const SetupWizard: React.FC<SetupWizardProps> = ({
  formData,
  errors,
  onChange,
  onValidateStep,
  onAllStepsValidated,
}) => {
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [visitedSteps, setVisitedSteps] = useState<Set<number>>(new Set([0]));

  const handleNext = () => {
    const isValid = onValidateStep(currentStep);
    if (!isValid) return;

    if (currentStep < STEP_LABELS.length - 1) {
      const next = currentStep + 1;
      setCurrentStep(next);
      setVisitedSteps((prev) => new Set([...prev, next]));
    } else {
      onAllStepsValidated();
    }
  };

  const handlePrev = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleStepClick = (index: number) => {
    // Can only jump to a step if previous steps are valid
    if (index < currentStep) {
      setCurrentStep(index);
    } else if (index > currentStep) {
      // Validate all steps between current and target
      let canJump = true;
      for (let i = currentStep; i < index; i++) {
        if (!onValidateStep(i)) {
          canJump = false;
          setCurrentStep(i);
          break;
        }
      }
      if (canJump) {
        setCurrentStep(index);
        setVisitedSteps((prev) => new Set([...prev, index]));
      }
    }
  };

  const stepsData: StepItem[] = STEP_LABELS.map((item, idx) => {
    let status: StepItem['status'] = 'pending';
    if (idx === currentStep) {
      status = 'active';
    } else if (idx < currentStep || visitedSteps.has(idx)) {
      status = 'completed';
    }
    return {
      id: item.id,
      label: item.label,
      description: item.description,
      status,
    };
  });

  return (
    <Panel
      label={`01 — EXPERIMENT WIZARD · STEP ${currentStep + 1} OF 5`}
      meta="OPERATOR CONSOLE"
      className="p-5"
    >
      {/* Stepper Navigation Strip */}
      <div className="mb-6 pb-4 border-b border-bd overflow-x-auto">
        <Stepper steps={stepsData} orientation="horizontal" />
      </div>

      {/* Interactive Step Buttons for Keyboard & Direct Navigation */}
      <div className="flex items-center gap-1.5 mb-6 overflow-x-auto pb-1" role="tablist" aria-label="Wizard Steps">
        {STEP_LABELS.map((s, idx) => (
          <button
            key={s.id}
            role="tab"
            aria-selected={currentStep === idx}
            onClick={() => handleStepClick(idx)}
            className={`px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider rounded-[2px] transition-colors whitespace-nowrap focus:outline-none focus:ring-1 focus:ring-cy ${
              currentStep === idx
                ? 'bg-cy text-[#080B10] font-bold'
                : visitedSteps.has(idx)
                  ? 'bg-s2 text-tx border border-bd hover:border-cy/50'
                  : 'bg-s1 text-mut border border-bd hover:text-tx'
            }`}
          >
            {s.label}
          </button>
        ))}
      </div>

      {/* Step Form Body */}
      <div className="min-h-[300px]">
        {currentStep === 0 && (
          <Step1DomainEpoch formData={formData} errors={errors} onChange={onChange} />
        )}
        {currentStep === 1 && (
          <Step2TargetInference formData={formData} errors={errors} onChange={onChange} />
        )}
        {currentStep === 2 && (
          <Step3BlueDefense formData={formData} errors={errors} onChange={onChange} />
        )}
        {currentStep === 3 && (
          <Step4RedConstraints formData={formData} errors={errors} onChange={onChange} />
        )}
        {currentStep === 4 && (
          <Step5DisclosurePolicy formData={formData} onChange={onChange} />
        )}
      </div>

      {/* Navigation Footer */}
      <div className="mt-8 pt-4 border-t border-bd flex items-center justify-between">
        <button
          type="button"
          onClick={handlePrev}
          disabled={currentStep === 0}
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-s2 border border-bd text-tx font-mono text-xs uppercase tracking-wider rounded-[2px] hover:border-cy disabled:opacity-40 disabled:cursor-not-allowed transition-colors focus:outline-none focus:ring-1 focus:ring-cy"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
          Previous
        </button>

        <span className="font-mono text-xs text-mut tabular-nums">
          STEP {currentStep + 1} / {STEP_LABELS.length}
        </span>

        {currentStep < STEP_LABELS.length - 1 ? (
          <button
            type="button"
            onClick={handleNext}
            className="inline-flex items-center gap-1.5 px-5 py-2 bg-cy text-[#080B10] font-mono text-xs uppercase tracking-wider font-bold rounded-[2px] hover:brightness-110 transition-colors focus:outline-none focus:ring-2 focus:ring-cy focus:ring-offset-2 focus:ring-offset-bg"
          >
            Next Step
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        ) : (
          <button
            type="button"
            onClick={handleNext}
            className="inline-flex items-center gap-1.5 px-5 py-2 bg-ok text-[#080B10] font-mono text-xs uppercase tracking-wider font-bold rounded-[2px] hover:brightness-110 transition-colors focus:outline-none focus:ring-2 focus:ring-ok focus:ring-offset-2 focus:ring-offset-bg"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            Validate & Review Preflight
          </button>
        )}
      </div>
    </Panel>
  );
};
