import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { WarRoomTopBar } from './WarRoomTopBar';
import { FailureInjectionPanel } from './FailureInjectionPanel';
import { PipelineWaterfall } from './PipelineWaterfall';
import type { Attempt } from '../../lib/schemas';

describe('WarRoomTopBar Component', () => {
  it('renders domain, epoch, and dual verdict correctly', () => {
    render(
      <WarRoomTopBar
        experimentId="exp_running_01"
        domain="BAYORA-PROD-01"
        epoch={4}
        lifecycleState="RUNNING"
        integrityStatus="VALID_WITHIN_PROFILE"
        modelOutcome="EXECUTED"
        witnessStatus="SYNCED"
        onQuarantine={vi.fn()}
        onTriggerReWitness={vi.fn()}
      />
    );

    expect(screen.getByText('BAYORA-PROD-01')).toBeInTheDocument();
    expect(screen.getByText(/DOC-WAR-04/)).toBeInTheDocument();
    expect(screen.getByText('04')).toBeInTheDocument();
    expect(screen.getByText('RUNNING')).toBeInTheDocument();
    expect(screen.getByText(/WITNESS:/)).toBeInTheDocument();
  });

  it('opens confirmation modal on Emergency Quarantine and requires typed confirmation', () => {
    const onQuarantine = vi.fn();
    render(
      <WarRoomTopBar
        experimentId="exp_running_01"
        domain="BAYORA-PROD-01"
        epoch={4}
        lifecycleState="RUNNING"
        integrityStatus="VALID_WITHIN_PROFILE"
        modelOutcome="EXECUTED"
        witnessStatus="SYNCED"
        onQuarantine={onQuarantine}
        onTriggerReWitness={vi.fn()}
      />
    );

    const quarantineBtn = screen.getByRole('button', { name: /Emergency Quarantine/i });
    fireEvent.click(quarantineBtn);

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/EMERGENCY STOP & DOMAIN QUARANTINE/)).toBeInTheDocument();

    const confirmBtn = screen.getByRole('button', { name: /Confirm Quarantine/i });
    expect(confirmBtn).toBeDisabled();

    // Type the required confirmation word (placeholder is the confirmWord)
    const input = screen.getByPlaceholderText('QUARANTINE');
    fireEvent.change(input, { target: { value: 'QUARANTINE' } });

    expect(confirmBtn).not.toBeDisabled();
    fireEvent.click(confirmBtn);

    expect(onQuarantine).toHaveBeenCalledWith('OPERATOR_EMERGENCY_QUARANTINE');
  });

  it('triggers onTriggerReWitness on Re-Witness button click', () => {
    const onTriggerReWitness = vi.fn();
    render(
      <WarRoomTopBar
        experimentId="exp_running_01"
        domain="BAYORA-PROD-01"
        epoch={4}
        lifecycleState="RUNNING"
        integrityStatus="VALID_WITHIN_PROFILE"
        modelOutcome="EXECUTED"
        witnessStatus="SYNCED"
        onQuarantine={vi.fn()}
        onTriggerReWitness={onTriggerReWitness}
      />
    );

    const reWitnessBtn = screen.getByRole('button', { name: /Re-Witness/i });
    fireEvent.click(reWitnessBtn);
    expect(onTriggerReWitness).toHaveBeenCalled();
  });

  it('displays alert banner when lifecycleState is INVALID with reason', () => {
    render(
      <WarRoomTopBar
        experimentId="exp_running_01"
        domain="BAYORA-PROD-01"
        epoch={4}
        lifecycleState="INVALID"
        integrityStatus="INVALID"
        modelOutcome="NOT_EVALUATED"
        witnessStatus="SYNCED"
        invalidReason="DEFENSE_BREACH_DETECTED"
        onQuarantine={vi.fn()}
        onTriggerReWitness={vi.fn()}
      />
    );

    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/DEFENSE_BREACH_DETECTED/)).toBeInTheDocument();
  });
});

describe('FailureInjectionPanel Component', () => {
  it('renders all failure injection buttons and triggers callbacks', () => {
    const onSetMode = vi.fn();
    render(
      <FailureInjectionPanel
        currentMode="none"
        onSetFailureMode={onSetMode}
      />
    );

    expect(screen.getByText(/DEMO MODE: FAILURE INJECTION MATRIX/)).toBeInTheDocument();

    const timeoutBtn = screen.getByRole('button', { name: /defense_timeout/i });
    fireEvent.click(timeoutBtn);
    expect(onSetMode).toHaveBeenCalledWith('defense_timeout');

    const recorderBtn = screen.getByRole('button', { name: /recorder_down/i });
    fireEvent.click(recorderBtn);
    expect(onSetMode).toHaveBeenCalledWith('recorder_down');

    const staleBtn = screen.getByRole('button', { name: /stale_epoch/i });
    fireEvent.click(staleBtn);
    expect(onSetMode).toHaveBeenCalledWith('stale_epoch');

    const witnessLagBtn = screen.getByRole('button', { name: /witness_lag/i });
    fireEvent.click(witnessLagBtn);
    expect(onSetMode).toHaveBeenCalledWith('witness_lag');
  });

  it('renders Reset button when active mode is not none', () => {
    const onSetMode = vi.fn();
    render(
      <FailureInjectionPanel
        currentMode="defense_timeout"
        onSetFailureMode={onSetMode}
      />
    );

    const resetBtn = screen.getByRole('button', { name: /Reset/i });
    expect(resetBtn).toBeInTheDocument();
    fireEvent.click(resetBtn);
    expect(onSetMode).toHaveBeenCalledWith('none');
  });
});

describe('PipelineWaterfall Component', () => {
  const mockAttempt: Attempt = {
    request_id: 'req_14',
    turn: 14,
    model_execution: 'EXECUTED',
    scoring: 'SCORED',
    integrity: 'VALID_WITHIN_PROFILE',
    latency_ms: {
      defense: 182,
      target: 614,
      total: 843,
    },
  };

  it('renders 6 pipeline stages with real latencies', () => {
    render(<PipelineWaterfall turn={14} attempt={mockAttempt} />);

    expect(screen.getByTestId('waterfall-stage-red')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-broker')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-blue')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-target')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-scorer')).toBeInTheDocument();
    expect(screen.getByTestId('waterfall-stage-recorder')).toBeInTheDocument();

    const blueStage = screen.getByTestId('waterfall-stage-blue');
    expect(blueStage).toHaveTextContent('182ms');
    const targetStage = screen.getByTestId('waterfall-stage-target');
    expect(targetStage).toHaveTextContent('614ms');
  });

  it('turns blue defense stage into purple timeout when defense_timeout is active', () => {
    render(<PipelineWaterfall turn={14} attempt={mockAttempt} failureMode="defense_timeout" />);

    const blueStage = screen.getByTestId('waterfall-stage-blue');
    expect(blueStage).toHaveClass('border-inv');
    expect(blueStage).toHaveTextContent('TIMEOUT');
    expect(blueStage).toHaveTextContent('1002ms');

    // Target and Scorer should be NOT_EVALUATED
    const targetStage = screen.getByTestId('waterfall-stage-target');
    expect(targetStage).toHaveTextContent('NOT_EVALUATED');
  });
});
