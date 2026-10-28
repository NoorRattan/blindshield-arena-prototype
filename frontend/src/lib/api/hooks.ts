import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { arenaClient } from './client';
import { useArenaStore } from '../../state/useArenaStore';
import type {
  ArenaEvent,
  CreateExperimentRequest,
  Epoch,
  SubmitAttackRequest,
} from '../schemas';

/**
 * React Query hook for all experiments status list (role-filtered)
 */
export function useExperiments() {
  const role = useArenaStore((s) => s.role);
  return useQuery({
    queryKey: ['experiments', role],
    queryFn: () => arenaClient.getExperiments(role),
    staleTime: 5000,
  });
}

/**
 * React Query hook for a single experiment status
 */
export function useExperimentStatus(experimentId: string) {
  const role = useArenaStore((s) => s.role);
  return useQuery({
    queryKey: ['experiment', experimentId, 'status', role],
    queryFn: () => arenaClient.getExperimentStatus(experimentId, role),
    enabled: Boolean(experimentId),
    staleTime: 3000,
  });
}

/**
 * React Query hook for experiment manifest (operator/auditor)
 */
export function useManifest(experimentId: string) {
  const role = useArenaStore((s) => s.role);
  return useQuery({
    queryKey: ['experiment', experimentId, 'manifest', role],
    queryFn: () => arenaClient.getManifest(experimentId, role),
    enabled: Boolean(experimentId) && (role === 'operator' || role === 'auditor'),
  });
}

/**
 * React Query hook for role-filtered feedback items
 */
export function useFeedback(experimentId: string) {
  const role = useArenaStore((s) => s.role);
  return useQuery({
    queryKey: ['experiment', experimentId, 'feedback', role],
    queryFn: () => arenaClient.getFeedback(experimentId, role),
    enabled: Boolean(experimentId),
    staleTime: 3000,
  });
}

/**
 * React Query hook for complete evidence bundle (auditor/operator)
 */
export function useEvidenceBundle(experimentId: string) {
  const role = useArenaStore((s) => s.role);
  return useQuery({
    queryKey: ['experiment', experimentId, 'bundle', role],
    queryFn: () => arenaClient.getEvidenceBundle(experimentId, role),
    enabled: Boolean(experimentId) && (role === 'operator' || role === 'auditor'),
  });
}

/**
 * Mutation hook for Red team attack submissions
 */
export function useSubmitAttack() {
  const queryClient = useQueryClient();
  const role = useArenaStore((s) => s.role);
  const epoch = useArenaStore((s) => s.epoch);

  return useMutation({
    mutationFn: ({
      experimentId,
      request,
      idempotencyKey,
    }: {
      experimentId: string;
      request: SubmitAttackRequest;
      idempotencyKey?: string;
    }) => arenaClient.submitAttack(experimentId, request, idempotencyKey, epoch as Epoch, role),
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['experiment', vars.experimentId] });
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
    },
  });
}

/**
 * Mutation hook for Operator creating a new experiment
 */
export function useCreateExperiment() {
  const queryClient = useQueryClient();
  const role = useArenaStore((s) => s.role);

  return useMutation({
    mutationFn: ({
      request,
      idempotencyKey,
    }: {
      request: CreateExperimentRequest;
      idempotencyKey?: string;
    }) => arenaClient.createExperiment(request, idempotencyKey, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
    },
  });
}

/**
 * Mutation hook for starting an experiment
 */
export function useStartExperiment() {
  const queryClient = useQueryClient();
  const role = useArenaStore((s) => s.role);

  return useMutation({
    mutationFn: (experimentId: string) => arenaClient.startExperiment(experimentId, role),
    onSuccess: (_, expId) => {
      queryClient.invalidateQueries({ queryKey: ['experiment', expId] });
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
    },
  });
}

/**
 * Mutation hook for closing an experiment with signed checkpoint
 */
export function useCloseExperiment() {
  const queryClient = useQueryClient();
  const role = useArenaStore((s) => s.role);

  return useMutation({
    mutationFn: (experimentId: string) => arenaClient.closeExperiment(experimentId, role),
    onSuccess: (_, expId) => {
      queryClient.invalidateQueries({ queryKey: ['experiment', expId] });
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
    },
  });
}

/**
 * Mutation hook for quarantining an experiment domain (operator only)
 */
export function useQuarantineExperiment() {
  const queryClient = useQueryClient();
  const role = useArenaStore((s) => s.role);

  return useMutation({
    mutationFn: ({
      experimentId,
      reason,
    }: {
      experimentId: string;
      reason: string;
    }) => arenaClient.quarantineExperiment(experimentId, reason, role),
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['experiment', vars.experimentId] });
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
    },
  });
}

/**
 * Mutation hook for triggering on-demand re-witness checkpoint
 */
export function useTriggerReWitness() {
  const queryClient = useQueryClient();
  const role = useArenaStore((s) => s.role);

  return useMutation({
    mutationFn: (experimentId: string) => arenaClient.triggerReWitness(experimentId, role),
    onSuccess: (_, expId) => {
      queryClient.invalidateQueries({ queryKey: ['experiment', expId] });
      queryClient.invalidateQueries({ queryKey: ['experiments'] });
    },
  });
}


/**
 * Real-time event stream hook for an active experiment
 */
export function useExperimentEvents(experimentId: string) {
  const role = useArenaStore((s) => s.role);
  const [events, setEvents] = useState<ArenaEvent[]>([]);
  const [latestEvent, setLatestEvent] = useState<ArenaEvent | null>(null);
  const [streamStatus, setStreamStatus] = useState<
    'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING'
  >('CLOSED');
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!experimentId) return;

    setEvents([]);
    setLatestEvent(null);
    setError(null);

    const unsubscribe = arenaClient.subscribeEvents(
      experimentId,
      (event) => {
        setEvents((prev) => [...prev, event]);
        setLatestEvent(event);
      },
      (err) => {
        setError(err);
      },
      (status) => {
        setStreamStatus(status);
      },
      role
    );

    return () => {
      unsubscribe();
    };
  }, [experimentId, role]);

  return {
    events,
    latestEvent,
    streamStatus,
    error,
  };
}
