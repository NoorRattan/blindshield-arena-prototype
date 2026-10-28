import type { ArenaEvent, Epoch, Role } from '../schemas';
import type { MockArenaServer } from './server';

export interface SseError extends Error {
  code?: string;
}

export type FailureMode =
  | 'none'
  | 'defense_timeout'
  | 'recorder_down'
  | 'stale_epoch'
  | 'witness_lag'
  | 'reconnect'
  | 'audit_unavailable';

export interface SseSubscriptionOptions {
  experimentId: string;
  role: Role;
  onEvent: (event: ArenaEvent) => void;
  onError?: (err: Error) => void;
  onStatusChange?: (status: 'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING') => void;
}

export class SseSimulator {
  private activeIntervals: Map<string, number> = new Map();
  private failureMode: FailureMode = 'none';

  constructor(private server: MockArenaServer) {}

  setFailureMode(mode: FailureMode): void {
    this.failureMode = mode;
  }

  getFailureMode(): FailureMode {
    return this.failureMode;
  }

  /**
   * Subscribes to an experiment event stream.
   * Emits events at periodic intervals (~0.4 - 2.5s jitter).
   * Respects role boundaries: non-operators do not receive raw internal payload text.
   */
  subscribe(options: SseSubscriptionOptions): () => void {
    const { experimentId, role, onEvent, onError, onStatusChange } = options;
    const subId = `sub_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

    // Immediate error if recorder is down
    if (this.failureMode === 'recorder_down') {
      const err: SseError = new Error('AUDIT_UNAVAILABLE: Recorder storage unreachable');
      err.code = 'AUDIT_UNAVAILABLE';
      onError?.(err);
      onStatusChange?.('CLOSED');
      return () => {};
    }

    if (this.failureMode === 'witness_lag') {
      onStatusChange?.('LAGGING');
    } else {
      onStatusChange?.('CONNECTED');
    }

    let eventSeq = 0;
    let reconnectAttempts = 0;

    const tick = () => {
      // Simulate reconnect failure mode
      if (this.failureMode === 'reconnect' && eventSeq === 1 && reconnectAttempts === 0) {
        reconnectAttempts++;
        onStatusChange?.('RECONNECTING');
        onError?.(new Error('SSE connection dropped; reconnecting...'));
        const timeoutId = window.setTimeout(() => {
          onStatusChange?.('CONNECTED');
          scheduleNext();
        }, 800);
        this.activeIntervals.set(subId, timeoutId);
        return;
      }

      try {
        const arena = this.server.getRawArena(experimentId);
        if (arena && arena.ledger.length > 0) {
          const index = eventSeq % arena.ledger.length;
          let event: ArenaEvent = arena.ledger[index];

          // Simulate stale epoch injection if configured
          if (this.failureMode === 'stale_epoch') {
            const staleEpoch = (arena.epoch - 1 > 0 ? arena.epoch - 1 : 1) as Epoch;
            event = {
              ...event,
              epoch: staleEpoch,
            };
          }

          // Simulate defense timeout injection
          if (this.failureMode === 'defense_timeout') {
            event = {
              ...event,
              actor: 'blue',
              action: 'defense_deadline_exceeded',
              outcome: 'DEADLINE_EXCEEDED',
            };
          }

          // Role filtering on streamed event: non-operators receive sanitized actions
          if (role !== 'operator') {
            event = {
              ...event,
              // Withhold internal artifact hashes from red/blue if not released
              artifacts: arena.state === 'RELEASED' ? event.artifacts : [],
            };
          }

          onEvent(event);
          eventSeq++;
        }
      } catch (err) {
        onError?.(err instanceof Error ? err : new Error(String(err)));
      }

      scheduleNext();
    };

    const scheduleNext = () => {
      // Periodic jitter between 400ms and 2000ms
      const delay = Math.floor(Math.random() * 1600) + 400;
      const timeoutId = window.setTimeout(tick, delay);
      this.activeIntervals.set(subId, timeoutId);
    };

    // First emission after a short initial tick (200ms)
    const initialTimeoutId = window.setTimeout(tick, 200);
    this.activeIntervals.set(subId, initialTimeoutId);

    // Unsubscribe cleanup function
    return () => {
      const activeTimer = this.activeIntervals.get(subId);
      if (activeTimer !== undefined) {
        clearTimeout(activeTimer);
        this.activeIntervals.delete(subId);
      }
      onStatusChange?.('CLOSED');
    };
  }

  /**
   * Cleans up all active subscriptions
   */
  destroy(): void {
    for (const timeoutId of this.activeIntervals.values()) {
      clearTimeout(timeoutId);
    }
    this.activeIntervals.clear();
  }
}
