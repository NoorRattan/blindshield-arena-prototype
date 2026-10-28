import '@testing-library/jest-dom/vitest';

// Polyfill window.matchMedia for jsdom tests
if (typeof window !== 'undefined' && !window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}

// Polyfill requestAnimationFrame on root global for GSAP / ScrollTrigger timers in jsdom/node
try {
  const rootGlobal = new Function('return this')();
  if (rootGlobal && typeof rootGlobal.requestAnimationFrame === 'undefined') {
    rootGlobal.requestAnimationFrame = (callback: (time: number) => void) => {
      return setTimeout(() => callback(Date.now()), 0);
    };
    rootGlobal.cancelAnimationFrame = (id: number) => {
      clearTimeout(id);
    };
  }
} catch {
  // ignore
}

// Polyfill ResizeObserver for jsdom tests (Recharts ResponsiveContainer)
if (typeof window !== 'undefined' && !window.ResizeObserver) {
  class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  window.ResizeObserver = ResizeObserver;
}

// Polyfill in-memory Storage for Node 22+ environments where globalThis.localStorage is undefined
class InMemoryStorage implements Storage {
  private store: Record<string, string> = {};

  get length(): number {
    return Object.keys(this.store).length;
  }

  clear(): void {
    this.store = {};
  }

  getItem(key: string): string | null {
    return this.store[key] ?? null;
  }

  key(index: number): string | null {
    return Object.keys(this.store)[index] ?? null;
  }

  removeItem(key: string): void {
    delete this.store[key];
  }

  setItem(key: string, value: string): void {
    this.store[key] = String(value);
  }
}

try {
  const mockLocalStorage = new InMemoryStorage();
  const mockSessionStorage = new InMemoryStorage();

  Object.defineProperty(globalThis, 'localStorage', {
    value: mockLocalStorage,
    configurable: true,
    writable: true,
  });

  Object.defineProperty(globalThis, 'sessionStorage', {
    value: mockSessionStorage,
    configurable: true,
    writable: true,
  });

  if (typeof window !== 'undefined') {
    Object.defineProperty(window, 'localStorage', {
      value: mockLocalStorage,
      configurable: true,
      writable: true,
    });
    Object.defineProperty(window, 'sessionStorage', {
      value: mockSessionStorage,
      configurable: true,
      writable: true,
    });
  }
} catch {
  // ignore
}

// Historical visual component tests explicitly inject their in-memory fixture.
// Production exports remain LiveArenaClient; no runtime simulation switch exists.
import { beforeEach, vi } from 'vitest';
import { useArenaStore } from '../state/useArenaStore';
vi.mock('../lib/api/client', async () => {
  const actual = await vi.importActual<typeof import('../lib/api/client')>('../lib/api/client');
  return { ...actual, arenaClient: new actual.DynamicArenaClient() };
});
beforeEach(() => {
  useArenaStore.setState({ connectionMode: 'simulated', domain: 'BAYORA-PROD-01', epoch: 4, witnessStatus: 'SYNCED' });
});
