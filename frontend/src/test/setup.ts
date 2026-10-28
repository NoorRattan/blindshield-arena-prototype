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
