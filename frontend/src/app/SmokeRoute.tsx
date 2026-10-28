import React, { useEffect } from 'react';

export const SmokeRoute: React.FC = () => {
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
  }, []);

  return (
    <div
      id="smoke-root"
      className="bg-bg text-tx p-8 transition-colors duration-200 flex flex-col justify-between"
    >
      <div className="border-b border-bd pb-4 mb-8 flex justify-between items-center">
        <div>
          <span className="font-mono text-xs uppercase tracking-widest text-mut">
            SYSTEM BOOTSTRAP · SMR-01
          </span>
          <h1 className="text-5xl font-display tracking-wider text-tx mt-1">
            BLINDSHIELD ARENA
          </h1>
        </div>

        <div
          id="smoke-theme-badge"
          className="px-4 py-2 text-xs font-mono uppercase tracking-wider bg-s2 border border-bd text-tx"
          aria-label="Theme mode: dark"
        >
          THEME: <span className="text-cy font-bold">DARK (EXCLUSIVE)</span>
        </div>
      </div>

      <section className="space-y-6 max-w-4xl">
        {/* Bebas Neue Demonstration */}
        <div className="border border-bd p-6 bg-s1">
          <p className="font-mono text-xs text-mut uppercase tracking-wider mb-2">
            01 — DISPLAY TYPOGRAPHY · BEBAS NEUE
          </p>
          <p className="font-display text-4xl text-tx">
            OPERATOR / PARTICIPANT / AUDITOR CONSOLE
          </p>
        </div>

        {/* Barlow Demonstration */}
        <div className="border border-bd p-6 bg-s1">
          <p className="font-mono text-xs text-mut uppercase tracking-wider mb-2">
            02 — BODY TYPOGRAPHY · BARLOW
          </p>
          <p className="font-body text-base text-tx leading-relaxed">
            Infrastructure assurance around an adversarial Red/Blue evaluation loop for AI safety testing.
            Two outcomes are produced: what happened to the model, and whether the experiment stayed valid.
          </p>
        </div>

        {/* DM Mono Demonstration */}
        <div className="border border-bd p-6 bg-s1">
          <p className="font-mono text-xs text-mut uppercase tracking-wider mb-2">
            03 — MONO TYPOGRAPHY · DM MONO (TABULAR NUMS)
          </p>
          <div className="font-mono text-sm space-y-1 text-tx">
            <p>EPOCH: <span className="text-cy">0001</span> · TARGET TIMEOUT: 30,000ms</p>
            <p className="text-mut text-xs truncate">
              GENESIS DIGEST: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            </p>
          </div>
        </div>
      </section>

      <div className="mt-8 pt-4 border-t border-bd text-xs font-mono text-mut flex justify-between">
        <span>STATUS: BOOTSTRAPPED</span>
        <span>VERIFICATION PIPELINE ACTIVE</span>
      </div>
    </div>
  );
};
