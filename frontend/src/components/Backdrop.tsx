import React from 'react';

export const Backdrop: React.FC = () => {
  return (
    <div
      aria-hidden="true"
      className="fixed inset-0 pointer-events-none z-[-10] overflow-hidden select-none"
    >
      {/* Layer (a): Ambient radial glows (cyan top-right 14%, cobalt bottom-left 14%) */}
      <div
        className="absolute inset-0"
        style={{
          background: `
            radial-gradient(ellipse 60% 45% at 85% 15%, color-mix(in srgb, var(--cy) 14%, transparent), transparent 70%),
            radial-gradient(ellipse 55% 45% at 15% 85%, color-mix(in srgb, var(--bl) 14%, transparent), transparent 70%)
          `,
        }}
      />

      {/* Layer (b): Precision grid 56px with radial edge fade and subtle slow drift */}
      <div
        className="backdrop-grid absolute -inset-[56px] opacity-100"
        style={{
          backgroundImage: `
            linear-gradient(to right, color-mix(in srgb, var(--bd) 45%, transparent) 1px, transparent 1px),
            linear-gradient(to bottom, color-mix(in srgb, var(--bd) 45%, transparent) 1px, transparent 1px)
          `,
          backgroundSize: '56px 56px',
          maskImage: 'radial-gradient(circle at 50% 50%, black 35%, transparent 85%)',
          WebkitMaskImage: 'radial-gradient(circle at 50% 50%, black 35%, transparent 85%)',
        }}
      />

      {/* Layer (c): Single scanline sweep (9s) */}
      <div className="backdrop-scanline absolute inset-x-0 h-48 opacity-100" />

      {/* Layer (d): Static film grain via procedural SVG noise */}
      <svg
        className="absolute inset-0 w-full h-full opacity-[0.03] mix-blend-screen"
        xmlns="http://www.w3.org/2000/svg"
      >
        <filter id="backdrop-noise-filter">
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.75"
            numOctaves="3"
            stitchTiles="stitch"
          />
        </filter>
        <rect width="100%" height="100%" filter="url(#backdrop-noise-filter)" />
      </svg>

      <style>{`
        @keyframes backdropDrift {
          0% { transform: translate(0, 0); }
          50% { transform: translate(28px, 28px); }
          100% { transform: translate(0, 0); }
        }
        @keyframes scanlineSweep {
          0% { transform: translateY(-100%); opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { transform: translateY(100vh); opacity: 0; }
        }
        .backdrop-grid {
          animation: backdropDrift 40s linear infinite;
        }
        .backdrop-scanline {
          background: linear-gradient(
            to bottom,
            transparent,
            color-mix(in srgb, var(--cy) 10%, transparent) 50%,
            transparent
          );
          animation: scanlineSweep 9s linear infinite;
        }
        @media (prefers-reduced-motion: reduce) {
          .backdrop-grid,
          .backdrop-scanline {
            animation: none !important;
          }
        }
      `}</style>
    </div>
  );
};
