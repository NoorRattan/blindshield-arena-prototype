import React from 'react';

export interface ArenaHero2DFallbackProps {
  activeNode?: 'red' | 'broker' | 'blue' | 'target' | 'scorer' | 'witness' | null;
  className?: string;
}

/**
 * 2D SVG Architectural Topology Fallback
 * Renders when WebGL is unavailable, in reduced-motion mode, or in test environments.
 */
export const ArenaHero2DFallback: React.FC<ArenaHero2DFallbackProps> = ({
  activeNode = 'broker',
  className = '',
}) => {
  return (
    <div
      className={`relative w-full h-full flex items-center justify-center select-none ${className}`}
      role="img"
      aria-label="BlindShield Arena Topology Diagram: Broker core, isolated tenant lanes, and witnessed evidence chain"
    >
      <svg
        viewBox="0 0 500 500"
        className="w-full h-full max-h-[460px] overflow-visible"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <radialGradient id="broker-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#00E5FF" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#00E5FF" stopOpacity="0" />
          </radialGradient>
          <filter id="cyan-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Orbit Rings (tilted ellipses) */}
        {/* Ring 1: Red & Blue lane orbit */}
        <ellipse
          cx="250"
          cy="250"
          rx="170"
          ry="75"
          fill="none"
          stroke="#232D42"
          strokeWidth="1.2"
          strokeDasharray="4 4"
          transform="rotate(-25 250 250)"
        />

        {/* Ring 2: Target & Scorer lane orbit */}
        <ellipse
          cx="250"
          cy="250"
          rx="210"
          ry="90"
          fill="none"
          stroke="#34425F"
          strokeWidth="1"
          strokeDasharray="6 3"
          transform="rotate(35 250 250)"
        />

        {/* Outer Ring: 24 Evidence blocks */}
        <circle
          cx="250"
          cy="250"
          r="230"
          fill="none"
          stroke="#232D42"
          strokeWidth="0.8"
          strokeDasharray="2 4"
        />

        {/* 24 Evidence Blocks arranged along outer perimeter */}
        {Array.from({ length: 24 }).map((_, i) => {
          const angle = (i * 2 * Math.PI) / 24;
          const x = 250 + 230 * Math.cos(angle);
          const y = 250 + 230 * Math.sin(angle);
          const isWitnessStep = activeNode === 'witness';
          return (
            <rect
              key={i}
              x={x - 4}
              y={y - 4}
              width="8"
              height="8"
              fill={isWitnessStep ? '#00E676' : '#161D2E'}
              stroke={isWitnessStep ? '#00E676' : '#34425F'}
              strokeWidth="1"
              transform={`rotate(${(angle * 180) / Math.PI + 45} ${x} ${y})`}
            />
          );
        })}

        {/* Central Broker Glow & Icosahedron Representation */}
        <circle cx="250" cy="250" r="60" fill="url(#broker-glow)" />

        {/* Outer wire polygon representing Broker */}
        <polygon
          points="250,195 295,220 295,280 250,305 205,280 205,220"
          fill="#0E131F"
          stroke={activeNode === 'broker' ? '#00E5FF' : '#34425F'}
          strokeWidth={activeNode === 'broker' ? '2.5' : '1.5'}
          filter={activeNode === 'broker' ? 'url(#cyan-glow)' : undefined}
        />
        {/* Inner wire lines for icosahedral faceted look */}
        <line x1="250" y1="195" x2="250" y2="305" stroke="#00E5FF" strokeWidth="0.8" strokeOpacity="0.4" />
        <line x1="205" y1="220" x2="295" y2="280" stroke="#00E5FF" strokeWidth="0.8" strokeOpacity="0.4" />
        <line x1="205" y1="280" x2="295" y2="220" stroke="#00E5FF" strokeWidth="0.8" strokeOpacity="0.4" />
        <circle cx="250" cy="250" r="12" fill="#00E5FF" fillOpacity="0.25" stroke="#00E5FF" strokeWidth="1.5" />
        <text
          x="250"
          y="253"
          textAnchor="middle"
          fill="#00E5FF"
          fontSize="9"
          fontFamily="DM Mono, monospace"
          letterSpacing="0.1em"
        >
          BROKER
        </text>

        {/* Node 1: Red Team (Top Left on Ring 1) */}
        <g transform="translate(130, 190)">
          <circle
            cx="0"
            cy="0"
            r={activeNode === 'red' ? 18 : 14}
            fill="#0E131F"
            stroke="#FF9100"
            strokeWidth={activeNode === 'red' ? 2.5 : 1.5}
          />
          <circle cx="0" cy="0" r="5" fill="#FF9100" />
          <text
            x="0"
            y="-22"
            textAnchor="middle"
            fill="#FF9100"
            fontSize="10"
            fontFamily="DM Mono, monospace"
            fontWeight="500"
            letterSpacing="0.1em"
          >
            RED NODE
          </text>
        </g>

        {/* Node 2: Blue Defense (Bottom Right on Ring 1) */}
        <g transform="translate(370, 310)">
          <circle
            cx="0"
            cy="0"
            r={activeNode === 'blue' ? 18 : 14}
            fill="#0E131F"
            stroke="#2979FF"
            strokeWidth={activeNode === 'blue' ? 2.5 : 1.5}
          />
          <circle cx="0" cy="0" r="5" fill="#2979FF" />
          <text
            x="0"
            y="30"
            textAnchor="middle"
            fill="#2979FF"
            fontSize="10"
            fontFamily="DM Mono, monospace"
            fontWeight="500"
            letterSpacing="0.1em"
          >
            FROZEN BLUE
          </text>
        </g>

        {/* Node 3: Target Model (Top Right on Ring 2) */}
        <g transform="translate(385, 175)">
          <circle
            cx="0"
            cy="0"
            r={activeNode === 'target' ? 18 : 14}
            fill="#0E131F"
            stroke="#00E676"
            strokeWidth={activeNode === 'target' ? 2.5 : 1.5}
          />
          <circle cx="0" cy="0" r="5" fill="#00E676" />
          <text
            x="0"
            y="-22"
            textAnchor="middle"
            fill="#00E676"
            fontSize="10"
            fontFamily="DM Mono, monospace"
            fontWeight="500"
            letterSpacing="0.1em"
          >
            TARGET MODEL
          </text>
        </g>

        {/* Node 4: Scorer / Witness (Bottom Left on Ring 2) */}
        <g transform="translate(115, 325)">
          <circle
            cx="0"
            cy="0"
            r={activeNode === 'scorer' ? 18 : 14}
            fill="#0E131F"
            stroke={activeNode === 'scorer' ? '#00E5FF' : '#8A97AD'}
            strokeWidth={activeNode === 'scorer' ? 2.5 : 1.5}
          />
          <circle cx="0" cy="0" r="5" fill={activeNode === 'scorer' ? '#00E5FF' : '#8A97AD'} />
          <text
            x="0"
            y="30"
            textAnchor="middle"
            fill="#8A97AD"
            fontSize="10"
            fontFamily="DM Mono, monospace"
            fontWeight="500"
            letterSpacing="0.1em"
          >
            SCORER
          </text>
        </g>

        {/* Connecting Hairline Vectors */}
        <path
          d="M 130 190 Q 190 220 205 235"
          fill="none"
          stroke="#FF9100"
          strokeWidth="1"
          strokeDasharray="3 3"
          strokeOpacity="0.6"
        />
        <path
          d="M 295 265 Q 330 280 370 310"
          fill="none"
          stroke="#2979FF"
          strokeWidth="1"
          strokeDasharray="3 3"
          strokeOpacity="0.6"
        />
      </svg>
    </div>
  );
};
