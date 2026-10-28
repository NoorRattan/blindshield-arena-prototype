import React, { useRef, useMemo, useEffect, useState } from 'react';
import { Canvas, useFrame, ThreeEvent } from '@react-three/fiber';
import * as THREE from 'three';
import type { ArenaEvent } from '../../lib/schemas';

interface EvidenceChain3DSceneProps {
  ledger: ArenaEvent[];
  brokenIndex?: number;
  selectedSeq?: number;
  onSelectEvent: (event: ArenaEvent) => void;
  className?: string;
}

const PALETTE = {
  emerald: new THREE.Color('#00E676'),
  cyan: new THREE.Color('#00E5FF'),
  amber: new THREE.Color('#FF9100'),
  blue: new THREE.Color('#2979FF'),
  purple: new THREE.Color('#EA80FC'),
  darkPurple: new THREE.Color('#8E00A8'),
  line: new THREE.Color('#232D42'),
  lineBroken: new THREE.Color('#FF1744'),
};

const HelixSceneContent: React.FC<{
  ledger: ArenaEvent[];
  brokenIndex?: number;
  selectedSeq?: number;
  onSelectEvent: (event: ArenaEvent) => void;
}> = ({ ledger, brokenIndex, selectedSeq, onSelectEvent }) => {
  const meshRef = useRef<THREE.InstancedMesh>(null);
  const groupRef = useRef<THREE.Group>(null);
  const mouseRef = useRef({ x: 0, y: 0 });

  // Gentle pointer parallax (max 6 deg ~ 0.1 rad)
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current.x = (e.clientX / window.innerWidth) * 2 - 1;
      mouseRef.current.y = -(e.clientY / window.innerHeight) * 2 + 1;
    };
    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  // Compute block positions along a gentle helix
  const { positions, linePositions, lineColors } = useMemo(() => {
    const count = ledger.length;
    const posList: THREE.Vector3[] = [];
    const lineCoords: number[] = [];
    const lineColArray: number[] = [];

    const radius = 3.2;
    const angleStep = 0.32;
    const heightStep = 0.22;

    for (let i = 0; i < count; i++) {
      const angle = i * angleStep;
      let x = Math.cos(angle) * radius;
      let z = Math.sin(angle) * radius;
      let y = (i - count / 2) * heightStep;

      // Tamper dislocation if past broken index
      if (brokenIndex !== undefined && i >= brokenIndex) {
        const offset = Math.sin(i * 1.5) * 0.9 + 0.6;
        x += Math.cos(angle + 1.2) * offset;
        z += Math.sin(angle + 1.2) * offset;
        y += (i - brokenIndex) * 0.08;
      }

      posList.push(new THREE.Vector3(x, y, z));

      // Connecting line segment to next block
      if (i < count - 1) {
        const nextAngle = (i + 1) * angleStep;
        let nx = Math.cos(nextAngle) * radius;
        let nz = Math.sin(nextAngle) * radius;
        let ny = (i + 1 - count / 2) * heightStep;

        if (brokenIndex !== undefined && i + 1 >= brokenIndex) {
          const nextOffset = Math.sin((i + 1) * 1.5) * 0.9 + 0.6;
          nx += Math.cos(nextAngle + 1.2) * nextOffset;
          nz += Math.sin(nextAngle + 1.2) * nextOffset;
          ny += (i + 1 - brokenIndex) * 0.08;
        }

        const isRupturedLink = brokenIndex !== undefined && i === brokenIndex - 1;

        lineCoords.push(x, y, z, nx, ny, nz);
        const col = isRupturedLink ? PALETTE.lineBroken : PALETTE.line;
        lineColArray.push(col.r, col.g, col.b, col.r, col.g, col.b);
      }
    }

    return {
      positions: posList,
      linePositions: new Float32Array(lineCoords),
      lineColors: new Float32Array(lineColArray),
    };
  }, [ledger, brokenIndex]);

  // Update instanced mesh matrices and colors
  useEffect(() => {
    if (!meshRef.current) return;
    const dummy = new THREE.Object3D();

    for (let i = 0; i < ledger.length; i++) {
      const pos = positions[i];
      if (!pos) continue;

      dummy.position.copy(pos);
      // Gentle orientation facing center
      dummy.lookAt(0, pos.y, 0);
      dummy.updateMatrix();
      meshRef.current.setMatrixAt(i, dummy.matrix);

      // Color mapping
      const event = ledger[i];
      let color = PALETTE.emerald;

      if (brokenIndex !== undefined && i === brokenIndex) {
        color = PALETTE.purple;
      } else if (brokenIndex !== undefined && i > brokenIndex) {
        color = PALETTE.darkPurple;
      } else if (selectedSeq === event.seq) {
        color = PALETTE.cyan;
      } else if (event.actor === 'red') {
        color = PALETTE.amber;
      } else if (event.actor === 'blue') {
        color = PALETTE.blue;
      } else if (event.actor === 'operator') {
        color = PALETTE.cyan;
      }

      meshRef.current.setColorAt(i, color);
    }

    meshRef.current.instanceMatrix.needsUpdate = true;
    if (meshRef.current.instanceColor) {
      meshRef.current.instanceColor.needsUpdate = true;
    }
  }, [ledger, positions, brokenIndex, selectedSeq]);

  // Smooth rotation and pointer parallax
  useFrame((_, delta) => {
    if (groupRef.current) {
      // Slow continuous rotation around Y
      groupRef.current.rotation.y += delta * 0.12;

      // Parallax damping (max ~0.1 rad / 6 deg)
      const targetRotX = mouseRef.current.y * 0.1;
      const targetRotZ = -mouseRef.current.x * 0.08;
      groupRef.current.rotation.x += (targetRotX - groupRef.current.rotation.x) * 0.05;
      groupRef.current.rotation.z += (targetRotZ - groupRef.current.rotation.z) * 0.05;
    }
  });

  const handleClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    if (e.instanceId !== undefined && ledger[e.instanceId]) {
      onSelectEvent(ledger[e.instanceId]);
    }
  };

  return (
    <group ref={groupRef}>
      {/* Instanced blocks along helix */}
      <instancedMesh
        ref={meshRef}
        args={[undefined, undefined, ledger.length]}
        onClick={handleClick}
      >
        <boxGeometry args={[0.32, 0.32, 0.32]} />
        <meshBasicMaterial wireframe={false} />
      </instancedMesh>

      {/* Wireframe outlines on blocks */}
      <lineSegments>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            args={[linePositions, 3]}
          />
          <bufferAttribute
            attach="attributes-color"
            args={[lineColors, 3]}
          />
        </bufferGeometry>
        <lineBasicMaterial args={[{ vertexColors: true, transparent: true, opacity: 0.6 }]} />
      </lineSegments>
    </group>
  );
};

export const EvidenceChain3DScene: React.FC<EvidenceChain3DSceneProps> = ({
  ledger,
  brokenIndex,
  selectedSeq,
  onSelectEvent,
  className = 'w-full h-[460px]',
}) => {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    return () => setMounted(false);
  }, []);

  if (!mounted) return null;

  return (
    <div className={`relative bg-s1/60 rounded-[2px] overflow-hidden ${className}`}>
      <Canvas
        camera={{ position: [0, 0, 9.5], fov: 42 }}
        dpr={[1, 1.75]}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight args={['#ffffff', 0.4]} />
        <HelixSceneContent
          ledger={ledger}
          brokenIndex={brokenIndex}
          selectedSeq={selectedSeq}
          onSelectEvent={onSelectEvent}
        />
      </Canvas>

      {/* 3D Scene Overlay Badge */}
      <div className="absolute top-2 left-2 px-2 py-0.5 rounded-[2px] bg-s2/80 border border-bd text-[10px] font-mono text-mut flex items-center gap-2 pointer-events-none">
        <span className="w-1.5 h-1.5 rounded-full bg-cy animate-pulse" />
        <span>R3F INSTANCED HELIX · {ledger.length} BLOCKS · CLICK BLOCK TO INSPECT</span>
      </div>
    </div>
  );
};
