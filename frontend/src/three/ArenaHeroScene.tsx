import React, { useRef, useMemo, useEffect, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { ArenaHero2DFallback } from './ArenaHero2DFallback';

export type ActiveArenaNode = 'red' | 'broker' | 'blue' | 'target' | 'scorer' | 'witness' | null;

export interface ArenaHeroSceneProps {
  activeNode?: ActiveArenaNode;
  scrollProgress?: number;
  className?: string;
}

function checkWebGLSupport(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    return Boolean(gl);
  } catch {
    return false;
  }
}

// Internal 3D scene content rendered within R3F Canvas
const SceneContent: React.FC<{ activeNode?: ActiveArenaNode; scrollProgress?: number }> = ({
  activeNode = 'broker',
  scrollProgress = 0,
}) => {
  const groupRef = useRef<THREE.Group>(null);
  const brokerOuterRef = useRef<THREE.Mesh>(null);
  const brokerInnerRef = useRef<THREE.Mesh>(null);
  const orbit1Ref = useRef<THREE.Group>(null);
  const orbit2Ref = useRef<THREE.Group>(null);
  const instancedBlocksRef = useRef<THREE.InstancedMesh>(null);

  // Parallax pointer target
  const mouseRef = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const handlePointerMove = (e: MouseEvent) => {
      // Normalize to -1 .. 1
      mouseRef.current.x = (e.clientX / window.innerWidth) * 2 - 1;
      mouseRef.current.y = -(e.clientY / window.innerHeight) * 2 + 1;
    };
    window.addEventListener('mousemove', handlePointerMove, { passive: true });
    return () => window.removeEventListener('mousemove', handlePointerMove);
  }, []);

  // Set up 24 instanced evidence blocks in a ring of radius 4.2
  const dummy = useMemo(() => new THREE.Object3D(), []);
  useEffect(() => {
    if (!instancedBlocksRef.current) return;
    const count = 24;
    const radius = 4.2;
    for (let i = 0; i < count; i++) {
      const angle = (i * 2 * Math.PI) / count;
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;
      dummy.position.set(x, 0, z);
      dummy.rotation.set(0, -angle, 0);
      dummy.scale.set(0.18, 0.18, 0.18);
      dummy.updateMatrix();
      instancedBlocksRef.current.setMatrixAt(i, dummy.matrix);
    }
    instancedBlocksRef.current.instanceMatrix.needsUpdate = true;
  }, [dummy]);

  useFrame((state, delta) => {
    // 1. Broker slow rotation & pulse
    if (brokerOuterRef.current) {
      brokerOuterRef.current.rotation.y += delta * 0.25;
      brokerOuterRef.current.rotation.x += delta * 0.12;
      const scale = activeNode === 'broker' ? 1.1 + Math.sin(state.clock.elapsedTime * 3) * 0.05 : 1.0;
      brokerOuterRef.current.scale.set(scale, scale, scale);
    }
    if (brokerInnerRef.current) {
      brokerInnerRef.current.rotation.y -= delta * 0.35;
    }

    // 2. Orbits rotation driven by time + scrollProgress
    if (orbit1Ref.current) {
      orbit1Ref.current.rotation.y += delta * 0.2 + scrollProgress * 0.02;
    }
    if (orbit2Ref.current) {
      orbit2Ref.current.rotation.y -= delta * 0.15 + scrollProgress * 0.02;
    }

    // 3. Evidence ring slow precession
    if (instancedBlocksRef.current) {
      instancedBlocksRef.current.rotation.y += delta * 0.08;
    }

    // 4. Parallax constraint (<= 6° ~ 0.1 rad)
    if (groupRef.current) {
      const targetRotX = mouseRef.current.y * 0.09;
      const targetRotY = mouseRef.current.x * 0.09;
      groupRef.current.rotation.x = THREE.MathUtils.lerp(groupRef.current.rotation.x, targetRotX, 0.05);
      groupRef.current.rotation.y = THREE.MathUtils.lerp(groupRef.current.rotation.y, targetRotY, 0.05);
    }
  });

  return (
    <group ref={groupRef}>
      {/* Central Broker Core: Wireframe Icosahedron + Inner mass */}
      <mesh ref={brokerOuterRef}>
        <icosahedronGeometry args={[1.2, 0]} />
        <meshBasicMaterial
          wireframe
          color={activeNode === 'broker' ? '#00E5FF' : '#34425F'}
          transparent
          opacity={0.8}
        />
      </mesh>
      <mesh ref={brokerInnerRef}>
        <icosahedronGeometry args={[0.8, 1]} />
        <meshBasicMaterial
          color="#00E5FF"
          transparent
          opacity={activeNode === 'broker' ? 0.25 : 0.1}
        />
      </mesh>

      {/* Orbit 1: Tilted at X=35°, holding Red Node & Blue Node */}
      <group ref={orbit1Ref} rotation={[THREE.MathUtils.degToRad(35), 0, THREE.MathUtils.degToRad(15)]}>
        {/* Ring wire */}
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <ringGeometry args={[2.48, 2.52, 64]} />
          <meshBasicMaterial color="#232D42" side={THREE.DoubleSide} />
        </mesh>

        {/* Red Node at angle 0 */}
        <group position={[2.5, 0, 0]}>
          <mesh>
            <sphereGeometry args={[activeNode === 'red' ? 0.28 : 0.2, 16, 16]} />
            <meshBasicMaterial color="#FF9100" />
          </mesh>
          <mesh>
            <icosahedronGeometry args={[0.36, 0]} />
            <meshBasicMaterial wireframe color="#FF9100" transparent opacity={0.6} />
          </mesh>
        </group>

        {/* Blue Node at angle PI */}
        <group position={[-2.5, 0, 0]}>
          <mesh>
            <sphereGeometry args={[activeNode === 'blue' ? 0.28 : 0.2, 16, 16]} />
            <meshBasicMaterial color="#2979FF" />
          </mesh>
          <mesh>
            <icosahedronGeometry args={[0.36, 0]} />
            <meshBasicMaterial wireframe color="#2979FF" transparent opacity={0.6} />
          </mesh>
        </group>
      </group>

      {/* Orbit 2: Tilted at X=-30°, Y=25°, holding Target Node & Scorer Node */}
      <group ref={orbit2Ref} rotation={[THREE.MathUtils.degToRad(-30), THREE.MathUtils.degToRad(25), 0]}>
        {/* Ring wire */}
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <ringGeometry args={[3.38, 3.42, 64]} />
          <meshBasicMaterial color="#34425F" side={THREE.DoubleSide} />
        </mesh>

        {/* Target Node at angle PI/2 */}
        <group position={[0, 0, 3.4]}>
          <mesh>
            <sphereGeometry args={[activeNode === 'target' ? 0.28 : 0.2, 16, 16]} />
            <meshBasicMaterial color="#00E676" />
          </mesh>
          <mesh>
            <octahedronGeometry args={[0.36, 0]} />
            <meshBasicMaterial wireframe color="#00E676" transparent opacity={0.6} />
          </mesh>
        </group>

        {/* Scorer Node at angle -PI/2 */}
        <group position={[0, 0, -3.4]}>
          <mesh>
            <sphereGeometry args={[activeNode === 'scorer' ? 0.28 : 0.2, 16, 16]} />
            <meshBasicMaterial color="#00E5FF" />
          </mesh>
          <mesh>
            <octahedronGeometry args={[0.36, 0]} />
            <meshBasicMaterial wireframe color="#00E5FF" transparent opacity={0.6} />
          </mesh>
        </group>
      </group>

      {/* 24 Instanced Evidence Blocks (Chain Ring) */}
      <instancedMesh ref={instancedBlocksRef} args={[undefined, undefined, 24]}>
        <boxGeometry args={[1, 1, 1]} />
        <meshBasicMaterial
          color={activeNode === 'witness' ? '#00E676' : '#232D42'}
          wireframe
        />
      </instancedMesh>
    </group>
  );
};

export const ArenaHeroScene: React.FC<ArenaHeroSceneProps> = ({
  activeNode = 'broker',
  scrollProgress = 0,
  className = '',
}) => {
  const [hasWebGL, setHasWebGL] = useState<boolean>(true);

  useEffect(() => {
    setHasWebGL(checkWebGLSupport());
  }, []);

  if (!hasWebGL) {
    return <ArenaHero2DFallback activeNode={activeNode} className={className} />;
  }

  return (
    <div className={`w-full h-full relative select-none ${className}`}>
      <Canvas
        camera={{ position: [0, 2.2, 7.8], fov: 45 }}
        dpr={[1, 1.75]}
        gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
        fallback={<ArenaHero2DFallback activeNode={activeNode} />}
      >
        <SceneContent activeNode={activeNode} scrollProgress={scrollProgress} />
      </Canvas>
    </div>
  );
};

export default ArenaHeroScene;
