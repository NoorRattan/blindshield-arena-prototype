/// <reference types="vitest" />
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import https from 'node:https';
import { lstatSync, readFileSync } from 'node:fs';

type BackendRole = 'operator' | 'red' | 'blue-human' | 'auditor';

const ROLE_PROXY_PATHS: ReadonlyArray<{ path: string; role: BackendRole }> = [
  { path: '/v1/operator', role: 'operator' },
  { path: '/v1/red', role: 'red' },
  { path: '/v1/blue', role: 'blue-human' },
  { path: '/v1/auditor', role: 'auditor' },
];

function readRegularFile(directory: string, name: string): Buffer {
  const file = path.resolve(directory, name);
  if (path.dirname(file) !== path.resolve(directory)) {
    throw new Error(`Invalid local TLS filename: ${name}`);
  }
  const stat = lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Local TLS input is not a regular file: ${name}`);
  }
  return readFileSync(file);
}

function resolveClientLabels(directory: string): Map<BackendRole, string> {
  const labels = new Map<BackendRole, string>();
  const clientRoles: BackendRole[] = ['operator', 'red', 'blue-human', 'auditor'];

  try {
    const clients = JSON.parse(readRegularFile(directory, 'clients.json').toString('utf8')) as Record<string, unknown>;
    for (const role of clientRoles) {
      const label = clients[role];
      if (typeof label === 'string' && /^client-[a-z0-9-]+$/.test(label)) labels.set(role, label);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  if (labels.size !== clientRoles.length) {
    try {
      const identities = JSON.parse(readRegularFile(directory, 'identities.json').toString('utf8')) as Record<
        string,
        { label?: unknown; binding?: unknown }
      >;
      for (const identity of Object.values(identities)) {
        const role = Array.isArray(identity.binding) ? identity.binding[1] : undefined;
        if (
          typeof role === 'string' &&
          clientRoles.includes(role as BackendRole) &&
          typeof identity.label === 'string' &&
          /^client-[a-z0-9-]+$/.test(identity.label)
        ) {
          labels.set(role as BackendRole, identity.label);
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }

  // PrototypeService writes the certificate files with these labels and may
  // omit a separate mapping file in older local runs.
  for (const role of clientRoles) {
    if (!labels.has(role)) labels.set(role, `client-${role}`);
  }
  return labels;
}

function createLocalMtlsProxy() {
  const target = new URL(process.env.VITE_BACKEND_URL || 'https://127.0.0.1:8443');
  if (
    target.protocol !== 'https:' ||
    !['127.0.0.1', 'localhost', '[::1]', '::1'].includes(target.hostname) ||
    target.username ||
    target.password ||
    target.search ||
    target.hash
  ) {
    throw new Error('The development mTLS proxy only permits an HTTPS loopback backend.');
  }

  const tlsDirectory = process.env.BLINDSHIELD_TLS_DIR;
  const proxies: Record<string, object> = {};
  if (!tlsDirectory) {
    console.warn('BlindShield live proxy is disabled: set BLINDSHIELD_TLS_DIR to the local backend TLS directory.');
  } else {
    const directory = path.resolve(tlsDirectory);
    const ca = readRegularFile(directory, 'ca.pem');
    const labels = resolveClientLabels(directory);
    for (const { path: prefix, role } of ROLE_PROXY_PATHS) {
      const labelRole = role === 'blue-human' ? 'blue-human' : role;
      const label = labels.get(labelRole);
      if (!label) throw new Error(`No local mTLS client certificate is provisioned for role ${role}.`);
      const agent = new https.Agent({
        ca,
        cert: readRegularFile(directory, `${label}.pem`),
        key: readRegularFile(directory, `${label}.key`),
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true,
        keepAlive: false,
      });
      proxies[prefix] = {
        target: target.toString(),
        changeOrigin: true,
        secure: true,
        agent,
        rewrite: (requestPath: string) => requestPath.replace(/^\/v1\/(?:operator|red|blue|auditor)(?=\/|$)/, '/v1'),
        configure: (proxy) => {
          proxy.on('error', (_error, _request, response) => {
            if (response.headersSent || response.writableEnded) return;
            response.writeHead(502, {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'no-store',
            });
            response.end(JSON.stringify({
              code: 'LOCAL_BACKEND_TLS_UNAVAILABLE',
              message: 'The loopback backend did not complete its authenticated TLS request.',
            }));
          });
        },
      };
    }
    console.info(`BlindShield local mTLS proxy configured for ${target.origin}. Client keys remain in the Vite process.`);
  }

  return proxies;
}

const localMtlsProxy = createLocalMtlsProxy();
const liveProxyGuard: Plugin = {
  name: 'blindshield-live-proxy-guard',
  enforce: 'pre',
  configureServer(server) {
    server.middlewares.use((request, response, next) => {
      const requestPath = request.url?.split('?')[0] ?? '';
      if (requestPath === '/local/create-request' && request.method === 'GET') {
        const origin = request.headers.origin;
        response.setHeader('Content-Type', 'application/json; charset=utf-8');
        response.setHeader('Cache-Control', 'no-store');
        if (origin && origin !== 'http://127.0.0.1:5173') {
          response.statusCode = 403;
          response.end(JSON.stringify({ code: 'LOCAL_ORIGIN_REQUIRED' }));
          return;
        }
        try {
          const directory = process.env.BLINDSHIELD_TLS_DIR;
          if (!directory) throw new Error('No local configuration');
          const config = JSON.parse(readRegularFile(directory, 'config.json').toString('utf8'));
          response.end(JSON.stringify({ request: config.profiles[0].request }));
        } catch {
          response.statusCode = 503;
          response.end(JSON.stringify({ code: 'LOCAL_PROFILE_UNAVAILABLE' }));
        }
        return;
      }
      if (requestPath.startsWith('/v1/')) {
        const hasRoleRoute = ROLE_PROXY_PATHS.some(({ path: prefix }) => requestPath.startsWith(`${prefix}/`));
        const origin = request.headers.origin;
        const originIsLocal = !origin || origin === 'http://127.0.0.1:5173';
        if (!hasRoleRoute || !process.env.BLINDSHIELD_TLS_DIR || !originIsLocal) {
          response.statusCode = originIsLocal ? 503 : 403;
          response.setHeader('Content-Type', 'application/json; charset=utf-8');
          response.setHeader('Cache-Control', 'no-store');
          response.end(JSON.stringify({
            code: originIsLocal ? 'LOCAL_MTLS_PROXY_NOT_CONFIGURED' : 'LOCAL_MTLS_PROXY_ORIGIN_REJECTED',
            message: originIsLocal
              ? 'Set BLINDSHIELD_TLS_DIR and use a role-scoped /v1/<role> route before enabling live mode.'
              : 'The local mTLS proxy accepts browser requests only from its loopback UI origin.',
          }));
          return;
        }
      }
      next();
    });
  },
};

export default defineConfig({
  plugins: [react(), liveProxyGuard],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: localMtlsProxy,
  },
});
