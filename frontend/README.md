# BlindShield Arena console

React 18, TypeScript and Vite console for operator, red-team, blue-team and auditor workflows.

```sh
npm ci
npm run dev
```

Open http://localhost:5173. **SIMULATED DATA** is the supported self-contained evaluation path. It uses browser/mock state and does not dispatch a real model.

## Checks

```sh
npm run verify
```

This runs type checking, ESLint, Vitest and the production build. Browser suites use Playwright through `npm run e2e:smoke` and need compatible browser binaries. See [the evaluator guide](../EVALUATION.md) for executed results.

The current delivery passed 284 Vitest tests, type checking, lint and build. Four
smoke/accessibility cases and two judge-walkthrough cases passed across desktop
and mobile viewports using Playwright with installed Microsoft Edge. This is not
a rerun of the entire historical 96-case browser suite.

## Live adapter status

`src/lib/api/liveClient.ts` adds HTTP transport, lifecycle operations, idempotency keys, feedback polling and ZIP bundle download. The new integration suite mocks `fetch`; passing it does not prove interoperability with a running Python service.

The backend authenticates the TLS client certificate. JavaScript role headers, fingerprints and browser role selection do not establish certificate identity. The Vite development proxy does not provision client certificates. Live mode needs an owner-provisioned authenticated transport and matching endpoint/response adapters. The development proxy is not a deployment gateway.

Known integration gaps include experiment-list/status projections, endpoints the console expects but the prototype does not expose, and the legacy JSON evidence view versus the backend's raw ZIP evidence endpoint. The explicit ZIP download method is separate. Backend authorization stays authoritative.

The console labels simulated telemetry. The earlier 96-case Playwright receipt predates this frontend delivery and remains historical.
