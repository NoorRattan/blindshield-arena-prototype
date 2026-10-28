# Frontend

This is the BlindShield Arena visual prototype built with React, TypeScript, and Vite.

## Start

~~~powershell
npm ci
npm run dev
~~~

## Checks

~~~powershell
npm run verify
npm run e2e:smoke
~~~

The project requires Node.js compatible with the locked dependencies. Playwright browser setup may be needed for local E2E runs; the recorded Docker run is documented in the backend release runbook.

## Scope

This UI uses local mock and browser state. It is not connected to the backend, authenticated API, or real model. Its workflow, badges, and sample results are illustrative and must not be presented as verified backend behavior.

The files PROJECT_OVERVIEW_AND_FRONTEND_SPEC.md, FRONTEND_PAGE_FEATURES.md, and FRONTEND_BRIEF.md are design specifications for proposed features, not descriptions of the implemented interface. The npm lock-only audit recorded eight high and one moderate finding; see the root submission packet for the receipt.

