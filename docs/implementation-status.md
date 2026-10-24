# Implementation Status

## Implemented

- Experiment-independent persistent lab configuration.
- Approved capability discovery.
- Researcher-defined investigation schema.
- Compose policy validation and fail-closed unsupported operation handling.
- Resource resolution against the approved capability catalog.
- Inspectable construction plans with specification digests, budgets, approvals,
  provenance, and ownership.
- Explicit authorization-gated construction and ownership-scoped disposal.
- Evidence hashing and controlled export.
- Retained readiness, maintenance, incident, capture, and Windows emergency
  stop tooling.
- Temporary synthetic construction tests with no bundled investigation.
- Configuration-driven network profiles and twelve validated boundary schemas.
- Read-only WSL/Docker network discovery and operator-confirmed machine
  configuration validation.
- Inspectable enforcement plans and explicit Linux/WSL capability rejection.
- Persistent runtime admission with pinned policy identity, resource
  reservations, shared-scope conflict detection, and inter-process state
  locking.

## Implemented but not live-verified

- Image acquisition/build provenance.
- Actual Compose construction and service execution on the target host.
- Runtime ownership labels and effective resource limits on the target daemon.
- Network containment and egress behavior on the target WSL/Docker instance.
- Workload observations and evidence preservation through disposal.
- Durable archive transfer and Windows emergency-stop behavior.

The current adapter genuinely supports only project-scoped deny-mode IPv4/IPv6
bridge enforcement. Restricted allow-lists, monitor-mode enforcement,
Windows-host controls, upstream VPN/routing controls, and temporary maintenance
restoration remain unsupported and fail closed. Passing repository tests
establishes code behavior only; it does not establish Docker or WSL isolation.
