# Implementation Status

## Implemented

- Experiment-independent persistent lab configuration.
- Approved capability discovery.
- Separate approved capability and material catalogs; materials identify
  concrete resources, and the materials catalog may be empty.
- Researcher-defined investigation schema.
- Compose policy validation and fail-closed unsupported operation handling.
- Resource resolution against explicitly registered, available materials;
  capabilities remain operation/adapter declarations rather than resources.
- Inspectable construction plans with specification digests, budgets, approvals,
  provenance, and ownership.
- Explicit authorization-gated construction and ownership-scoped disposal.
- Evidence hashing and controlled export.
- Retained readiness, maintenance, incident, capture, and Windows emergency
  stop tooling.
- Temporary synthetic construction tests with no bundled investigation.
- Configuration-driven network profiles and twelve validated boundary schemas.
- Read-only WSL/Docker network discovery, IPv4/IPv6 forwarding observation,
  redacted proxy-variable discovery, and operator-confirmed machine
  configuration validation.
- Read-only Docker project inspection of the approved context, daemon identity,
  owned network attachments, container ownership, image content IDs, mounts,
  ports, privileges, capabilities/devices, users, root filesystem, tmpfs and
  resource limits, and security options. Runtime readiness and post-start
  construction checks fail closed unless these effective settings pass.
- A shared `lab/enforcement/` package with typed scope/status/result contracts,
  a coordinator used by runtime readiness, a Docker adapter over the existing
  inspector, an approval-gated Linux/WSL adapter over the owned-rule script,
  and a read-only Windows host observer that never claims enforcement.
- A concrete `lab/osapi/` layer for Linux interfaces/routes/forwarding/firewall,
  sockets/processes/sysctl/resolvers/proxies/mounts; Docker daemon and project
  resources; Windows host observations; and separate WSL state/network
  observations. It returns structured command and observation results through
  `lab/lab.py os inspect`.
- A typed `lab/osapi/actions.py` interface wired into construction, validation,
  the network CLI, and `LinuxWslAdapter`. It runs the existing Linux/WSL
  boundary script only after the current Docker target reports a local
  Unix-socket endpoint, a daemon name matching the host, and `sudo -n -v`
  succeeds. The Docker context does not prove the physical daemon host. Docker
  Compose create/start/stop/down and approval-gated connect/disconnect actions
  use a resolved context; attachment changes are restricted to project-owned
  container/network IDs. Windows mutations and cross-distribution WSL controls
  remain unsupported.
- Linux boundary operations read the effective IPv4/IPv6 ruleset before and
  after the existing script; a fresh post-operation check confirms the
  project-owned chains and jump targets, or their absence after removal.
- Inspectable enforcement plans and explicit Linux/WSL capability rejection.
- Project-owned IPv4/IPv6 bridge chains with leading host/forwarding jumps,
  idempotent installation, ordering verification, and scoped removal.
- Persistent runtime admission with pinned policy identity, resource
  reservations, shared-scope conflict detection, and inter-process state
  locking.

## Implemented but not live-verified

- Image acquisition/build provenance.
- Whether registered materials are present and match their declared identities
  at execution time; catalog registration is not runtime verification.
- Actual Compose construction and service execution on the target host.
- Effective container settings on a constructed project; no lab-owned
  containers or networks were present during this implementation session.
- Network containment and egress behavior on the target WSL/Docker instance.
- Workload observations and evidence preservation through disposal.
- Durable archive transfer and Windows emergency-stop behavior.

The adapter's project-owned IPv4/IPv6 chains are structurally verified from
fresh kernel ruleset observations, but no live packet acceptance runner is
available, so they are not proof of effective isolation. Windows/WSL
cross-boundary isolation remains `UNKNOWN`. Restricted allow-lists,
monitor-mode enforcement, Windows-host
controls, dedicated DNS/proxy enforcement, upstream VPN/routing controls, and
temporary maintenance restoration remain unsupported and fail closed.
`runtime start` refuses readiness without project-specific verified rules and
passing Docker inspection and acceptance evidence. A Docker context
observation, local socket endpoint, or daemon-name match does not establish the
physical daemon host or Windows/WSL isolation. Passing repository tests
establishes code behavior only; it does not establish Docker or WSL isolation.
The Docker inspector is unit-tested with fixtures; live inspection of a
lab-owned container remains a separate acceptance activity.
See [the enforcement gap register](enforcement-gap-register.md) for the
boundary owner, verification, and restoration status of all twelve policies.
