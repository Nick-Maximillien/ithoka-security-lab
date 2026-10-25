# Project Documentation

This directory documents the current implementation and its acceptance
limits. Begin with [the repository README](../README.md) for the project
overview, [the operator guide](../lab-set.md) for setup and experiment
workflows, and [the command reference](../lab-set.d/commands.md) for exact
system commands.

## Current project state

The repository provides a Python control plane for researcher-authored
investigations, a Docker Compose construction backend, profile-based network
policy resolution, project-scoped Linux/WSL firewall actions, read-only
Linux/Docker/Windows/WSL observations, a separate persistent runtime/admission
store, a separate empty researcher workspace with a bounded Docker tool runner,
evidence collection/archive, shell operations, and an optional local-only
Streamlit dashboard.

The action API is typed and allowlisted; it is not a general-purpose host
command runner. Compose lifecycle actions and ownership-checked network
attachment actions are scoped to an explicitly resolved Docker context.
Linux/WSL firewall actions delegate to the existing boundary script after
target, ownership, and privilege checks. Windows mutations and cross-
distribution WSL controls are unsupported.

The Linux/WSL adapter currently supports project-owned deny-mode IPv4/IPv6
bridge-chain operations and structural verification. The supplied network
profiles also require controls that are not implemented or runtime-accepted,
including Windows-host, dedicated DNS/proxy, and external packet acceptance.
They fail closed while those required boundaries remain enabled. No live
packet-acceptance runner or physical air-gap claim is available. Docker
context/socket observations do not prove the physical daemon host.

The repository's current unit suite contains 135 tests. Tests and static
inspection do not establish host isolation, workload behavior, image
provenance, packet capture completeness, or Windows/WSL boundary acceptance.
See [readiness inventory](readiness-inventory.md) and
[final readiness](final-readiness.md) for recorded evidence and gaps.

## Documents

| Document | Scope |
| --- | --- |
| [Architecture](architecture.md) | Control-plane components, ownership, network policy, runtime state, and lifecycle. |
| [Operations](operations.md) | Lifecycle prerequisites, control gates, evidence, and runtime separation. |
| [Investigation authoring](experiment-authoring.md) | Required specification sections and Compose validation requirements. |
| [Network boundaries](network-boundaries.md) | Discovery, policy plans, adapter scope, verification, and acceptance gaps. |
| [Enforcement gap register](enforcement-gap-register.md) | Each boundary's observer/enforcer, verification, and restoration limitations. |
| [Evidence handling](evidence-handling.md) | Evidence staging, integrity, archive, and transfer rules. |
| [Recovery](recovery.md) | Targeted recovery and emergency-stop guidance. |
| [Threat model](threat-model.md) | Trust boundaries, assumptions, and residual risk. |
| [Implementation status](implementation-status.md) | Implemented features, test status, and unverified runtime behavior. |
| [Readiness inventory](readiness-inventory.md) | Historical host observations and current implementation facts. |
| [Final readiness](final-readiness.md) | Engineering readiness snapshot and acceptance checklist. |
| [Requirements traceability](requirements-traceability.md) | Requirement-to-implementation mapping. |
| [ADR-0001](adr/ADR-0001-experiment-runtime-and-canonical-workshop.md) | Accepted runtime and canonical-workshop decision. |

Host observations in readiness documents are dated snapshots, not live facts.
Re-run the documented read-only discovery and inspection commands before
relying on host-specific values.
