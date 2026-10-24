# Architecture

The lab is persistent infrastructure; each researcher-defined investigation
is disposable apparatus constructed inside it.

## Components

| Layer | Responsibility |
| --- | --- |
| `lab/` Python control plane | Readiness, specification validation, capability/resource resolution, planning, authorization, construction, ownership, disposal, evidence export |
| YAML specification | Research question, apparatus, resources, procedure, observations, evaluation, evidence, safety, and budgets |
| Capability catalog | Approved reusable interfaces and their policy contracts |
| Docker Compose adapter | Creates an investigation-scoped project from the submitted apparatus |
| Shell/PowerShell tools | Readiness, capture, maintenance, incident recording, and emergency stop |
| Evidence staging | Durable records outside disposable runtime resources |
| Optional Streamlit GUI | Local-only presentation client; no Docker socket, subprocess, or independent policy |

There is no predefined experiment registry, default investigation, fixed service
role, fixed topology, or experiment-specific controller branch.

The command-driven workspace layer provides an empty, ownership-scoped
experiment workspace. Researchers can create source trees, scripts, datasets,
and configuration there without a template. `stop`, `reset`, and `destroy`
remain separate lifecycle operations; selected evidence is copied to durable
staging before destruction.

## Construction boundary

The engine accepts only declared, validated operations. It does not execute
arbitrary host shell commands on behalf of a specification. Compose apparatus
must satisfy the backend policy: internal networks, no published ports or host
network, no host mounts or Docker socket, non-root service execution, dropped
capabilities, `no-new-privileges`, and bounded resources.

Every constructed project is named from an investigator-assigned ID and is
disposed using that exact ownership scope. Global Docker prune and deletion of
unrelated resources are not used.

## Current limitation

The initial backend is Docker Compose on WSL2. Runtime acceptance, image
provenance, network egress, host isolation, and Windows emergency-stop behavior
must be demonstrated separately; static validation is not runtime proof.
## Networks subsystem

Network policy has three configuration layers. The twelve files under
`config/networks/boundaries/` are the authoritative researcher-editable
boundary settings. The four files under `config/networks/profiles/` select
those boundary files and provide explicit profile overrides. The configured
`active-profile` is only the default for new experiments. The resolver in
`lab/networks.py` combines the active profile with investigation overrides and
records SHA-256 provenance for every input file.

Construction pins that effective policy beside the generated Compose runtime
file. The Linux/WSL adapter consumes the pinned JSON and verifies its
project-scoped rules before services start. Changing `active-profile` or a
boundary file affects later operations only; it does not silently mutate a
running investigation.

The current adapter can enforce and verify deny-mode IPv4/IPv6 bridge
controls. Windows Firewall, VMware, VPN/upstream routing, restricted
allow-lists, and temporary maintenance restoration are reported as
unsupported or unverified rather than represented as successful isolation.

The persistent runtime state is held in `state/runtime/runtime.json`. It owns
runtime lifecycle state, policy snapshots, experiment admission records,
resource reservations, maintenance decisions, and audit events. Experiment
records are separate from runtime-owned state, and releasing one experiment
pins its effective policy and provenance without changing another experiment.
Different profile names can coexist when effective requirements and shared
enforcement scopes are compatible; shared-resource conflicts and capacity
pressure are concrete admission failures. State transitions use an
inter-process lock, and runtime stop is blocked while owned experiments or
active maintenance remain.

The current operational path is:

```text
researcher specification
  -> selected profile and boundary resolution
  -> machine configuration and capability validation
  -> inspectable enforcement plan
  -> owned Docker network creation
  -> scoped boundary apply and verification
  -> workload start/admission
  -> evidence collection and ownership-scoped teardown
```

Read-only discovery uses installed WSL/Linux and Docker commands and never
changes host state. The supported adapter verifies only project-scoped
deny-mode IPv4/IPv6 bridge rules. The policy model records unsupported or
unverified Windows, VPN, upstream, restricted, monitor-enforcement, and
temporary-maintenance capabilities instead of claiming them.
