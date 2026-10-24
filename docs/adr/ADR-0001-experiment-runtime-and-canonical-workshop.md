# ADR-0001: Scientific Experiment Engine and Runtime Adapter

- Status: Accepted for the current implementation scope; live runtime acceptance pending
- Date: 2026-10-22
- Decision owners: Lab maintainers

## Context

The lab needs an experiment construction and scientific record model that is not coupled to named experiment IDs. The current Docker Compose scripts provide useful containment and lifecycle controls but couple the default project/network to one client/server workload and support only `client-request` and `policy-review` execution modes.

The governing design selects WSL/Docker for lightweight Linux services and container-network research, VMware for guest-kernel work, and manual evidence transfer by default. It requires bounded resource use, isolated per-experiment state, explicit maintenance, and truthful isolation claims. It does not mandate a specific orchestrator.

Canonical Workshop is a declarative tool for reproducible Ubuntu development environments. The official project documentation describes Workshop definitions composed from SDKs and launched on Ubuntu or WSL; it is built on LXD system containers and lists LXD 6.8+ as a prerequisite. Its commands can install/download SDKs and launch/update environments. Workshop addresses environment composition, not the experiment/run/observation/evidence custody lifecycle.

## Decision

1. Keep Docker Compose as the current execution adapter and preserve the existing host emergency stop.
2. Build the scientific definition, capability/method catalogs, state records, and preview/validation above the runtime adapter boundary.
3. Use registered, allowlisted capability operations. Definitions do not contain shell commands or grant permissions.
4. Keep definition validation/preview and instance recording separate from runtime construction and run execution. Runtime actions remain behind explicit approval.
5. Give each experiment instance a distinct identity, generated Compose project/network namespace, lease, evidence directory, and immutable definition/run snapshot. Keep the stable lab owner label as the facility authority.
6. Treat the Workshop option as deferred. Reconsider only for a concrete reproducible development-tool environment that cannot be provided safely and more simply by the existing adapter.
7. Keep network profile resolution, machine discovery, enforcement planning,
   scoped boundary application, and runtime admission in the existing Python
   control plane. Do not introduce a second policy engine or a global
   maintenance mode.

## Options considered

| Option | Fit and benefits | Costs, risks, and unresolved requirements |
| --- | --- | --- |
| A. Docker adapter plus runtime-independent scientific engine | Reuses the existing tested-in-source Compose hardening, ownership labels, approval gates, and operator knowledge. Lowest migration and resource overhead. Runtime independent records can later support other adapters. | Existing Compose behavior needs instance namespacing; Docker/WSL runtime acceptance is still pending. Not suitable for experiments needing an independent kernel. |
| B. Docker plus optional Workshop/LXD tool environments | Workshop could provide reproducible developer/tool environments and composable SDKs on Ubuntu/WSL. Keeps existing Compose lab while allowing a separate optional adapter. | Adds LXD 6.8+, Snap/Workshop dependencies, storage pools, networks, update/acquisition paths, another privileged management plane, memory/disk overhead, and ownership/recovery/testing work. Compatibility with lab evidence and containment is not established. No installation is authorized. |
| C. Replace or broadly migrate to LXD/Workshop | System containers offer Ubuntu userspace, systemd, and composable development SDKs. | Misfits the existing Docker-specific design and does not supply scientific run/observation/evidence lifecycle. Does not provide separate guest kernels. Migration would increase host footprint and complexity without resolving the key abstraction gap. |

## Consequences

- Experiment manifests and scientific records are runtime-neutral; adapter-specific fields are capability contracts.
- Docker remains the only implemented infrastructure runtime. Capability availability must be explicit, and unsupported operations fail closed.
- Docker isolation remains logical, shares the Linux kernel, and integrates with Windows through WSL. The ADR does not claim a physical air gap.
- No Workshop, LXD, Snap, image, package, or other dependency is installed or acquired by this decision.
- This ADR does not authorize Compose rendering against a live daemon, container creation, network changes, or host changes.
- The current repository test suite has 38 passing tests. They validate the
  policy and lifecycle code with temporary repositories and mocks; they do not
  replace live WSL/Docker acceptance.

## Revisit conditions

Revisit option B if a named experiment requires a reproducible Ubuntu tool environment, the current Docker capability cannot provide it safely, official Workshop/LXD prerequisites are verified for the target WSL setup, resource headroom is measured, and a threat model, ownership design, evidence integration, rollback plan, and mocked/runtime acceptance suite exist.

Revisit option C only if requirements materially change to justify LXD as the primary adapter and comparative tests show better containment, resource behavior, and lifecycle fit than Docker. Workshop must not be treated as a substitute for the scientific engine.

## References reviewed

- Canonical Workshop repository: <https://github.com/canonical/workshop>
- Canonical Workshop getting started: <https://documentation.ubuntu.com/canonical-workshop/stable/tutorial/part-1-get-started/>
- Canonical Workshop documentation: <https://documentation.ubuntu.com/canonical-workshop/latest/>
- Repository governing design: `docker-lab-low-level-design.md` and `lab-design-foundational/lab-design-foundational.md`

The project repository documents Ubuntu/WSL support, SDK-based environment definitions, LXD as the underlying container technology, and LXD 6.8+ installation prerequisite. These facts do not establish suitability for hostile security workloads or complete host isolation.
