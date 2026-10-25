# Ithoka Security Research Lab

This repository implements a locally operated, Docker-backed cybersecurity
research lab. Python is the control plane; YAML describes researcher-defined
investigations; Docker Compose is an execution backend; Bash and PowerShell
are thin operational interfaces.

The installed lab is **experiment-independent**. It contains no predefined
experiments, sample workloads, default experiment ID, fixed client/server
topology, or registered activity catalogue. A researcher supplies an
investigation specification and the construction engine translates it into a
disposable, ownership-scoped environment.

Start with the [operator guide](lab-set.md) for the complete setup-to-teardown
workflow and the [system command reference](lab-set.d/commands.md) for every
CLI, shell, and Windows host command. The [documentation index](docs/README.md)
links the architecture, network policy, evidence, recovery, implementation
status, and readiness records.

## Control plane

- [`lab/lab.py`](lab/lab.py) — CLI entry point.
- [`lab/cli.py`](lab/cli.py) — lab-first command interface.
- [`lab/foundation.py`](lab/foundation.py) — common safety, YAML, path,
  locking, and integrity primitives.
- [`lab/validation.py`](lab/validation.py) — backend policy validation.
- [`lab/construction.py`](lab/construction.py) — specification validation,
  resource resolution, planning, construction, and disposal.
- [`lab/networks.py`](lab/networks.py) — profile resolution, machine
  configuration validation, read-only discovery, enforcement plans, and
  adapter capability checks.
- [`lab/enforcement/`](lab/enforcement/) — typed enforcement results and the
  Docker, Linux/WSL, and Windows host adapters used by lifecycle checks.
- [`lab/osapi/actions.py`](lab/osapi/actions.py) — typed, allowlisted native
  actions used by construction, boundary verification, and disposal.
- [`lab/osapi/`](lab/osapi/) — read-only Linux, Docker, Windows, and WSL
  observations and bounded command execution.
- [`lab/runtime.py`](lab/runtime.py) — persistent runtime lifecycle,
  experiment admission, policy pinning, resource reservations, and
  concurrency-safe state transitions.
- [`lab/evidence.py`](lab/evidence.py) — evidence hashing and controlled
  export.
- [`lab/dashboard.py`](lab/dashboard.py) — dashboard read models and action
  delegation; it has no Docker or shell execution access.
- [`lab/catalog/capabilities.yaml`](lab/catalog/capabilities.yaml) — approved
  reusable capability interfaces.
- [`lab/catalog/materials.yaml`](lab/catalog/materials.yaml) — explicitly
  approved experiment resources and artifacts; an empty catalog is valid.

## Quick start

```bash
cd /home/maximillien/security-lab
# If the engine dependency is not installed in the selected Python environment:
python3 -m pip install -r requirements-lab-engine.txt
if [[ ! -f config/lab.env ]]; then cp config/lab.env.example config/lab.env; fi
python3 lab/lab.py status
python3 lab/lab.py capabilities --json
python3 lab/lab.py materials
./scripts/preflight.sh
```

Before applying any network boundary, inspect the current WSL/Linux and Docker
environment without changing it:

```bash
python3 lab/lab.py networks discover
# Run `networks configure` only if machine.yaml is missing; otherwise review it.
python3 lab/lab.py networks validate-config
sudo -v
python3 lab/lab.py networks preflight
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

The machine file must contain the operator-confirmed Docker context and, where
used, the approved lab interfaces and Docker networks. It must not contain
invented interface names, addresses, gateways, or host firewall claims.
The preflight is a read-only check of the approved Docker context, default
network inventory, firewall command backends, and root-readable IPv4/IPv6
rules. It does not install rules or alter any Docker resource. The network plan
is read-only and reports whether the selected policy is supported. It is not
proof of live enforcement. A project-owned Docker network does not exist until
its investigation is constructed from a researcher-supplied specification.
`networks apply` requires that existing owned network and never creates it.
Construction creates the Compose network, applies and verifies the boundary,
and only then starts workloads.

For detailed, read-only operating-system observations, run:

```bash
python3 lab/lab.py os inspect
python3 lab/lab.py os inspect --project sec-lab-i-<id>
```

The report keeps Linux, Docker, Windows, and WSL observations separate.
Successful inventory collection is not a security verification; unavailable
platforms and unverified cross-boundary paths remain `UNKNOWN`.

The current supplied profiles remain unsupported for readiness because Windows
host isolation, dedicated DNS/proxy controls, and live runtime acceptance are
not implemented. The Linux adapter now uses owned IPv4/IPv6 chains ahead of
host and forwarding rules for the project bridge, but this structural
verification is not packet-level acceptance. Do not proceed to construction
unless the reviewed investigation policy only requests capabilities the plan
reports as supported. Disabling a boundary is an explicit reduction in
protection, not a claim that the adapter enforces it.

```bash
python3 lab/lab.py validate-investigation path/to/investigation.yaml
python3 lab/lab.py plan path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --output state/plans/local-study-01.json
# Continue only if the plan reports network_policy_supported: true.
export REQUIRE_RUNTIME_APPROVAL=true
python3 lab/lab.py construct-investigation path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --authorize "approved local construction after plan review"
python3 lab/lab.py networks verify sec-lab-i-local-study-01 --profile isolated
python3 lab/lab.py networks test sec-lab-i-local-study-01 --profile isolated \
  --authorize "approved local network acceptance"
```

Set `REQUIRE_RUNTIME_APPROVAL=true` in `config/lab.env` as well as the current
shell before construction. The specification's selected network profile must
match the profile used for later verification. Review the construction plan's
`network_policy_supported` field before proceeding. The currently supplied
profiles enable Windows-host, DNS, and proxy boundaries that the adapter
cannot enforce as distinct controls and require external runtime acceptance
that the adapter does not perform; the plan reports them as unsupported and
construction fails closed while they remain required. Do not
disable them unless the experiment explicitly does not require those guarantees;
doing so does not provide Windows-host, DNS, or proxy isolation. The adapter
does not control Windows Firewall, routes, unrelated networks, or global
firewall tables.

The adapter creates project-owned IPv4/IPv6 chains and checks their ordering in
the host `INPUT`, `OUTPUT`, and `FORWARD` paths. `controlled-access` restricted
rules, Windows Firewall, upstream VPN/routing controls, DNS/proxy-specific
enforcement, live acceptance, capture, and temporary maintenance access are
not implemented as verified capabilities and fail closed when required.

`networks test` verifies the already-applied owned boundary and inspects the
owned Docker network. It reports inconclusive and exits unsuccessfully because
the repository does not yet have a bounded live acceptance runner. Structural
firewall checks and unit tests do not establish actual packet blocking.

For command-driven technical work, initialize a disposable workspace without
any predefined workload:

```bash
python3 lab/lab.py experiment init local-study-01
python3 lab/lab.py experiment enter local-study-01
python3 lab/lab.py experiment inspect local-study-01
```

The returned workspace path is the experiment's mutable project area. The
researcher may create source files, scripts, datasets, and configuration there.
Collect selected outputs before lifecycle cleanup:

```bash
python3 lab/lab.py experiment collect local-study-01 path/to/result.log
python3 lab/lab.py experiment stop local-study-01
python3 lab/lab.py experiment reset local-study-01
python3 lab/lab.py experiment destroy local-study-01
```

`reset` removes mutable workspace contents but preserves the experiment
record and evidence. `destroy` removes the experiment workspace while retaining
selected evidence under `evidence-staging/experiments/<id>`.

For actual tool execution, use the explicit bounded Docker tool runner rather
than an unrestricted host shell:

```bash
python3 lab/lab.py experiment exec local-study-01 \
  --image approved/tool-image:tag \
  sh -c 'your-command'
```

The runner uses no network, no host mounts, a read-only root, dropped
capabilities, `no-new-privileges`, and CPU/memory/PID limits. Output and the
command are recorded under the experiment's `records/` directory. Image
availability and provenance must be separately approved.

Dispose only the owned investigation project:

```bash
python3 lab/lab.py dispose-investigation path/to/investigation.yaml \
  --investigation-id local-study-01
```

See [`lab-set.md`](lab-set.md) and [`docs/architecture.md`](docs/architecture.md)
for the full operating model.

## Optional local GUI

The optional Streamlit dashboard is a presentation client of the Python
control plane. It is not a second controller, does not access Docker directly,
does not execute arbitrary commands, and does not browse unrestricted files.
Install its separately pinned dependency set only if the GUI is needed:

```bash
python3 -m pip install -r requirements-lab-gui.txt
./scripts/gui.sh
```

Open `http://127.0.0.1:8501` from the Windows browser. The server binds to
loopback only, keeps XSRF protection enabled, disables usage telemetry, and
does not attach to experiment networks. Loopback forwarding from WSL to
Windows is not itself an authentication or isolation boundary.

## Current enforcement and limitations

Specification/Compose validation rejects disallowed constructs such as
published ports, host networking, host binds, Docker socket mounts, privileged
services, added capabilities, writable roots, and unbounded resource
declarations. That static validation is not runtime proof. The Linux/WSL
boundary adapter is limited to project-owned deny-mode IPv4/IPv6 bridge rules;
the supplied profiles request additional Windows-host, DNS, proxy, and
external-acceptance guarantees that are not currently implemented. As a
result, those profiles fail closed and workload construction is blocked while
those requirements remain enabled.

The native OS action interface uses typed allowlisted operations: scoped Linux
boundary-script apply/verify/remove, Docker Compose create/start/stop/down, and
approval-gated connect/disconnect for project-owned Docker network resources.
It does not expose arbitrary host shell execution. Native Windows mutations
and controls of another WSL distribution are unsupported. A Docker context
and its local socket/name checks do not prove the daemon's physical host.
Docker containers share the Linux kernel and WSL integrates with Windows; no
physical air-gap claim is made.

The controller does not pull images, install packages, modify Windows
firewalls/routes, change the Docker context, alter global WSL settings, or
perform global Docker pruning.

## Verification status

The repository test suite currently contains 135 tests covering researcher-
defined specification validation, capability/material catalogs, resource
resolution, machine configuration, enforcement planning and adapters, OS
observations and allowlisted actions, runtime admission, effective Docker
inspection, shell-controller contracts, state locking, policy provenance, and
static safety contracts. Tests use temporary repositories, mocked
Docker/boundary calls, and isolated shell fakes; they do not modify the host
firewall or install an operational experiment. Run them from WSL with
`python3 -m unittest discover -s tests`.

Actual Docker construction, image provenance, live network behavior, packet
capture, disposal on the target host, and Windows emergency-stop behavior
remain separately authorized runtime acceptance work. The dated host-specific
observations and their limitations are recorded in
[`docs/readiness-inventory.md`](docs/readiness-inventory.md); re-run discovery
and inspection before relying on them.
