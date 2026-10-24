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
- [`lab/runtime.py`](lab/runtime.py) — persistent runtime lifecycle,
  experiment admission, policy pinning, resource reservations, and
  concurrency-safe state transitions.
- [`lab/evidence.py`](lab/evidence.py) — evidence hashing and controlled
  export.
- [`lab/dashboard.py`](lab/dashboard.py) — dashboard read models and action
  delegation; it has no Docker or shell execution access.
- [`lab/catalog/capabilities.yaml`](lab/catalog/capabilities.yaml) — approved
  reusable capability interfaces.

## Quick start

```bash
cd /home/maximillien/security-lab
cp config/lab.env.example config/lab.env
python3 lab/lab.py status
python3 lab/lab.py capabilities --json
./scripts/preflight.sh
```

Before applying any network boundary, inspect the current WSL/Linux and Docker
environment without changing it:

```bash
python3 lab/lab.py networks discover
python3 lab/lab.py networks configure
# Edit operator_confirmed in config/networks/machine.yaml.
python3 lab/lab.py networks validate-config
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

The machine file must contain the operator-confirmed Docker context and, where
used, the approved lab interfaces and Docker networks. It must not contain
invented interface names, addresses, gateways, or host firewall claims.
Review the generated plan before an explicitly authorized scoped operation:

```bash
python3 lab/lab.py networks apply sec-lab-i-local-study-01 \
  --profile isolated --authorize "reviewed local boundary plan"
python3 lab/lab.py networks verify sec-lab-i-local-study-01 \
  --profile isolated
python3 lab/lab.py networks test sec-lab-i-local-study-01 \
  --profile isolated \
  --authorize "approved local network acceptance"
```

Apply and verify require the intended Linux/WSL environment, Docker network
ownership, `sudo`, `iptables`, and `ip6tables`; they do not alter Windows
Firewall, routes, unrelated networks, or global firewall tables.

The supported adapter currently verifies project-scoped deny-mode IPv4 and
IPv6 bridge rules. `controlled-access` restricted rules, Windows Firewall,
upstream VPN/routing controls, and temporary maintenance access are not
implemented as verified capabilities and fail closed.

`networks test` verifies the already-applied owned boundary and inspects the
owned Docker network. It does not create disposable containers or probe
arbitrary external targets. Workload-specific connectivity tests belong in the
researcher-defined investigation and must be recorded as evidence.

Then submit a researcher-defined specification:

```bash
python3 lab/lab.py validate-investigation path/to/investigation.yaml
python3 lab/lab.py plan path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --output state/plans/local-study-01.json
```

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

Construction requires explicit authorization and
`REQUIRE_RUNTIME_APPROVAL=true`:

```bash
export REQUIRE_RUNTIME_APPROVAL=true
python3 lab/lab.py construct-investigation path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --authorize "approved local construction after plan review"
```

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

## Safety boundary

The lab enforces internal Docker networking, rejects published ports, host
networking, host binds, Docker socket mounts, added capabilities, privileged
services, writable roots, and unbounded resource declarations. Docker is not a
complete security boundary: containers share the host kernel and WSL
integrates with Windows. No physical air-gap claim is made.

The controller does not pull images, install packages, modify Windows
firewalls/routes, change the Docker context, alter global WSL settings, or
perform global Docker pruning.

## Verification status

The repository test suite currently contains 38 tests covering researcher-
defined specification validation, policy resolution, machine configuration,
enforcement-plan generation, runtime admission, state locking, policy
provenance, and static safety contracts. Tests use temporary repositories and
mocked Docker/boundary calls; they do not modify the host firewall or install
an operational experiment.

Actual Docker construction, image provenance, live network behavior, packet
capture, disposal on the target host, and Windows emergency-stop behavior
remain separately authorized runtime acceptance work.
