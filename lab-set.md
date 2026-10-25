# Lab Operator Guide

This guide takes an operator from checkout and host discovery through network
policy review, experiment setup, observation, evidence preservation, and
cleanup. The complete command inventory is in
[lab-set.d/commands.md](lab-set.d/commands.md); technical details and limits
are linked in [Project documentation](#project-documentation).

The control plane runs from the intended Linux/WSL checkout. It does not
switch Docker contexts, install tools, pull images, alter Windows firewall or
routes, or make global Docker changes. Treat every command result as evidence
only for what that command actually observed. `UNKNOWN`, `NOT_TESTED`,
`BLOCKED`, or `UNSUPPORTED` is never a pass.

## 0. Stop gates and operating model

There are two separate experiment surfaces:

1. **Investigation construction** validates a researcher-authored YAML
   specification and Compose apparatus, plans it, and manages one
   ownership-scoped Docker Compose project.
2. **Research workspace** provides a separate empty workspace and a bounded
   no-network Docker tool runner. It does not create the investigation
   apparatus or implement a general-purpose terminal.

The persistent Lab Runtime and its admission/resource accounting are a third,
separate lifecycle. Do not assume that using one surface automatically starts
or admits another.

Before any construction or network mutation, stop unless all of these are
true:

- You have confirmed the checkout, WSL distribution, Docker context, daemon
  target, intended project ID, and authorization.
- Host-specific configuration is based on current discovery and an operator
  has reviewed it.
- The effective policy is valid **and supported** by the adapter. A saved plan
  or a profile name is not a support result.
- The target is owned by this lab and its runtime settings have been
  inspected.
- You understand what remains unverified. Do not disable a required boundary
  merely to make the policy pass.

Currently supplied profiles request Windows-host, DNS, proxy, or external
runtime-acceptance controls beyond the implemented adapter. They therefore
fail closed while those controls remain enabled. Linux/WSL mutation is limited
to project-owned deny-mode IPv4/IPv6 bridge rules. There is no live packet
acceptance runner. Native Windows mutations and control of another WSL
distribution are unsupported. No physical air gap or host isolation is
claimed.

## 1. Prepare the checkout and inspect readiness

Run from the intended WSL/Linux distribution:

```bash
cd /home/maximillien/security-lab
# If the engine dependency is not installed in the selected Python environment:
python3 -m pip install -r requirements-lab-engine.txt
if [[ ! -f config/lab.env ]]; then cp config/lab.env.example config/lab.env; fi
python3 lab/lab.py --help
python3 lab/lab.py status --json
python3 lab/lab.py capabilities --json
python3 lab/lab.py materials --json
docker context show
docker info --format 'name={{.Name}} os={{.OperatingSystem}} server={{.ServerVersion}}'
docker compose version
./scripts/preflight.sh
```

Use a private, untracked `config/lab.env` for local values. Review
`config/lab.env.example` before changing project IDs, evidence paths, approval
flags, capture settings, or warning thresholds. Keep `REQUIRE_RUNTIME_APPROVAL`
false until the reviewed plan is ready for an authorized construction action.
Do not add secrets to policy, specification, or evidence files.

`preflight.sh` records host/Docker inventory and checks repository
configuration, Docker/Compose availability, policy definitions, and capacity
warnings. It does not construct an experiment, apply firewall rules, or prove
isolation. Confirm the context and daemon target from the displayed outputs;
do not change the context as a workaround. A successful `status` similarly
reports static configuration and host prerequisites; it is not runtime
acceptance.

## 2. Discover and record the network environment

First collect read-only observations:

```bash
python3 lab/lab.py os inspect
python3 lab/lab.py networks discover
python3 lab/lab.py networks profiles
python3 lab/lab.py networks boundaries
python3 lab/lab.py networks show
python3 lab/lab.py networks capabilities
```

Optional Docker project inspection is scoped to a named project and context:

```bash
python3 lab/lab.py os inspect --project sec-lab-i-<investigation-id>
python3 lab/lab.py os inspect --project sec-lab-i-<investigation-id> \
  --context <confirmed-docker-context>
python3 lab/lab.py networks inspect-docker sec-lab-i-<investigation-id>
```

OS inspection collects structured Linux, Docker, Windows, and WSL observations;
it does not mutate them. Docker project inspection evaluates effective
container/network settings and ownership. Neither report demonstrates actual
packet blocking or proves where a Docker daemon physically runs.

Create the machine configuration only if it does not exist:

```bash
python3 lab/lab.py networks configure
```

Review `config/networks/machine.yaml` against the read-only discovery and the
actual Docker context. Only enter operator-confirmed values; do not guess
interfaces, networks, addresses, routes, or host firewall capabilities.
Validate and preflight:

```bash
python3 lab/lab.py networks validate-config
sudo -v
python3 lab/lab.py networks preflight
```

The network preflight is read-only. `sudo -v` checks interactive privilege
availability; it does not install rules. Preflight checks the configured
target, Docker networks, firewall tools, and ability to read rules. It does
not change firewall state.

## 3. Understand and configure profiles

Network configuration has three layers:

- `config/networks/boundaries/*.yaml` defines the canonical boundary
  requirements.
- `config/networks/profiles/*.yaml` selects boundary files and may define
  explicit overrides.
- `config/networks/active-profile` chooses the default for new requests.

Inspect before editing:

```bash
python3 lab/lab.py networks profiles
python3 lab/lab.py networks show
python3 lab/lab.py networks show dns
python3 lab/lab.py networks validate
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

Profile resolution combines the selected profile, boundary definitions,
investigation overrides, and any applicable temporary scope; it records input
provenance. Changing `active-profile` affects future requests, not the policy
pinned to an existing investigation. `networks select <profile>` changes the
default only after policy and host checks succeed. It is not an enforcement
command. For a profile that passes those checks, the command is:

```bash
python3 lab/lab.py networks select <supported-profile>
```

Do not create a profile by weakening a required security property to bypass an
unsupported-capability error. The current adapter enforces only scoped
deny-mode IPv4/IPv6 bridge rules. `allow`, `restricted`, and `monitor`
semantics, Windows Firewall, upstream VPN/routing, dedicated DNS/proxy
enforcement, and live external acceptance are unavailable. Construction must
remain blocked whenever the research requirement depends on one of these
controls.

## 4. Plan network enforcement and probe only authorized targets

Generate a plan and inspect its output before considering any mutation:

```bash
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

The plan is a capability/readiness report, not an applied policy. A successful
`networks discover`, `preflight`, `validate`, or `plan` is not a network
acceptance test. `networks test` currently does not provide bounded live
packet probes; it verifies available structural/runtime observations and
reports acceptance as inconclusive when actual behavior is not tested.

Only after selecting an explicitly authorized, supported policy and confirming
the exact owned project may an operator apply/remove rules:

```bash
python3 lab/lab.py networks apply sec-lab-i-<investigation-id> \
  --profile <supported-profile> \
  --authorize "reason and change approval"
python3 lab/lab.py networks verify sec-lab-i-<investigation-id> \
  --profile <supported-profile>
python3 lab/lab.py networks drift sec-lab-i-<investigation-id>
python3 lab/lab.py networks remove sec-lab-i-<investigation-id> \
  --authorize "reason and cleanup approval"
```

`apply` requires the already-created project-owned network; it does not create
one. It is normally performed by the construction lifecycle after it creates
the owned network and stopped containers, and before starting services. Do
not manually apply rules to an unrelated project or use a profile different
from the investigation's resolved policy. Removal is ownership-scoped and
fails closed if recorded identities no longer match.

`networks test <project> --profile <profile> --authorize <reason>` may be run
only for an authorized owned project. Interpret its report literally: a
structural firewall check is not proof that traffic is blocked end to end.
Never probe networks outside the scope you are authorized to assess.

Network maintenance requests are not a temporary firewall opening:

```bash
python3 lab/lab.py networks maintenance status
python3 lab/lab.py runtime request-maintenance <operation-id> \
  <experiment-id> --destination <approved-destination>
```

Temporary maintenance apply, expiry, restoration, and independent verification
are unsupported; requests fail closed and are recorded. Do not substitute
direct host firewall changes.

## 5. Set up the persistent Lab Runtime (optional, separate lifecycle)

The runtime holds persistent lab state, pinned policies, admission records,
resource reservations, and audit history. Inspect it before attempting a
transition:

```bash
python3 lab/lab.py runtime status
python3 lab/lab.py runtime inspect
python3 lab/lab.py runtime doctor
```

Initialize/start/verify only when the environment has separately met its
readiness and acceptance prerequisites:

```bash
python3 lab/lab.py runtime configure
python3 lab/lab.py runtime start
python3 lab/lab.py runtime verify
```

Admit a planned experiment with explicit reservations, then release that
admission when the experiment is complete:

```bash
python3 lab/lab.py runtime admit-experiment <experiment-id> \
  --profile <profile> \
  --memory-mib <MiB> \
  --cpu-millicores <millicores> \
  --pids <count>
python3 lab/lab.py runtime release-experiment <experiment-id>
```

Admission pins the effective policy and checks shared resource conflicts. It
does not by itself construct Docker services or prove runtime isolation.
`runtime stop` is blocked while active experiment admissions or maintenance
remain. `restart`, `recover`, and `doctor` are state/recovery tools, not a
substitute for inspecting their reports.

## 6. Author, validate, and plan an investigation

Write a researcher-owned specification and apparatus; the repository provides
no default experiment template or workload. Keep the specification in a
reviewed location and do not put secrets in it. The required top-level
sections are `schema_version`, `investigation`, `apparatus`, `resources`,
`procedure`, `observations`, `evaluation`, `evidence`, `safety`, and
`resource_budget`. The current apparatus backend is `docker.compose`; procedure
operations are declarative and bounded, not arbitrary host shell commands.

Validate and plan using a unique investigator-assigned ID:

```bash
python3 lab/lab.py validate-investigation path/to/investigation.yaml
python3 lab/lab.py plan path/to/investigation.yaml \
  --investigation-id <unique-id> \
  --output state/plans/<unique-id>.json
```

Review specification digest, resource/material resolutions, image references
and provenance, topology, procedure, limits, approvals, ownership, resolved
network policy, provenance hashes, `network_policy_supported`, and any
capability error. Capabilities describe operations/adapters; materials
describe approved resources and may be an empty catalog. An image name or
capability ID is not automatically an approved material. Images are not
automatically pulled or built.

Do not proceed if validation fails, the plan is unsupported, the selected
policy differs from the intended experiment, provenance is unresolved, or an
observed target does not match the approved target.

## 7. Authorize and construct the disposable apparatus

Set runtime approval only for the current authorized operation, and keep the
setting in both the local config and current shell. Edit the local,
untracked `config/lab.env` to set `REQUIRE_RUNTIME_APPROVAL=true`, then:

```bash
export REQUIRE_RUNTIME_APPROVAL=true
python3 lab/lab.py construct-investigation \
  path/to/investigation.yaml \
  --investigation-id <unique-id> \
  --authorize "approved construction after plan and provenance review"
```

Construction is scoped to the generated Compose project, for example
`sec-lab-i-<unique-id>`. It does not globally prune Docker objects. The
lifecycle creates the owned network and stopped containers, applies and
verifies the supported boundary, inspects effective Docker settings, and only
then starts services. If policy support, ownership, firewall application, or
effective settings fail, it must not activate the workload.

Afterward inspect the exact project and policy:

```bash
python3 lab/lab.py networks inspect-docker sec-lab-i-<unique-id>
python3 lab/lab.py networks verify sec-lab-i-<unique-id> \
  --profile <selected-profile>
python3 lab/lab.py networks drift sec-lab-i-<unique-id>
```

These are not packet-level tests. No general-purpose active acceptance probe
is currently implemented.

## 8. Conduct work in a bounded researcher workspace (optional path)

This workspace is separate from Compose investigation construction:

```bash
python3 lab/lab.py experiment init <experiment-id>
python3 lab/lab.py experiment inspect <experiment-id>
python3 lab/lab.py experiment enter <experiment-id>
```

The returned directory is researcher-owned and initially empty. The bounded
tool runner executes an explicitly selected, already available image without
network access or host mounts, with a read-only root, dropped capabilities,
`no-new-privileges`, and resource limits:

```bash
python3 lab/lab.py experiment exec <experiment-id> \
  --image <approved-image-reference> \
  <command> [arguments...]
```

The command and result are recorded. This is not unrestricted host execution.
Review image approval, availability, and provenance before use.

Collect only the intended output paths; inspect the manifest and records:

```bash
python3 lab/lab.py experiment collect <experiment-id> path/to/result.log
python3 lab/lab.py experiment inspect <experiment-id>
```

`stop` marks the workspace stopped. `reset` clears mutable workspace contents
while retaining its record and staged evidence. `destroy` removes the
workspace while preserving selected evidence in
`evidence-staging/experiments/<id>`. Collect evidence before reset/destroy.

## 9. Observe, capture, and record events

Use the read-only inventory commands at the start and end of an authorized
run. To capture a specific interface, first review scope, sensitivity, output
storage, and tool availability; set `CAPTURE_APPROVAL=true` only for the
approved capture:

```bash
CAPTURE_APPROVAL=true ./scripts/capture-start.sh <interface>
./scripts/capture-stop.sh
```

Capture is host-interface scoped and may include sensitive traffic. It is
stored under the configured evidence staging area with metadata. Stale or
mismatched process state causes a fail-closed stop; investigate rather than
deleting PID/state files blindly.

Create an incident record when needed:

```bash
./scripts/incident.sh <incident-type>
```

The script creates a private, non-overwriting record with sections for
observations, containment, residual resources, evidence, recovery decision,
and follow-up. It does not contain or perform containment actions.

## 10. Stop, dispose, archive, and recover

Stop the exact workspace or Compose investigation; then dispose only the
owned project:

```bash
python3 lab/lab.py experiment stop <experiment-id>
python3 lab/lab.py dispose-investigation \
  path/to/investigation.yaml \
  --investigation-id <unique-id>
```

Disposal uses the investigation specification and ownership labels. Do not
replace it with `docker system prune`, broad deletion, global firewall edits,
or WSL unregister/shutdown.

Archive staged evidence to an existing repository-local archive directory:

```bash
python3 lab/lab.py archive path/to/evidence \
  --destination state/archives
```

The archive operation hashes files, verifies copied contents, and refuses
overwrites. External transfer is a separate reviewed procedure. See
[Evidence handling](docs/evidence-handling.md) before handling sensitive
captures or transferring results.

For targeted Windows-side escalation, first verify the exact execution mode,
Docker context, Compose project, and (for WSL-hosted Docker) distribution:

```powershell
.\host\EmergencyStop.ps1 -Action StopLab `
  -ExecutionMode WslDocker `
  -Distribution "<confirmed-distribution>" `
  -DockerContext "<confirmed-context>" `
  -Project "sec-lab-i-<unique-id>"
```

`StopLab` is project-scoped and verifies that owned containers are stopped.
`ShutdownWsl` terminates the entire explicitly selected distribution and can
affect unrelated workloads; it requires exact interactive confirmation and
is an escalation only, not routine cleanup. See
[Recovery](docs/recovery.md).

## 11. Optional tools and recurring maintenance

The Streamlit dashboard is optional and delegates to the same Python control
plane. Install the GUI dependency set only when needed:

```bash
python3 -m pip install -r requirements-lab-gui.txt
./scripts/gui.sh
```

It binds to loopback (`127.0.0.1`), has XSRF protection enabled, and provides
no terminal or direct Docker access. Loopback forwarding is not
authentication.

Dependency maintenance scripts record approvals and provenance; they do not
install or download packages:

```bash
./scripts/maintenance.sh status
./scripts/maintenance.sh check
MAINTENANCE_APPROVAL=true ./scripts/maintenance.sh record \
  <name> <dependency-reference> <source-or-registry> <digest-or-build-input>
./scripts/maintenance.sh close
```

`record` stores metadata only; `close` records required follow-up checks and
does not claim they passed. Do not use it as a network access grant.

## 12. Project documentation

- [System command reference](lab-set.d/commands.md) — every command and
  argument shape.
- [Architecture](docs/architecture.md) — components and lifecycle boundaries.
- [Investigation authoring](docs/experiment-authoring.md) — schema and
  Compose constraints.
- [Network boundaries](docs/network-boundaries.md) and
  [network configuration guide](config/networks/README.md) — profiles,
  boundaries, support limits, and policy provenance.
- [Enforcement gap register](docs/enforcement-gap-register.md) — owner,
  implementation, verification, and known gaps for each boundary.
- [Operations](docs/operations.md) — lifecycle and persistent runtime notes.
- [Evidence handling](docs/evidence-handling.md) — staging, integrity, and
  archive rules.
- [Recovery](docs/recovery.md) — targeted recovery and escalation.
- [Threat model](docs/threat-model.md) — assumptions, trust boundaries, and
  residual risks.
- [Implementation status](docs/implementation-status.md),
  [readiness inventory](docs/readiness-inventory.md), and
  [final readiness](docs/final-readiness.md) — current engineering and
  acceptance state.
