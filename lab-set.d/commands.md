# System Command Reference

This is the command inventory for the operator workflows in [lab-set.md](../lab-set.md).
Run Python controller commands from the repository root in the intended Linux/
WSL distribution:

```bash
cd /home/maximillien/security-lab
python3 lab/lab.py <command>
```

The controller requires POSIX. It does not change Docker context or choose a
WSL distribution. Use `python3 lab/lab.py --help` and each subcommand's
`--help` for the installed parser's exact syntax. Placeholders such as
`<experiment-id>` and `<project>` are not literal values.

## Status, catalogs, and OS observation

| Command | Purpose and effect |
| --- | --- |
| `python3 lab/lab.py status [--json]` | Report lab/configuration, selected profile, policy support, host prerequisites, and readiness state. Does not establish runtime acceptance. |
| `python3 lab/lab.py capabilities [--json]` | Validate/list reusable operation and adapter capability declarations. |
| `python3 lab/lab.py materials [--json]` | List approved concrete materials. An empty catalog is valid. |
| `python3 lab/lab.py os inspect [--project <project>] [--context <context>]` | Collect structured read-only Linux, Docker, Windows, and WSL observations. Project inspection is optional and read-only. |
| `docker context show`, `docker info`, `docker compose version` | Independently inspect the active Docker context, daemon identity/version, and Compose availability. Read-only. |
| `./scripts/preflight.sh` | Record host/Docker inventory; check config, Docker/Compose, catalogs, policy definitions, and capacity warning. No construction or firewall mutation. |

OS observations can be unavailable. The command returns failure when the
report contains unknown or failed observations; read the structured result
instead of interpreting a nonzero status as proof that the host is unsafe or
safe.

## Network policy, discovery, and enforcement

All commands in this section start with `python3 lab/lab.py networks`.

| Subcommand | Arguments | Purpose and effects |
| --- | --- | --- |
| `profiles` | none | Resolve and report each profile's definition, enforcement support, and whether acceptance was evaluated. |
| `select` | `<profile>` | Validate policy/host requirements and change `config/networks/active-profile`. Affects future defaults only. |
| `show` | `[boundary]` | Show resolved effective policy, or one named boundary. |
| `boundaries` | none | List available boundary identifiers. |
| `validate` | none | Validate the network policy definitions; no host mutation. |
| `discover` | none | Read host, interface, routes, forwarding, firewall, Docker, and related network inventory where available. |
| `inspect-docker` | `<project>` | Read-only inspection of one Compose project's Docker context, ownership, network attachments, and effective container settings. |
| `configure` | `[--overwrite]` | Create operator machine configuration from the example/discovery. Do not overwrite reviewed host values without explicit review. |
| `validate-config` | none | Validate `machine.yaml` and operator-confirmed fields. |
| `preflight` | none | Read-only checks for approved Docker target, network inventory, firewall tools, and privilege to inspect rules. |
| `plan` | `[--profile <profile>] --output <path>` | Write an inspectable resolved enforcement plan. It does not apply enforcement. |
| `apply` | `<project> [--profile <profile>] --authorize <reason>` | Apply supported rules to an already-existing owned project network. A mutating, approval-gated action. |
| `verify` | `<project> [--profile <profile>]` | Verify supported structural/project state; not packet-level acceptance. |
| `remove` | `<project> --authorize <reason>` | Remove only matching recorded project-owned boundary state. Approval-gated mutation. |
| `test` | `<project> [--profile <profile>] --authorize <reason>` | Run implemented checks for an owned project; actual network acceptance remains inconclusive without packet probes. |
| `capabilities` | none | Report supported network operations and adapters. |
| `drift` | `<project>` | Compare the pinned policy/owned state with current resolved state. |
| `maintenance status` | none | Report maintenance state. |
| `maintenance enter` | none | Fail-closed placeholder; temporary policy apply is not supported. |
| `maintenance leave` | none | Fail-closed placeholder; temporary policy restoration is not supported. |

Typical read-only setup sequence:

```bash
python3 lab/lab.py networks discover
python3 lab/lab.py networks profiles
python3 lab/lab.py networks boundaries
python3 lab/lab.py networks show
python3 lab/lab.py networks validate
python3 lab/lab.py networks configure
python3 lab/lab.py networks validate-config
sudo -v
python3 lab/lab.py networks preflight
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

Run `configure` only when `config/networks/machine.yaml` is absent. The
currently supplied profiles request unsupported Windows-host, DNS, proxy, or
external-acceptance guarantees and ordinarily report unsupported; do not
weaken a required policy merely to activate a workload.

If an investigation is already constructed and support/authorization checks
pass, the project-specific sequence is:

```bash
python3 lab/lab.py networks verify sec-lab-i-<id> --profile <profile>
python3 lab/lab.py networks drift sec-lab-i-<id>
python3 lab/lab.py networks test sec-lab-i-<id> --profile <profile> \
  --authorize "approved acceptance check"
```

Do not manually call `apply` during ordinary construction: the construction
lifecycle owns network creation, boundary application and verification, and
workload startup ordering. The action layer uses a selected Docker context
explicitly, but that does not prove the daemon's physical host. The
Linux/WSL adapter is limited to owned deny-mode IPv4/IPv6 bridge rules.

## Investigation construction lifecycle

| Command | Purpose and effects |
| --- | --- |
| `python3 lab/lab.py validate-investigation <specification.yaml>` | Validate specification, resources, Compose apparatus, policy, and bounded operations. |
| `python3 lab/lab.py plan <specification.yaml> --investigation-id <id> --output <path>` | Generate a reviewable, ownership-scoped plan and pinned policy/provenance. Does not construct resources. |
| `python3 lab/lab.py construct-investigation <specification.yaml> --investigation-id <id> --authorize <reason>` | Create the owned Compose project if required approvals, policy support, and checks pass. |
| `python3 lab/lab.py dispose-investigation <specification.yaml> --investigation-id <id>` | Dispose only the corresponding owned Compose project; unrelated resources are not globally pruned. |

Construction approval is additionally controlled by
`REQUIRE_RUNTIME_APPROVAL=true`. Set it only after reviewing the plan and
dependency provenance. Keep the ID stable through plan, construction,
inspection, and disposal; the project name is derived as
`sec-lab-i-<id>`. The construction lifecycle orders network creation,
boundary apply/verify, Docker inspection, and service startup. Policy
unsupported, target mismatch, failed verification, or ownership uncertainty
must stop construction.

Current apparatus is Docker Compose. Specifications declare the research
question, apparatus, resources, declarative procedure, observations,
evaluation, evidence, safety, and resource budget. Arbitrary host shell
operations are not accepted. Materials and capabilities are separate
catalogs; registration alone does not prove image availability or provenance.

## Research workspace and evidence

| Command | Purpose and effects |
| --- | --- |
| `python3 lab/lab.py experiment init <id>` | Create a new empty researcher workspace. |
| `python3 lab/lab.py experiment enter <id>` | Print the workspace path. It does not change the parent shell's working directory. |
| `python3 lab/lab.py experiment inspect <id>` | Read its state, records, and evidence metadata. |
| `python3 lab/lab.py experiment exec <id> --image <image> <command> [args...]` | Run a bounded command in an image without network or host mounts, with read-only root and resource/security limits; records command/output. |
| `python3 lab/lab.py experiment collect <id> <path> [<path> ...]` | Collect selected paths and produce evidence metadata/manifest. |
| `python3 lab/lab.py experiment stop <id>` | Mark the workspace stopped. |
| `python3 lab/lab.py experiment reset <id>` | Clear mutable workspace contents; retain experiment record and staged evidence. |
| `python3 lab/lab.py experiment destroy <id>` | Remove the workspace while retaining selected evidence. |
| `python3 lab/lab.py archive <evidence-directory> [--destination <existing-dir>]` | Create and verify a manifest in the source evidence directory. If a destination is provided, also create a verified repository-local copy; refuses overwrite. |

The research workspace is distinct from a Compose investigation. `experiment
exec` is not an unrestricted shell and uses the selected image already
available to Docker; it does not pull or approve images. Collect evidence
before reset/destroy. External archive transfer is not implemented.

## Persistent Lab Runtime

| Command | Purpose and effects |
| --- | --- |
| `python3 lab/lab.py runtime status` | Read lifecycle/admission status. |
| `python3 lab/lab.py runtime configure` | Initialize persistent runtime state/configuration. |
| `python3 lab/lab.py runtime start` | Attempt readiness-gated runtime start. |
| `python3 lab/lab.py runtime verify` | Verify the current runtime and active records. |
| `python3 lab/lab.py runtime stop` | Stop only when active admissions and maintenance do not block it. |
| `python3 lab/lab.py runtime restart` | Restart through the runtime lifecycle checks. |
| `python3 lab/lab.py runtime recover` | Reconcile records that require recovery; inspect output and evidence. |
| `python3 lab/lab.py runtime inspect` | Inspect persistent runtime records and policy snapshots. |
| `python3 lab/lab.py runtime doctor` | Report runtime, admission, and recovery readiness. |
| `python3 lab/lab.py runtime admit-experiment <id> [--profile <profile>] [--memory-mib N] [--cpu-millicores N] [--pids N]` | Reserve capacity and pin policy for an experiment admission. |
| `python3 lab/lab.py runtime release-experiment <id>` | Release that admission; does not re-evaluate acceptance. |
| `python3 lab/lab.py runtime request-maintenance <operation-id> <experiment-id> [--destination <destination>]` | Record a scoped maintenance request; currently rejected because verified temporary restoration is unavailable. |

Runtime admission is distinct from Compose construction and the workspace
lifecycle. It is state/resource accounting; it does not start services.

## Shell operational scripts

Run these scripts from the repository checkout. They load `config/lab.env` if
present, otherwise the example configuration. `scripts/lib.sh` is a shared
library and is not an operator command.

| Command | Purpose and caution |
| --- | --- |
| `./scripts/preflight.sh` | Host/Docker and policy readiness checks; may create state/log output, but does not apply firewall rules. |
| `CAPTURE_APPROVAL=true ./scripts/capture-start.sh <interface>` | Start `tcpdump`/`tshark` on one explicitly selected interface; creates sensitive capture and metadata. |
| `./scripts/capture-stop.sh` | Request orderly stop for the recorded capture after validating PID, arguments, run, and path. Retains evidence. |
| `./scripts/maintenance.sh status` | Show dependency acquisition/closure records. |
| `./scripts/maintenance.sh check` | Check Docker/Compose availability and policy prerequisites; no download or grant. |
| `MAINTENANCE_APPROVAL=true ./scripts/maintenance.sh record <name> <dependency-reference> <source-or-registry> <digest-or-build-input>` | Record acquisition metadata only; does not download or verify dependencies. |
| `./scripts/maintenance.sh close` | Record closure and required follow-up checks; does not prove they passed. |
| `./scripts/incident.sh <incident-type>` | Create a private, non-overwriting incident record template; no containment action. |
| `./scripts/gui.sh` | Launch optional local Streamlit UI on loopback, default port 8501. |

`scripts/network-boundary.sh` is an internal fixed-argument controller used
through `lab/osapi/actions.py`. Do not invoke it as a general firewall
interface. It only supports the boundary action paths wired through the
allowlisted action executor and its ownership checks.

## Windows host emergency stop

Run only from an approved PowerShell session after confirming exact Docker
execution mode, context, project name, and (for WSL Docker) distribution:

```powershell
.\host\EmergencyStop.ps1 -Action StopLab `
  -ExecutionMode WslDocker `
  -Distribution "<confirmed-distribution>" `
  -DockerContext "<confirmed-context>" `
  -Project "sec-lab-i-<id>"
```

`StopLab` performs a project-scoped Compose stop and verifies that owned
containers are no longer running. `-ExecutionMode` must be `WindowsDocker` or
`WslDocker`; the latter requires `-Distribution`. `-Action ShutdownWsl
-Distribution <name>` is a separate, broad escalation that terminates the
entire selected WSL distribution, may interrupt unrelated workloads, and
requires typing the exact confirmation string. It is not normal cleanup.

## Local environment values

Review `config/lab.env.example` before copying it to `config/lab.env`.
Notable settings:

| Variable | Meaning |
| --- | --- |
| `LAB_PROJECT` | Fixed shell-controller project identifier. |
| `EVIDENCE_STAGING` | Repository-relative evidence root. |
| `REQUIRE_RUNTIME_APPROVAL` | Must be `true` for approved investigation construction. |
| `CAPTURE_APPROVAL`, `CAPTURE_INTERFACE`, `CAPTURE_TOOL` | Capture approval and optional default settings; review before enabling. |
| `MAINTENANCE_APPROVAL` | Required before recording a dependency acquisition entry. |
| `RESOURCE_MEMORY_WARN_PERCENT`, `RESOURCE_FREE_DISK_WARN_GB` | Capacity warning thresholds. |

Do not treat approval flags as authorization by themselves. They are a local
control in addition to operator approval, scope review, and policy capability
checks. Never commit local configuration or secrets.

## Developer checks

Run from the repository root in the intended Python environment:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q lab tests
git diff --check
```

The unit suite uses mocks and isolated fixtures for host-sensitive behavior;
it is not live acceptance. The engine's pinned Python dependency is listed in
`requirements-lab-engine.txt`. The separately pinned GUI dependency is in
`requirements-lab-gui.txt`.

## Status and capability vocabulary

- **PASS** means only that the named check passed for the state it inspected.
- **FAIL/ERROR** means stop and investigate; do not continue to construction.
- **UNKNOWN/NOT_TESTED/INCONCLUSIVE** means evidence is absent or incomplete,
  not that the control is effective.
- **BLOCKED/UNSUPPORTED** means the requested policy/action cannot proceed;
  do not bypass it by weakening required guarantees.

The Linux firewall action requires a local Unix-socket Docker endpoint,
daemon-name match to the Linux host, project ownership, and non-interactive
`sudo`. These checks do not establish the daemon's physical location. Docker
operations use context explicitly, and successful Docker authorization is not
OS elevation. Windows mutations and cross-distribution WSL controls are
unsupported.
