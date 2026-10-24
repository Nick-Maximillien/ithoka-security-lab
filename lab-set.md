# Lab Operator Command Set

This is the operator entry point for the persistent security research lab. The
lab contains no predefined investigations, default experiment ID, workload, or
fixed Compose apparatus. A researcher supplies an investigation specification;
the lab validates, plans, constructs, observes, and disposes its temporary
apparatus.

## 1. Host and lab readiness

Run from the intended WSL/Linux checkout:

```bash
cd /home/maximillien/security-lab
cp config/lab.env.example config/lab.env
python3 lab/lab.py status
python3 lab/lab.py capabilities --json
./scripts/preflight.sh
python3 lab/lab.py networks discover
# Run `networks configure` only if machine.yaml is missing.
# Review operator_confirmed values, then:
python3 lab/lab.py networks validate-config
sudo -v
python3 lab/lab.py networks preflight
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

`preflight.sh` checks the Docker daemon, Compose availability, host inventory,
capacity, and persistent lab paths. It does not validate or construct an
investigation. `networks discover` is read-only. `machine.yaml` is the
operator-confirmed host-specific configuration and must not contain guessed
interfaces, addresses, gateways, or Docker network IDs. Docker images are not
pulled automatically. The supplied profile plan currently reports
`supported: false` because it requires Windows-host, DNS, proxy, and external
runtime-acceptance controls that are not implemented. Do not construct an
experiment until its reviewed effective policy reports supported; disabling
those controls means those guarantees are not provided.

## 2. Initialize a command-driven experiment

The researcher can start with an empty technical workspace. No template,
workload, or research-paper form is created:

```bash
python3 lab/lab.py experiment init local-study-01
python3 lab/lab.py experiment enter local-study-01
python3 lab/lab.py experiment inspect local-study-01
```

The returned workspace path is the mutable project area for source code,
scripts, datasets, configuration, and command-created technical work.

Execute tools through the bounded runner, not an unrestricted host shell:

```bash
python3 lab/lab.py experiment exec local-study-01 \
  --image approved/tool-image:tag \
  sh -c 'your-command'
```

Tool commands run without network access or host mounts, with read-only root,
dropped capabilities, `no-new-privileges`, and bounded resources. Their output
is recorded for later evidence collection.

## 3. Write an optional apparatus specification

Create a researcher-owned YAML file outside the installed lab resources, or
under an approved workspace path. It must declare:

- the research question and optional hypothesis;
- a backend and apparatus definition;
- requested resources and their provenance;
- declarative procedure operations;
- observations, evaluation, evidence, and safety requirements;
- resource budgets.

The apparatus Compose file is part of the submitted investigation and must
pass the lab's policy checks: internal networks, no published ports, no host
network, no host binds or Docker socket, non-root service user, dropped
capabilities, `no-new-privileges`, and bounded memory, CPU, and PIDs.

## 4. Validate and plan before apparatus creation

```bash
python3 lab/lab.py validate-investigation path/to/investigation.yaml
python3 lab/lab.py plan path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --output state/plans/local-study-01.json
```

The plan records the specification digest, resolved approved resources,
procedure, budget, authorization classes, and ownership identifier. Planning
does not create Docker resources.

## 5. Authorize and construct

Review the plan and dependency provenance. For runtime construction, set the
approval only after the review:

```bash
export REQUIRE_RUNTIME_APPROVAL=true
python3 lab/lab.py construct-investigation \
  path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --authorize "approved local construction after plan review"
```

The current Docker adapter creates only the Compose project named
`sec-lab-i-local-study-01`, with ownership scoped to that investigation ID.
No global Docker cleanup or automatic dependency acquisition is performed.
Before construction, the effective policy must pass adapter capability checks.
Actual image provenance, runtime behavior, and host isolation remain runtime
acceptance activities.

## 6. Network boundary apply and verification

Construction applies and verifies the required boundary after creating the
project network and before workload startup. A separate apply is not a setup
step and is only valid for an existing, uniquely owned project network. For
normal operation, inspect the boundary after construction:

```bash
python3 lab/lab.py networks verify sec-lab-i-local-study-01 \
  --profile isolated
python3 lab/lab.py networks test sec-lab-i-local-study-01 \
  --profile isolated \
  --authorize "approved local network acceptance"
```

The adapter requires Docker, `sudo`, `iptables`, and `ip6tables`, and records
the owned network identity under `state/network-boundary`. It does not modify
Windows Firewall, host routes, VPN settings, unrelated networks, or global
firewall tables. The supplied profiles currently require unsupported
Windows-host, DNS, and proxy capabilities; construction fails closed until
those requirements are resolved. `controlled-access`, capture, and temporary
maintenance operations are also rejected until their semantics can be applied
and verified.

## 7. Operate, observe, and preserve evidence

The workspace lifecycle is explicit:

```bash
python3 lab/lab.py experiment collect local-study-01 path/to/output.pcap
python3 lab/lab.py experiment stop local-study-01
python3 lab/lab.py experiment reset local-study-01
```

`stop` changes lifecycle state, while `reset` clears mutable workspace contents
and retains the experiment record and collected evidence.

## 8. Dispose by ownership

After execution and evidence review:

```bash
python3 lab/lab.py dispose-investigation \
  path/to/investigation.yaml \
  --investigation-id local-study-01
```

Disposal targets only that Compose project with `down --remove-orphans`.
Evidence must be staged outside the disposable runtime and archived separately:

```bash
python3 lab/lab.py archive path/to/evidence \
  --destination state/archives
```

The destination must already exist under the repository's approved archive
area; archives are hashed, independently re-verified after copying, and never
overwritten. Export outside the repository is not implemented by this
controller and requires a separately reviewed operator transfer procedure.

## 9. Retained operational tools

- `scripts/preflight.sh` — persistent lab/host readiness.
- `scripts/capture-start.sh` and `scripts/capture-stop.sh` — explicitly
  approved host-interface capture.
- `scripts/maintenance.sh` — dependency provenance and acquisition records.
- `scripts/incident.sh` — operator incident records.
- `host/EmergencyStop.ps1` — independently usable Windows/WSL escalation.

The lab does not claim a physical air gap. Containers share the Linux kernel,
and WSL integrates with Windows. Runtime containment, egress, firewall,
routing, capture completeness, and emergency-stop behavior require separate
authorized verification.

## 10. Optional local dashboard

Install the optional pinned GUI dependency and start the dashboard from WSL:

```bash
python3 -m pip install -r requirements-lab-gui.txt
./scripts/gui.sh
```

Open `http://127.0.0.1:8501` in a Windows browser. The dashboard binds only to
loopback and delegates every action to the Python control plane. It provides
status, readiness records, workspace records, plans, construction, stop/reset/
destroy confirmations, evidence collection, and hash/archive actions. It does
not provide a terminal, arbitrary shell execution, direct Docker access,
secrets, or unrestricted file browsing.
