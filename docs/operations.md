# Operations

For the complete setup-to-disposal sequence, start with the
[operator guide](../lab-set.md). The full CLI and script inventory is in the
[system command reference](../lab-set.d/commands.md). This document summarizes
the lifecycle boundaries and readiness gates.

The lab lifecycle is independent of any investigation:

```bash
python3 lab/lab.py status
python3 lab/lab.py capabilities --json
./scripts/preflight.sh
python3 lab/lab.py validate-investigation path/to/investigation.yaml
python3 lab/lab.py plan path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --output state/plans/local-study-01.json
export REQUIRE_RUNTIME_APPROVAL=true
python3 lab/lab.py construct-investigation path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --authorize "reviewed construction plan"
python3 lab/lab.py dispose-investigation path/to/investigation.yaml \
  --investigation-id local-study-01
```

Construction and disposal operate on one investigator-assigned Compose project.
The lab does not globally prune Docker resources or acquire dependencies
without a separate approved maintenance action.

The persistent Lab Runtime is independent of any one experiment:

```bash
python3 lab/lab.py runtime configure
python3 lab/lab.py runtime start
python3 lab/lab.py runtime verify
python3 lab/lab.py runtime doctor
```

Before construction, use the network workflow:

```bash
python3 lab/lab.py os inspect
python3 lab/lab.py networks discover
python3 lab/lab.py networks profiles
python3 lab/lab.py networks configure  # only if machine.yaml is absent
python3 lab/lab.py networks validate-config
sudo -v
python3 lab/lab.py networks preflight
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

For a read-only OS and Docker inventory, run:

```bash
python3 lab/lab.py os inspect
python3 lab/lab.py os inspect --project sec-lab-i-<id>
```

This does not change host state. A platform or subsystem result of `UNKNOWN`
means its state could not be established; do not treat it as a pass.

Discovery, validation, preflight, and plan generation do not create networks
or apply firewall rules. The plan reports policy support; the currently
supplied profiles require unsupported Windows-host, DNS, proxy, and external
runtime-acceptance controls and therefore cannot be used to construct workloads
while those boundaries remain required. An unsupported plan is saved for
inspection but returns a failing command status; do not proceed based on a
generated plan alone.
Project `networks apply` and `verify` require the already-created, owned
experiment network. Construction owns the required ordering and will not
start services unless boundary application and verification succeed.

Experiments must be admitted with explicit resource reservations before
runtime-owned shared capacity is allocated. Admission pins the selected
effective policy, its provenance identity, required capability, enforcement
scope, and resource reservation. `active-profile` is only the default for new
requests; changing it does not mutate pinned experiment policies. Profile names
alone do not conflict: admission compares effective requirements and shared
enforcement resources. A maintenance profile is a peer profile and follows the
same admission path. A maintenance request is instead scoped to an experiment
and operation ID; unsupported temporary enforcement is rejected and audited
rather than opening a global maintenance route.

Before services start, construction creates the project network and stopped
containers, then invokes the typed OS action executor, which runs the existing
fixed-argument `scripts/network-boundary.sh` for apply and verify. Operators
should not invoke that internal script as a general firewall interface. The
construction path writes the resolved policy beside the runtime file and
passes that policy to the adapter, so profile and investigation changes alter
the adapter request without editing controller source.
The controller inspects effective Docker settings before readiness and again
after workloads start. Inspect an existing project manually with
`python3 lab/lab.py networks inspect-docker sec-lab-i-<id>`; a missing or
unexpected state is reported as `UNKNOWN`, `BLOCKED`, or `FAIL`, never as a
successful isolation result.
The controller requires `sudo`, Docker, `iptables`, and `ip6tables`, and
records the exact owned bridge and network identity under
`state/network-boundary`. A failed or unverifiable boundary prevents startup.
Disposal removes only rules whose project, bridge, network identity, and
ownership labels still match; cleanup errors are reported rather than ignored.

Evidence is staged outside the disposable project and archived with
`lab.py archive` only to an existing archive directory under the repository.
The controller rejects external destinations; any transfer beyond the
repository is a separate, approved operator procedure. Docker/WSL runtime
containment and workload observations remain acceptance tasks, not claims made
by static validation.

Only deny-mode IPv4/IPv6 bridge enforcement is currently supported by the
Linux/WSL adapter. Observation capture requires an installed `tcpdump` or
`tshark` and is separately scoped; restricted controlled access, Windows-host
controls, upstream routing, and temporary maintenance restoration fail closed.

The typed action layer also restricts Docker Compose lifecycle calls to the
approved create/start/stop/down operations and restricts network attachment
changes to explicitly approved, ID-addressed resources whose ownership labels
match the project. It runs with a resolved Docker context; this does not prove
the daemon's physical host. Windows mutations and cross-distribution WSL
control return explicit unsupported results.

The `experiment` workspace commands form a separate, non-Compose workflow.
They initialize an empty researcher workspace, run only bounded no-network
Docker tools, collect selected evidence, and keep stop/reset/destroy distinct.
The persistent Lab Runtime's admission and reservations are also separate;
neither feature should be assumed to automatically construct the other.
