# Operations

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
python3 lab/lab.py networks discover
python3 lab/lab.py networks configure
python3 lab/lab.py networks validate-config
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

Discovery, configuration validation, and plan generation are read-only. Apply
and verify require explicit authorization and operate only on an owned project
network:

```bash
python3 lab/lab.py networks apply sec-lab-i-local-study-01 \
  --profile isolated --authorize "reviewed boundary plan"
python3 lab/lab.py networks verify sec-lab-i-local-study-01 \
  --profile isolated
```

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
containers, then invokes `scripts/network-boundary.sh apply` and `verify`.
It writes the resolved policy beside the runtime file and passes that policy
to the adapter, so profile and investigation changes alter the adapter request
without editing controller source.
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
