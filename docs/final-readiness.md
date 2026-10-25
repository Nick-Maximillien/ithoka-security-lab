# Final Runtime Readiness

This document records the current engineering readiness. It is not a runtime
acceptance certificate. Docker construction, network containment, image
provenance, evidence capture, and host recovery still require an explicitly
authorized operator phase in WSL.

## Repairs made

- Hardened Compose validation against malformed networks, extra networks,
  root users, explicit network modes, Windows-style host paths, and malformed
  volume entries.
- Enforced the configured lab resource ceilings during specification
  validation and constrained investigation identifiers to the documented
  format.
- Made construction require `REQUIRE_RUNTIME_APPROVAL=true` for every
  investigation, rather than only specifications that list a particular
  approval entry.
- Reworked archive verification to recalculate every copied file digest and
  remove a partial archive on verification failure.
- Changed `status` to distinguish static configuration from untested runtime
  readiness.
- Corrected emergency-stop ownership verification to use Docker Compose's
  actual project label, added Docker context probing for `StopLab`, and made
  the Compose project explicit. `ShutdownWsl` remains a separate,
  distribution-confirmed escalation.
- Added regression tests for malformed Compose input, approval enforcement, and
  archive verification.
- Reconciled archive and recovery documentation with the repository-scoped
  export boundary and the commands that actually exist.
- Added network discovery, machine-specific configuration validation,
  inspectable enforcement plans, scoped apply/verify/remove commands, policy
  provenance metadata, and runtime admission locking.
- Integrated distinct capability and material catalogs. Resource references
  resolve only to explicitly registered, available materials; an empty
  materials catalog remains valid.
- Repaired shell-controller parsing and state handling, aligned maintenance
  record fields with policy, and added isolated shell regression coverage.
- Restored Compose validation in the validation module and kept unsupported
  runtime boundaries fail-closed.
- Added read-only inspection of effective Docker project state, wired it into
  pre-readiness and post-start lifecycle gates, and added mock coverage for
  context refusal, effective-settings violations, incomplete state, and
  containment after a post-start failure.
- Added `lab/enforcement/` with typed scope/result contracts and Docker,
  Linux/WSL, and read-only Windows host adapters; documented each boundary's
  owner, verification state, and restoration behavior.
- Added `lab/osapi/` with structured Linux, Docker, Windows, and WSL
  observations, shell-free bounded command execution, and the read-only
  `os inspect` command. Linux apply/verify/remove now checks a fresh
  IPv4/IPv6 ruleset for the project-owned chains after the boundary script.

## Verification results

The repository test, syntax, and diff checks listed here were rerun on
2026-10-25. Host and Docker observations below are recorded snapshots and must
be refreshed before operational use.

Commands run from the Windows-hosted workspace through WSL:

| Command | Result |
| --- | --- |
| `python3 -m unittest discover -s tests -v` | **PASS — 135 tests** |
| `python3 -m compileall -q lab tests` | **PASS** |
| `python3 lab/lab.py networks inspect-docker sec-lab-i-no-resources` | **UNKNOWN — no owned project network exists** |
| `python3 lab/lab.py os inspect` | **Valid read-only JSON; exit 1 because firewall and cross-boundary observations are UNKNOWN** |

No Docker construction, image pull/build, capture, host-network change,
destructive lifecycle action, WSL shutdown, or emergency stop was executed.
No network acceptance test was run. The Docker inspection is implemented and
mock-tested, but there was no project container to verify live. `pytest` is
not required; the repository's unittest suite was used. Live OS inspection
could read the Docker daemon and most Linux/Windows inventories, but Linux and
Windows firewall reads were unavailable and WSL networking/boundary assessment
remained `UNKNOWN`. No host firewall or network changes were made.

## Capability status

| Area | Implemented? | Unit-tested? | Integration-tested? | Runtime-tested? | Remaining limitation |
| --- | --- | --- | --- | --- | --- |
| CLI | Yes | Partial | No | No | Must be exercised from intended WSL checkout |
| Specification validation | Yes | Yes | Partial | No | Runtime Compose parser behavior remains unverified |
| Capability catalog | Yes | Yes | No | No | Adapter/runtime enforcement is not established by registration |
| Materials catalog | Yes | Yes | No | No | Registration does not prove runtime presence or provenance |
| Resource resolution | Yes | Yes | No | No | Image/material provenance and presence require operator acceptance |
| Construction | Yes | Partial/mock | No | No | Docker project and effective limits require acceptance |
| Disposal | Yes | No | No | No | Ownership and orphan behavior require target-host verification |
| Workspace lifecycle | Yes | Yes | No | No | Host filesystem recovery remains untested |
| Evidence collection | Yes | Partial | No | No | Runtime capture completeness is unknown |
| Archive verification | Yes | Yes | No | No | External transfer is intentionally not implemented |
| Dashboard | Yes, optional | Partial | No | No | Streamlit dependency/import and rerun behavior need operator environment testing |
| Operational scripts | Yes | Syntax only | No | No | Docker, capture, and host state checks remain untested |
| Emergency stop | Yes | Static policy only | No | No | Windows/WSL execution and ownership verification remain untested |
| Docker runtime inspection | Yes | Yes | No | Partial/read-only | No lab-owned project network or container was available |
| Runtime policy | Policy resolution, scoped adapter path, and admission locking | Yes | Mocked only | No | Live Docker/firewall acceptance is pending |

## Runtime blockers

The following must block a relevant investigation until verified:

1. The approved Docker context is `default`, and the daemon ID was observed,
   but that daemon identity is not pinned in machine configuration or separately
   operator-confirmed.
2. Submitted images do not have reviewed provenance and availability records.
3. Effective Compose resource limits, network egress behavior, published-port
   absence, and host-mount absence have not been observed at runtime.
4. Ownership-scoped stop/disposal and orphan cleanup have not been tested on
   the target Docker environment.
5. Packet-capture visibility and evidence survival through stop/reset/disposal
   have not been accepted.
6. Windows emergency-stop behavior, logging, and the explicit WSL shutdown
   escalation have not been accepted.

Catalog entries describe approved intent only. They do not prove that an
adapter is active, a resource is present, or an experiment has passed runtime
acceptance.

## Next operator sequence

Run from the intended WSL checkout. Do not set runtime approval until the plan
and dependency provenance have been reviewed:

```bash
cd /home/maximillien/security-lab
cp config/lab.env.example config/lab.env
python3 lab/lab.py status --json
python3 lab/lab.py capabilities --json
./scripts/preflight.sh
python3 lab/lab.py validate-investigation path/to/investigation.yaml
python3 lab/lab.py plan path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --output state/plans/local-study-01.json
```

Review the plan, resources, image provenance, and host inventory. At a separate
operator decision point, set `REQUIRE_RUNTIME_APPROVAL=true` and run the
authorized construction command from [lab-set.md](../lab-set.md). Observe and
record runtime behavior before collecting evidence. Dispose only the exact
generated project after review, then archive to an existing repository-local
archive directory. Do not use global Docker cleanup, change host networking,
or shut down WSL as part of routine acceptance.

## Acceptance matrix

| ID | Requirement | Verification method | Expected result | Actual status | Evidence | Next action |
| --- | --- | --- | --- | --- | --- | --- |
| VR-01 | Generic synthetic specification validates | `python -m pytest -q` | Valid fixture passes without registry changes | PASS | `tests/test_construction.py` | Keep regression coverage |
| VR-02 | Compose policy rejects unsafe structure | Unit tests and static inspection | Invalid structure fails closed | PASS | `tests/test_construction.py` | Add runtime render check |
| VR-03 | Runtime approval cannot be bypassed | Construction approval test | Missing flag blocks construction | PASS | `tests/test_construction.py` | Verify in WSL operator phase |
| VR-04 | Archive integrity is independently checked | Archive regression test | Copied files match manifest hashes | PASS | `tests/test_construction.py` | Test archive on approved host path |
| VR-05 | Docker daemon and context readiness | `scripts/preflight.sh` in WSL | Inventory succeeds and is retained | NOT TESTED in this sprint | `state/preflight-inventory.txt` is prior operator data | Re-run from WSL |
| VR-06 | Runtime network containment | Authorized acceptance procedure | No prohibited egress or published ports | NOT TESTED | None | Execute runtime boundary tests |
| VR-07 | Ownership-scoped disposal | Target Docker inspection | Only exact project resources are removed | NOT TESTED | None | Execute disposal acceptance |
| VR-08 | Emergency stop | Windows PowerShell acceptance procedure | Context, stop, and label verification all pass | NOT TESTED | None | Run with exact project and reviewed context |
