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

## Verification results

Commands run from the Windows-hosted workspace:

| Command | Result |
| --- | --- |
| `python -m pytest -q` | **PASS — 38 passed** |
| `python -m compileall -q lab gui` | **PASS** |
| `bash -n scripts/lib.sh scripts/preflight.sh scripts/capture-start.sh scripts/capture-stop.sh scripts/gui.sh scripts/maintenance.sh scripts/incident.sh` | **PASS** |
| `python lab/lab.py status --json` | **BLOCKED in this shell — controller intentionally requires POSIX/WSL** |
| `python lab/lab.py capabilities --json` | **BLOCKED in this shell — same environment guard** |

No Docker construction, image pull/build, capture, host-network change,
destructive lifecycle action, WSL shutdown, or emergency stop was executed.
No formatter, linter, or runtime acceptance test was available or run.

## Capability status

| Area | Implemented? | Unit-tested? | Integration-tested? | Runtime-tested? | Remaining limitation |
| --- | --- | --- | --- | --- | --- |
| CLI | Yes | Partial | No | No | Must be exercised from intended WSL checkout |
| Specification validation | Yes | Yes | Partial | No | Runtime Compose parser behavior remains unverified |
| Resource resolution | Yes | Yes | No | No | Image provenance is operator work |
| Construction | Yes | Partial/mock | No | No | Docker project and effective limits require acceptance |
| Disposal | Yes | No | No | No | Ownership and orphan behavior require target-host verification |
| Workspace lifecycle | Yes | Yes | No | No | Host filesystem recovery remains untested |
| Evidence collection | Yes | Partial | No | No | Runtime capture completeness is unknown |
| Archive verification | Yes | Yes | No | No | External transfer is intentionally not implemented |
| Dashboard | Yes, optional | Partial | No | No | Streamlit dependency/import and rerun behavior need operator environment testing |
| Operational scripts | Yes | Syntax only | No | No | Docker, capture, and host state checks remain untested |
| Emergency stop | Yes | Static policy only | No | No | Windows/WSL execution and ownership verification remain untested |
| Runtime policy | Policy resolution, scoped adapter path, and admission locking | Yes | Mocked only | No | Live Docker/firewall acceptance is pending |

## Runtime blockers

The following must block a relevant investigation until verified:

1. The operator has not confirmed the Docker context and daemon identity in the
   intended WSL distribution.
2. Submitted images do not have reviewed provenance and availability records.
3. Effective Compose resource limits, network egress behavior, published-port
   absence, and host-mount absence have not been observed at runtime.
4. Ownership-scoped stop/disposal and orphan cleanup have not been tested on
   the target Docker environment.
5. Packet-capture visibility and evidence survival through stop/reset/disposal
   have not been accepted.
6. Windows emergency-stop behavior, logging, and the explicit WSL shutdown
   escalation have not been accepted.

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
