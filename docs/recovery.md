# Recovery

## Unexpected runtime or boundary condition

For an unexpected path, privilege, published port, resource condition, or uncertain controller state:

1. Stop client activity and prioritize containment; do not delay containment to collect evidence.
2. From an approved Windows PowerShell session, run the targeted host-side `host/EmergencyStop.ps1 -Action StopLab` command with the verified Docker execution mode, context, project, and (for WSL Docker) distribution. The exact syntax is in [../lab-set.md](../lab-set.md).
3. Verify the script result and independently confirm that no owned lab container remains running.
4. Create an incident record with `./scripts/incident.sh TYPE` when safe; document the observation, containment, residual resources, evidence references, and recovery decision.
5. Preserve evidence when doing so does not delay containment. Do not reset or destroy until evidence and incident handling are reviewed.

The emergency stop calls targeted Compose stop for the named project and verifies
containers bearing Docker Compose's exact project label are not running. Supply
the exact generated project name (`sec-lab-i-<investigation-id>`); it does not
change firewall rules, routes, or unrelated processes. If construction stopped
after boundary installation, use the normal targeted disposal path so the
project-scoped rules can be removed; do not flush firewall tables globally.

## WSL shutdown escalation

`-Action ShutdownWsl` is separate from `StopLab`, requires a verified explicit distribution and interactive `SHUTDOWN <distribution>` confirmation, and may terminate unrelated workloads in that distribution. Use only when that wider impact is explicitly accepted. It does not unregister WSL or delete evidence.

## Runtime lifecycle recovery

Inspect policy state before recovery with:

```bash
python3 lab/lab.py networks show
python3 lab/lab.py networks maintenance status
```

The active profile and boundary files are configuration for subsequent
operations. An investigation uses the resolved policy recorded with its
runtime state; do not edit configuration and assume an already-running
investigation changed. If policy files change, stop and dispose the owned
investigation, validate the new policy, and construct again.

Maintenance entry and exit are deliberately blocked in the current release:
temporary firewall application and verified restoration are not implemented.
Do not substitute broad Internet access, global firewall changes, or manual
rule flushing. A failed enforcement cleanup is recorded under
`state/network-boundary/failures.log` and requires targeted operator review.

Runtime recovery uses:

```bash
python3 lab/lab.py runtime doctor
python3 lab/lab.py runtime recover
```

Runtime stop/restart is refused while active experiment ownership records
remain. Recovery does not delete experiment workspaces, Docker resources, or
preserved evidence.

If the boundary state is uncertain, do not rerun `apply` blindly. Inspect the
owned project and policy first:

```bash
python3 lab/lab.py networks show
python3 lab/lab.py networks drift sec-lab-i-local-study-01
python3 lab/lab.py runtime inspect
python3 lab/lab.py runtime doctor
```

Use `networks verify` only after confirming the project name, policy file, and
owned Docker network identity. `networks remove` and investigation disposal
are ownership-scoped; they do not flush global firewall tables or remove
unrelated Docker resources.

- `python3 lab/lab.py experiment stop EXPERIMENT_ID`: stop the command-driven workspace lifecycle while retaining records and evidence.
- `python3 lab/lab.py dispose-investigation SPECIFICATION --investigation-id ID`: remove only the named Compose project after review.
- `python3 lab/lab.py archive EVIDENCE_DIRECTORY --destination state/archives`: hash and re-verify evidence, then copy without overwrite.

These controls have not been runtime-accepted according to [readiness-inventory.md](readiness-inventory.md). Never substitute global prune, broad volume deletion, WSL unregister, or host network/firewall changes. Consult [../lab-set.md](../lab-set.md) and [evidence-handling.md](evidence-handling.md) before routine recovery.
