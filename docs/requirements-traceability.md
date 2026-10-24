# Requirements Traceability

| Requirement | Implementation | Current evidence |
| --- | --- | --- |
| No predefined investigations | No `experiments/` tree or default experiment config | Static test |
| Capability discovery | `lab/lab.py capabilities`, capability catalog | CLI output and unit tests |
| Researcher-defined specification | `lab/construction.py validate_investigation` | Synthetic specification tests |
| Resource resolution | `resolve_resources` against approved catalog | Construction unit test |
| Inspectable planning | `build_construction_plan` / `lab.py plan` | JSON plan test |
| Authorization gate | `construct_investigation` and `REQUIRE_RUNTIME_APPROVAL` | Code path; Docker runtime untested |
| Scoped construction/disposal | Investigation-specific Compose project | Code path; target runtime untested |
| Evidence integrity/export | `lab/evidence.py archive_evidence` | Existing archive tests |
| Host/daemon readiness | `scripts/preflight.sh` | WSL/Docker host check passed; runtime untested |
| Network discovery | `lab.py networks discover` | Read-only command and unit coverage |
| Machine-specific network configuration | `config/networks/machine.yaml` | Schema validation; operator confirmation required |
| Enforcement planning | `lab.py networks plan` | Resolved policy, scopes, adapters, and capability result |
| Boundary apply/verify | `lab.py networks apply/verify` and `scripts/network-boundary.sh` | Scoped implementation; live Docker/firewall acceptance pending |
| Runtime admission | `lab/runtime.py` | Policy pinning, resource reservations, shared-scope conflicts, locking |
| Strong isolation claim | Explicitly not claimed | WSL/Docker limitations documented |

Repository tests do not prove image provenance, service behavior, network
containment, disposal on the target host, archive durability, or emergency
stop behavior.
