# Readiness Inventory

**Inventory status recorded:** 2026-10-22 (historical host observation)

This is a repository readiness record based on operator-provided command output. A host check passing does not establish experiment runtime acceptance. Unknown means no trustworthy completed result was recorded. Do not convert an unknown or not-tested item into a pass.

## Repository facts

- Workspace is `/home/maximillien/security-lab` in an Ubuntu WSL distribution, accessed in this session through a WSL UNC path.
- The repository contains the Compose definition, platform scripts, configuration examples, experiment definitions, tests, design documents, and [../lab-set.md](../lab-set.md).
- Runtime state and evidence are generated under repository-local `state/`, `logs/`, and `evidence-staging/` paths by default. Scientific runs use `state/science/instances/<instance-id>/` and `evidence-staging/science/<instance-id>/<run-id>/`.

## Host/runtime facts

| Check | Recorded result |
| --- | --- |
| WSL distribution and version | **Pass** — Ubuntu 22.04.5 LTS under WSL2; kernel `6.6.87.2-microsoft-standard-WSL2` |
| Docker CLI path | **Pass** — Docker Engine client 28.5.2 on Linux/amd64 |
| Docker context and daemon identity | **Pass** — `default` context, Unix socket `/var/run/docker.sock`, Docker Engine server 28.5.2, daemon reachable |
| Docker Compose implementation/version | **Pass** — Docker Compose v2.36.2 |
| Existing containers, networks, and images | **Pass for collision check** — zero containers and zero images reported; network inventory was not separately recorded |
| WSL network mode, routes, DNS, IPv6, VPN, and port proxies | Unknown |
| Windows listeners and firewall profiles | Not inspected |
| Current CPU and memory capacity | **Observed** — 4 CPUs and 3.759 GiB Docker-reported memory; free headroom and disk capacity remain unverified |
| Capture tool/interface | Not verified |
| Approved archive destination | Not verified |

## Acceptance state

Host and daemon readiness checks have passed as recorded above. No runtime acceptance result is recorded yet for Compose rendering, image build, workload execution, client/server exchange, boundary behavior, instance disposal, archive transfer, or emergency stop. Repository tests exercise the controller with mocked Docker behavior and static safety contracts; they do not establish target-runtime acceptance.

Before enabling runtime approval:

1. Preserve the host and daemon output above as the baseline readiness record.
2. Inspect available disk headroom and the complete Docker network/resource inventory.
3. Confirm dependency availability/acquisition and inspect all validation output.
4. Run the checks in [../lab-set.md](../lab-set.md), starting with `lab.py validate` and `preflight.sh`; retain actual command output and mark each outcome Pass, Fail, or Not tested.

No repository operation is authorized by this inventory to change host firewall, routes, WSL configuration, Docker context, or unrelated resources.

## Current repository implementation state

The codebase now provides read-only network discovery and an explicit
operator-confirmed configuration at `config/networks/machine.yaml`, generated
from `machine.yaml.example`. Run `python3 lab/lab.py networks discover` and
review current host values before relying on the historical observations above.
The repository currently has 38 passing tests, including policy resolution,
enforcement-plan generation, runtime admission, and state-locking tests. These
tests remain isolated and do not establish live Docker, firewall, packet
capture, or Windows-host acceptance.
