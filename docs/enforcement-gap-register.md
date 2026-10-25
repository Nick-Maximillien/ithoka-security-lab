# Enforcement Gap Register

This register maps the current boundary policy to its OS API observer,
enforcement owner, and truthful runtime state. The boundary YAML and resolved policy remain the source
of truth; this table does not grant policy exceptions. A required `UNKNOWN`,
`FAIL`, or `BLOCKED` result prevents the relevant readiness gate from passing.

| Boundary | Enforcement owner | Current implementation and verification | Failure / restoration |
| --- | --- | --- | --- |
| `capture.yaml` | Linux process inventory plus capture scripts/evidence controller | Process names are observable; live capture interface, integrity, and evidence completeness are not verified by network readiness. | Capture failures are reported; no claim of capture completeness. |
| `dns.yaml` | `lab/osapi/linux/resolvers.py` | Reads `/etc/resolv.conf`; no DNS query/bypass acceptance or dedicated resolver enforcement exists. | Unsupported policy blocks construction. No DNS state is changed. |
| `docker-networks.yaml` | Docker observer, Compose validator, and `lab/osapi/actions.py` | Effective network state is inspected; Compose lifecycle and approval-gated connect/disconnect actions are available. Attachment changes are limited to ID-addressed containers and networks whose ownership labels match the project. | The selected context is used explicitly per command; failed inspection/ownership checks block attachment changes. Command success is not policy verification. |
| `external-networks.yaml` | Linux firewall observer and `network-boundary.sh` via `OSActionExecutor` | IPv4/IPv6 rules and counters are parsed; actions require a local Unix-socket endpoint and daemon name matching the Linux host, plus non-interactive `sudo`. Physical daemon location is not proven by the context. | Remote/Docker Desktop targets or missing privileges block execution; the existing script remains the sole firewall mutation owner. External packet acceptance is unavailable. |
| `filesystem.yaml` | Linux mount observer, Docker inspector, Compose validator | Host-visible mount table and container bind/socket mounts and root/tmpfs settings are inspected. | Violations fail inspection; no host mounts are modified. |
| `ipv4.yaml` | Linux routes/forwarding/firewall observers and `network-boundary.sh` | IPv4 address/route/forwarding/ruleset observations are independent of the owned-chain verifier; behavioral isolation is not proven. | Apply/verify failure blocks start; owned rules only are removed. |
| `ipv6.yaml` | Linux routes/forwarding/firewall observers and `network-boundary.sh` | IPv6 state is inspected separately from IPv4; packet-level behavior is not proven. | Apply/verify failure blocks start; owned rules only are removed. |
| `lab-egress.yaml` | Linux/WSL `network-boundary.sh` and firewall observer | Project-scoped rule structure and kernel rulesets are checked; external behavior remains unaccepted. | Failure blocks start; cleanup is ownership-scoped. |
| `lab-ingress.yaml` | Linux/WSL `network-boundary.sh` and firewall observer | Project-scoped rule structure and kernel rulesets are checked; external behavior remains unaccepted. | Failure blocks start; cleanup is ownership-scoped. |
| `proxies.yaml` | `lab/osapi/linux/proxies.py` | Proxy variable names are inventoried with values redacted; bypass prevention is not implemented. | Unsupported policy blocks construction; no proxy configuration is changed. |
| `resource-access.yaml` | Docker effective-state inspector, Compose validator, Linux process/mount observers | Privilege, capabilities, devices, mounts, user, limits, and security options are inspected for lab containers. | Violations fail closed; no unrelated Docker resources are changed. |
| `windows-host.yaml` | `lab/osapi/windows/` via PowerShell | Firewall profiles/rules, interfaces, routes, listening sockets, and process names are collected when Windows PowerShell is available. Rule filters are not fully expanded; no lab-owned Windows rule verifier is implemented. | Inspection remains `UNKNOWN` as enforcement evidence; mutation/restoration is `UNSUPPORTED`. |

## Enforcement contract

`lab/enforcement/models.py` defines typed scopes, results, and the status
vocabulary; `lab/osapi/models.py` records OS observations and command outcomes.
`lab/osapi/command.py` performs bounded shell-free process execution.
`lab/osapi/actions.py` accepts typed operation requests and maps only
registered Linux/WSL boundary-script and Docker Compose/network-attachment
actions to fixed argument vectors. Docker attachment mutations require an
explicit context and approval reference and recheck project ownership before
execution.
Windows mutations, remote Linux firewall control, Docker Desktop host-firewall
control, and cross-distribution WSL operations are explicitly unsupported.
`DockerAdapter` uses the existing project inspector and exposes the concrete
Docker Engine observers to the coordinator. The runtime coordinator evaluates
fresh results before readiness. `LinuxWslAdapter` only
invokes the existing fixed-argument boundary script for a validated project
and repository-pinned policy; mutations require an approval reference, and
apply is followed by a separate verify operation. `WindowsHostAdapter` is
read-only and deliberately does not claim host isolation.

The Linux shell adapter requires Docker, non-interactive `sudo`, IPv4/IPv6
firewall tools, and its other declared utilities. No privileged host changes
were run while developing or testing these adapters. Tests cover OS API
parsing, injected action results, ownership checks, and argument/scoping
behavior; Windows and live Linux/Docker enforcement remain unverified.
