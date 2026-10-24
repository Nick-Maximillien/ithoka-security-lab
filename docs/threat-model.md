# Threat Model

## Scope and assets

The lab is a constrained WSL/Ubuntu/Docker setup for controlled experiments. Assets include the Windows workstation, WSL distribution, Docker daemon and unrelated Docker workloads, host credentials/files, lab definitions, runtime availability, and staged/durable experiment evidence.

Relevant failure or threat scenarios include accidental external or host connectivity, cross-network attachment, published ports, excessive container privilege, Docker socket/host-file access, dependency supply-chain risk, resource exhaustion, evidence loss or disclosure, and mistaken teardown of unrelated resources.

This implementation is not designed to safely contain arbitrary malware, hostile kernel code, or activity that requires a dedicated physical isolation boundary. Containers share the Docker environment's Linux kernel; WSL integrates with Windows.

## Declared controls

- Default Compose network is an internal bridge; services attach only to that network.
- No declared published ports, host network mode, host mounts, Docker socket mount, privileged mode, or added capabilities.
- Services run as non-root `lab`, with read-only roots, all capabilities dropped, `no-new-privileges`, memory and PID limits.
- Controller validates effective Compose policy, uses fixed project/experiment identifiers and ownership labels, and scopes lifecycle actions to owned resources.
- Runtime creation, capture, and dependency-record actions have separate explicit approval flags; destroy and WSL shutdown require interactive confirmation.
- Evidence is staged outside container filesystems and can be hashed before optional transfer.
- Network policies are resolved from profiles and boundary files, pinned per
  experiment, and checked against the capabilities of the selected adapter.
- The supported Linux/WSL adapter applies and verifies only project-scoped
  deny-mode IPv4/IPv6 bridge rules; apply, verify, and cleanup use ownership
  identifiers and never flush global firewall state.

These are repository/configuration controls. They are not proof of effective runtime behavior until checked on the intended Docker daemon.

## Residual risks and unverified paths

The shared kernel, Docker daemon, WSL/Windows integration, host services, DNS, IPv4/IPv6, VPN, proxy, forwarding, image supply chain, host operator privileges, and resource competition remain relevant. Internet/LAN/host reachability, runtime attachments, capture visibility, and host emergency-stop behavior are not accepted by current runtime evidence; see [readiness-inventory.md](readiness-inventory.md).

Network capture is an observation point, not a preventive control and not proof
that unseen paths are absent. Capture requires an approved interface and an
installed `tcpdump` or `tshark`; it is not automatically enabled continuously.
A response that stops containers cannot undo traffic already transmitted.

Restricted controlled-access rules, monitor-mode enforcement, Windows Firewall,
upstream VPN/routing, and temporary maintenance restoration are unsupported or
unverified. The resolver and runtime reject these mandatory capabilities rather
than silently converting them to another mode.

## Operator requirements

Verify the Docker context and host before runtime creation, review dependencies and effective Compose output, use only authorized targets, preserve evidence without delaying containment, and record untested behavior as **Not tested**. See [../lab-set.md](../lab-set.md) for the current command set.
