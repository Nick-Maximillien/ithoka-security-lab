# Network Boundaries

Network topology is supplied by each researcher-defined Compose apparatus and
validated before construction. The persistent lab does not prescribe clients,
servers, ports, or a fixed network name.

The backend rejects published ports, host networking, external networks, host
binds, and Docker socket mounts. Internal networks are a preventive control,
not proof of complete WSL, Windows-host, DNS, IPv6, VPN, proxy, forwarding, or
Internet isolation.

The current policy subsystem resolves four peer profiles (`isolated`,
`observation`, `controlled-access`, and `maintenance`) from the twelve
boundary definitions under `config/networks/`. `active-profile` is only the
default for new experiments. Each investigation pins its resolved policy,
provenance, requested capabilities, adapter list, scopes, and verification
requirements.

Read-only discovery and plan generation are available:

```bash
python3 lab/lab.py networks discover
python3 lab/lab.py networks validate-config
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

The Linux/WSL adapter applies and verifies only owned project-scoped deny-mode
IPv4/IPv6 bridge rules. It does not prove Windows-host, VPN, upstream routing,
physical, or complete WSL isolation. Restricted allow-list semantics,
monitor-mode enforcement, and temporary maintenance restoration fail closed.
Live Docker construction, connectivity tests, and teardown remain operator
acceptance activities.
