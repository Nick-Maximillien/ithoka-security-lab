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
sudo -v
python3 lab/lab.py networks preflight
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

`preflight` checks the approved Docker context, default network inventory,
firewall backends, and root-readable rule listings. It is read-only and does not
apply global or project rules. Planning reports policy support, but does not
prove live enforcement. These setup operations do not create the investigation
network. Preflight's `ready` field means only that machine prerequisites were
observed; inspect its separate `policy_support` result before considering a
runtime.

`networks capabilities` distinguishes implemented Linux bridge enforcement
from controls that remain unverified or unsupported. The Linux adapter uses
project-owned IPv4/IPv6 chains, inserts jumps at the start of host `INPUT`,
`OUTPUT`, and `FORWARD`, and verifies that no earlier rule can bypass those
jumps. It preserves unrelated rules and checks ownership before cleanup. These
structural checks are not packet-level runtime acceptance.

`networks apply` requires the already-created, correctly labeled Compose
project network. The supported creation lifecycle is
`construct-investigation`: Compose creates the network, the adapter applies and
verifies the boundary, and only then does Compose start services. Do not create
a substitute network manually or run `networks apply` before construction.

The Linux/WSL adapter applies and verifies project-owned deny-mode IPv4/IPv6
chains. The supplied profiles still require Windows-host, dedicated DNS,
proxy, and external runtime-acceptance controls that the adapter does not
enforce or perform; those profiles report unsupported and construction fails
closed. The external enforcement chains alone do not establish that packets
are blocked: no bounded, pre-start live acceptance runner is implemented.
`networks test` therefore reports inconclusive and fails after structural
verification. `runtime start` requires project-scoped policy, current firewall
verification, and passing acceptance evidence; absent evidence keeps readiness
closed. A running lifecycle state or successful read-only preflight is not
evidence that network controls are effective.
Windows Firewall, VPN, upstream routing, physical, DNS, proxy, and complete WSL
isolation are not proved by the adapter. Restricted allow-list semantics,
capture, and temporary maintenance restoration fail closed. Live Docker
construction, connectivity tests, and teardown remain operator acceptance
activities.

Inspect capability and machine state without mutation:

```bash
python3 lab/lab.py networks capabilities
python3 lab/lab.py networks discover
sudo -v
python3 lab/lab.py networks preflight
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
python3 lab/lab.py runtime verify
```

Only if support checks pass, the project-specific commands are:

```bash
python3 lab/lab.py networks apply sec-lab-i-<id> --profile <profile> \
  --authorize "reviewed boundary application"
python3 lab/lab.py networks verify sec-lab-i-<id> --profile <profile>
python3 lab/lab.py networks test sec-lab-i-<id> --profile <profile> \
  --authorize "approved acceptance review"
python3 lab/lab.py networks drift sec-lab-i-<id>
```

The current `isolated` profile does not pass the support check; do not use
project-specific commands to bypass it. If a project has already applied
owned rules, cleanup is scoped to those rules and chains:

```bash
python3 lab/lab.py networks remove sec-lab-i-<id> --profile <profile> \
  --authorize "reviewed owned-rule cleanup"
```
